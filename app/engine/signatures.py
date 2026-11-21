"""FilesMagic signature matcher: the engine's own byte-signature detection (replaces YARA-X).

A rule (app.engine.signature_rules) names byte patterns and a boolean condition over where and
how often they occur. This module finds the patterns and evaluates the conditions. No external
matching engine is involved; the only primitives are the standard library's bytes.find and re.

Semantics, chosen to match the YARA-X rules this replaces (tests/test_signatures.py checks them
against YARA-X itself whenever the yara-x package is installed, as it is in development):

  - A match is identified by its START offset. Every start offset at which the pattern matches is
    a separate match, so matches may overlap ("aa" occurs twice in "aaa"). bytes.find and
    re.search are restarted one byte after the previous start, not after its end, which is what
    makes overlapping matches visible; re.finditer would silently skip them.
  - A regular expression matches at an offset if re.match succeeds there. Python's backtracking
    engine explores every alternative before failing, so "matches at offset i" is the same yes/no
    answer YARA-X gives; only the match length could differ, and no rule uses lengths.
  - nocase is ASCII case folding (re.IGNORECASE on bytes), as in YARA. wide is UTF-16LE of an
    ASCII literal (each byte followed by 0x00) and, as in YARA, the plain form then does not match.
  - At most MAX_MATCHES_PER_PATTERN matches are recorded per pattern (YARA-X's
    max_matches_per_pattern, which the previous scanner set to the same value). Counts saturate
    there; rules that compare counts treat a saturated count as "not exact" (see the rules).
  - `within(name, lo, hi)` is YARA's `$x in (lo..hi)`: some recorded match starts in [lo, hi].
  - u16/u32 read little-endian integers; reading outside the file is false, like YARA's undefined.

Bounds: patterns are searched lazily, only when a condition asks (conditions short-circuit, and
each rule's `applies` header check runs first). Each pattern's work is at most
MAX_MATCHES_PER_PATTERN restarted searches over the input, and the whole scan checks a deadline
between searches. A single re.search cannot be interrupted; the rule set is reviewed so that no
regular expression backtracks super-linearly (tests time adversarial inputs), and the worker's
CPU limit and timeout stay the outer bound.
"""

import hashlib
import re
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from app.models import Finding, Severity

NAME = "signatures"
MAX_MATCHES_PER_PATTERN = 1000
# Longest regex match, in bytes from its start. Measured on YARA-X 1.21: a regex match ends at most
# 4095 bytes after its atom (tests/test_signatures.py). Every rule regex starts with its atom, so
# this reproduces it, and it bounds the work per candidate offset.
MAX_REGEX_MATCH = 4095
SCAN_TIMEOUT_SECONDS = 10
MAX_EVIDENCE = 5
_CATEGORY = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_PATTERN_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")


class SignatureError(RuntimeError):
    """The signature scan could not produce a trustworthy result."""


@dataclass(frozen=True)
class Pattern:
    literal: bytes | None = None
    regex: bytes | None = None
    nocase: bool = False
    wide: bool = False
    # A literal every match starts with. Candidates are then found with bytes.find and the regex
    # is tried only there, inside the MAX_REGEX_MATCH window: O(window) per candidate, never a
    # backtracking search across the rest of the file.
    prefix: bytes | None = None

    def compiled(self) -> "Compiled":
        if self.regex is not None:
            return Compiled(re.compile(self.regex, re.IGNORECASE if self.nocase else 0), self.prefix)
        text = bytes(b for c in self.literal for b in (c, 0)) if self.wide else self.literal
        return Compiled(re.compile(re.escape(text), re.IGNORECASE) if self.nocase else text)


@dataclass(frozen=True)
class Compiled:
    search: re.Pattern | bytes  # bytes: a case-sensitive literal, searched with bytes.find
    prefix: bytes | None = None


def literal(text: bytes, nocase: bool = False, wide: bool = False) -> Pattern:
    return Pattern(literal=text, nocase=nocase, wide=wide)


def regex(expr: bytes, nocase: bool = False, prefix: bytes | None = None) -> Pattern:
    return Pattern(regex=expr, nocase=nocase, prefix=prefix)


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    category: str
    severity: Severity
    patterns: dict[str, Pattern]
    condition: Callable[["Matches"], bool]
    # File-type selection: a cheap header check evaluated before any pattern is searched. It is
    # part of the condition (both must hold), split out so other formats cost nothing.
    applies: Callable[["Matches"], bool] = lambda m: True


def _next_start(data: bytes, c: Compiled, pos: int) -> int:
    """The first start offset >= pos at which `c` matches, or -1."""
    if isinstance(c.search, bytes):
        return data.find(c.search, pos)
    rx = c.search
    if c.prefix is not None:
        while (pos := data.find(c.prefix, pos)) >= 0:
            if rx.match(data, pos, pos + MAX_REGEX_MATCH):
                return pos
            pos += 1
        return -1
    while m := rx.search(data, pos):
        start = m.start()
        # The leftmost-start search found a match; keep it if it also fits the window.
        if m.end() - start <= MAX_REGEX_MATCH or rx.match(data, start, start + MAX_REGEX_MATCH):
            return start
        pos = start + 1
    return -1


def find_all(data: bytes, pattern: Compiled, limit: int = MAX_MATCHES_PER_PATTERN,
             deadline: float | None = None) -> list[int]:
    """Every start offset at which `pattern` matches, overlapping, in order, at most `limit`."""
    offsets, pos, steps = [], 0, 0
    while len(offsets) < limit and (pos := _next_start(data, pattern, pos)) >= 0:
        offsets.append(pos)
        pos += 1
        steps += 1
        if deadline is not None and steps % 64 == 0 and time.monotonic() > deadline:
            raise SignatureError(f"signature scan exceeded {SCAN_TIMEOUT_SECONDS}s")
    return offsets


class Matches:
    """Lazy view of one file's pattern matches for one rule; what a condition reads."""

    def __init__(self, data: bytes, patterns: dict[str, Compiled], cache: dict, deadline: float):
        self.data, self._patterns, self._cache, self._deadline = data, patterns, cache, deadline

    def offsets(self, name: str) -> list[int]:
        pattern = self._patterns[name]
        s = pattern.search
        key = (s if isinstance(s, bytes) else (s.pattern, s.flags), pattern.prefix)
        if key not in self._cache:  # shared by every rule that uses the same pattern
            if time.monotonic() > self._deadline:
                raise SignatureError(f"signature scan exceeded {SCAN_TIMEOUT_SECONDS}s")
            self._cache[key] = find_all(self.data, pattern, deadline=self._deadline)
        return self._cache[key]

    def has(self, name: str) -> bool:
        return bool(self.offsets(name))

    def count(self, name: str) -> int:
        return len(self.offsets(name))

    def any(self, *names: str) -> bool:
        return any(self.has(n) for n in names)

    def within(self, name: str, lo: int, hi: int) -> bool:
        return any(lo <= o <= hi for o in self.offsets(name))

    def u16(self, offset: int) -> int | None:
        return struct.unpack_from("<H", self.data, offset)[0] if 0 <= offset <= len(self.data) - 2 else None

    def u32(self, offset: int) -> int | None:
        return struct.unpack_from("<I", self.data, offset)[0] if 0 <= offset <= len(self.data) - 4 else None


def validate(rules: list[Rule]) -> None:
    """The metadata every Finding needs, checked when the scanner is created (fail closed)."""
    seen = set()
    for r in rules:
        if not re.fullmatch(r"[A-Za-z_]\w*", r.id) or r.id in seen:
            raise SignatureError(f"rule id {r.id!r} is invalid or duplicated")
        seen.add(r.id)
        if not r.description or not _CATEGORY.match(r.category) or not isinstance(r.severity, Severity):
            raise SignatureError(f"rule {r.id} has missing or invalid metadata")
        for name, p in r.patterns.items():
            if (not _PATTERN_NAME.match(name) or (p.literal is None) == (p.regex is None)
                    or (p.wide and p.regex is not None) or (p.prefix is not None and (p.regex is None or p.nocase))):
                raise SignatureError(f"rule {r.id} pattern {name!r} is invalid")
            p.compiled()  # a regex that does not compile is a load error, not a scan error
            # The prefix must be what every match starts with, or candidates would be missed.
            if p.prefix is not None and not p.regex.startswith((p.prefix, re.escape(p.prefix))):
                raise SignatureError(f"rule {r.id} pattern {name!r}: prefix is not the regex's literal start")


class SignatureScanner:
    name = NAME

    def __init__(self, rules: list[Rule] | None = None):
        self.error: str | None = None
        self._rules: list[tuple[Rule, dict]] | None = None
        try:
            if rules is None:
                from app.engine.signature_rules import RULES as rules
            validate(rules)
            self._rules = [(r, {n: p.compiled() for n, p in r.patterns.items()}) for r in rules]
        except Exception as e:  # SignatureError, re.error, ImportError, ...
            self.error = f"{type(e).__name__}: {e}"

    @property
    def ready(self) -> bool:
        return self._rules is not None

    def scan(self, filename: str, data: bytes) -> list[Finding]:
        if self._rules is None:
            raise SignatureError(f"signature rules are not ready: {self.error}")
        deadline, cache, found = time.monotonic() + SCAN_TIMEOUT_SECONDS, {}, []
        for rule, patterns in self._rules:
            m = Matches(data, patterns, cache, deadline)
            try:
                matched = rule.applies(m) and rule.condition(m)
            except SignatureError:
                raise
            except Exception as e:  # a defective condition must not pass a file
                raise SignatureError(f"rule {rule.id} could not be evaluated: {type(e).__name__}") from e
            if matched:
                found.append(Finding(scanner=NAME, category=rule.category, severity=rule.severity,
                                     description=rule.description, rule_id=rule.id, evidence=evidence(m, rule)))
        return found


def evidence(m: Matches, rule: Rule) -> list[str]:
    """Where each pattern of a matched rule occurs: offsets, never file content."""
    items = []
    for name in rule.patterns:
        offsets = m.offsets(name)
        if offsets:
            more = "+" if len(offsets) >= MAX_MATCHES_PER_PATTERN else ""
            shown = ", ".join(f"0x{o:x}" for o in offsets[:3])
            items.append(f"${name}: {len(offsets)}{more} match(es) at offset {shown}{' ...' if len(offsets) > 3 else ''}")
    return items[:MAX_EVIDENCE * 2] or ["matched by the file-header checks of the rule (no byte patterns)"]


RULES_FILE = Path(__file__).resolve().parent / "signature_rules.py"


def ruleset_hash(path: Path = RULES_FILE) -> str:
    """Version of the rule set: SHA-256 of the rule file with line endings normalised."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")).hexdigest()
