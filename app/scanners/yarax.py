"""YARA-X scanner: matches uploads against the curated rules in app/rules/.

Rules are compiled once, when the scanner is created. If that fails (yara-x not
installed, no rule files, syntax error, missing or invalid metadata), the scanner
stays registered but not ready, and every scan raises, so the decision engine
reports UNABLE_TO_SCAN instead of SAFE.
"""

import logging
from pathlib import Path

from app.models import Finding, Severity

try:
    import yara_x
except ImportError:  # reported as "not ready" below instead of crashing the API
    yara_x = None

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
SCAN_TIMEOUT_SECONDS = 10
MAX_MATCHES_PER_PATTERN = 1000


class YaraXError(RuntimeError):
    """YARA-X could not produce a trustworthy result."""


def compile_rules(rules_dir: Path):
    if yara_x is None:
        raise YaraXError("the yara-x package is not installed")
    rule_files = sorted(rules_dir.glob("*.yar"))
    if not rule_files:
        raise YaraXError(f"no .yar rule files found in {rules_dir}")

    compiler = yara_x.Compiler(includes_enabled=False)
    # Every rule must carry the metadata a Finding needs; anything else is a compile error.
    for identifier, regexp in [
        ("description", None),
        ("category", r"^[a-z0-9]+(-[a-z0-9]+)*$"),
        ("severity", "^(" + "|".join(s.value for s in Severity) + ")$"),
    ]:
        compiler.allowed_metadata(
            identifier=identifier, value_type=yara_x.MetaType.STRING, required=True, regexp=regexp, error=True
        )
    for path in rule_files:
        compiler.add_source(path.read_text(encoding="utf-8"), origin=path.name)
    return compiler.build()


class YaraXScanner:
    name = "yara-x"

    def __init__(self, rules_dir: Path = RULES_DIR):
        self.error: str | None = None
        self._rules = None
        try:
            self._rules = compile_rules(rules_dir)
        except Exception as e:  # CompileError, OSError, YaraXError, ...
            self.error = f"{type(e).__name__}: {e}"
            logger.error("YARA-X rules could not be loaded: %s", self.error)

    @property
    def ready(self) -> bool:
        return self._rules is not None

    def scan(self, filename: str, data: bytes) -> list[Finding]:
        if self._rules is None:
            raise YaraXError(f"YARA-X is not ready: {self.error}")

        # A Scanner must not be shared between threads; creating one is cheap.
        scanner = yara_x.Scanner(self._rules)
        scanner.set_timeout(SCAN_TIMEOUT_SECONDS)
        # Our rules only test whether a pattern occurs, never how often. Without a cap,
        # a 10 MB file full of one pattern made YARA-X track every match (~135 MiB extra).
        scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN)
        try:
            results = scanner.scan(data)
        except yara_x.TimeoutError as e:
            raise YaraXError(f"YARA-X scan timed out after {SCAN_TIMEOUT_SECONDS}s") from e
        except yara_x.ScanError as e:
            raise YaraXError(f"YARA-X scan failed: {e}") from e

        return [self._finding(rule) for rule in results.matching_rules]

    def _finding(self, rule) -> Finding:
        # Fail closed: a match we cannot describe must not be dropped.
        try:
            meta = dict(rule.metadata)
            return Finding(
                scanner=self.name,
                category=meta["category"],
                severity=Severity(meta["severity"]),
                description=meta["description"],
                rule_id=rule.identifier,
            )
        except Exception as e:
            raise YaraXError(f"YARA-X rule {getattr(rule, 'identifier', '?')!r} has unusable metadata: {e}") from e
