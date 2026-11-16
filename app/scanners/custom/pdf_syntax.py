"""Byte-level PDF syntax for the custom detector.

The FilesMagic capstone's own lexer, written from ISO 32000-1:2008 sections 7.2-7.5. It does
not use pypdf or YARA-X and does not build an object graph: it reads the bytes in order, the
way a text-oriented scanner would, and records exactly what it could and could not inspect.

Understood:
  - name objects (7.3.5), including #xx escapes. Only names containing '#' (and /Encrypt)
    reach Python code; ordinary names are skipped inside the regular expression engine, which
    keeps a 10 MB file of dense syntax within the worker's CPU budget;
  - literal strings (7.3.4.2: balanced parentheses, backslash escapes) and comments (7.2.3).
    Their text is skipped for syntax, so a "(" or "stream" inside them cannot desynchronise
    the lexer, but escaped names written inside them are still reported, marked with that
    context: a reader that jumps to an object through the cross-reference table can parse
    text that a sequential reader takes for a comment or string;
  - indirect object headers "N G obj", "endobj" and "trailer" (7.3.10, 7.5.5), used only to
    say where a token was found;
  - object streams (7.5.7), which can hide entire objects from a plain byte search: inflated
    (FlateDecode only, zlib RFC 1950) or read as is when unfiltered, then lexed like the file
    body. Every other stream (page content, fonts, images, metadata, embedded files) holds no
    object syntax and is skipped by design, whatever else its dictionary claims.

Coverage gaps are reported, never guessed at:
  - object streams with any other filter or filter chain, or a filter given by indirect
    reference (`not_inspected`);
  - every object stream of an encrypted document (`not_inspected`; names in object
    dictionaries in the file body are never encrypted and are still read);
  - object streams that are corrupt or truncated, or contain an unbalanced string, are
    inspected only up to that point (`partial`).
Not handled: PDF 1.0/1.1, where '#' in a name was an ordinary character.

Malformed input raises CustomScanError (invalid_structure): a file with no indirect object,
or a string or stream in the file body that never ends. Readers locate objects through the
cross-reference table, so junk that leaves the sequential lexer inside a string or stream
could hide later objects from it; failing closed prevents that.

Nothing is executed, rendered, decrypted or fetched. Every loop is bounded by the limits below.
"""

import re
import zlib
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass, field

from app.scanners.custom.errors import CustomScanError

MAX_STREAMS = 50_000
MAX_ESCAPED_NAMES = 50_000  # names with #-escapes kept; a benign document has a few hundred at most
MAX_STREAM_BYTES = 20 * 1024 * 1024  # decoded bytes per object stream
# ponytail: measured worst case (32 MiB of nested strings) ~3.6 s of the worker's 20 s CPU budget on
# a Windows dev laptop; object streams hold objects only, not page content, so benign totals are a
# few MB. Recalibrate on the Linux VM if a benign corpus ever hits this limit.
MAX_DECODED_BYTES = 32 * 1024 * 1024  # decoded bytes per document
INFLATE_CHUNK = 64 * 1024

DELIMITERS = b"()<>[]{}/%"
# Characters a name may contain literally (7.3.5): "!" to "~" except delimiters and "#".
REGULAR = frozenset(range(0x21, 0x7F)) - frozenset(DELIMITERS) - {ord("#")}

_END = rb"\x00\t\n\x0c\r ()<>\[\]{}/%"  # whitespace and delimiters: what ends a name
_ANY_NAME = re.compile(rb"/([^" + _END + rb"]*)")
_ESCAPED_NAME = re.compile(rb"/([^" + _END + rb"#]*#[^" + _END + rb"]*)")


_FLAT_STRING = rb"(?:[^()\\]|\\[\s\S])*"  # string content without nested parentheses


def _token_pattern(name: bytes, skip: bytes) -> re.Pattern:
    # ponytail: one alternation does the lexing in C. `skip` swallows whole runs of syntax that
    # needs no Python attention (one iteration per run instead of per token); what is left is
    # rare: escaped names, comments, strings with '#' or nesting, the stream keyword. Deeper
    # nesting falls back to _string_end. Every alternative starts with a distinct character, so
    # backtracking stays linear. The run is possessive (++, Python 3.11+): with a plain "+" the
    # engine keeps backtracking state per repetition, measured at >3 GiB for 19 MB of strings.
    return re.compile(
        rb"(?P<skip>(?:" + skip + rb")++)"
        rb"|/(?P<name>" + name + rb")"
        rb"|(?P<comment>%[^\r\n]*)"
        rb"|\((?P<simple>(?:[^()\\]|\\[\s\S]|\(" + _FLAT_STRING + rb"\))*)\)"  # up to one nesting level
        rb"|(?P<string>\()"
        # The keyword, not the tail of a name such as /stream or /A1stream.
        rb"|(?<![^\x00\t\n\x0c\r ()<>\[\]{}%])(?P<stream>stream(?:\r\n|\n|\r))"
    )


# Plain text (anything but a name, comment or string start, and "s" only when it does not begin
# "stream" + EOL) and strings without '#', nesting or end.
_SKIP_TEXT = rb"[^/%(s]+|s(?!tream[\r\n])|\((?:[^()\\#]|\\[\s\S])*\)"
_ALL_TOKENS = _token_pattern(rb"[^" + _END + rb"]*", _SKIP_TEXT)
_ESCAPED_TOKENS = _token_pattern(
    rb"[^" + _END + rb"#]*#[^" + _END + rb"]*|Encrypt(?![^" + _END + rb"])",
    # ... and names without '#', except /Encrypt, which must be seen.
    _SKIP_TEXT + rb"|/(?!Encrypt(?![^" + _END + rb"]))[^" + _END + rb"#]*(?![^" + _END + rb"])",
)
_STRING_SPECIAL = re.compile(rb"[()\\]")
_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
_EVENT = re.compile(
    rb"(?<![0-9])([0-9]{1,10})[\x00\t\n\x0c\r ]+([0-9]{1,5})[\x00\t\n\x0c\r ]+obj(?![A-Za-z0-9])"
    rb"|(?<![A-Za-z])(endobj|trailer)(?![A-Za-z0-9])"
)
_ENDSTREAM = b"endstream"

FILTERS = {
    b"ASCIIHexDecode", b"AHx", b"ASCII85Decode", b"A85", b"LZWDecode", b"LZW", b"FlateDecode", b"Fl",
    b"RunLengthDecode", b"RL", b"CCITTFaxDecode", b"CCF", b"JBIG2Decode", b"DCTDecode", b"DCT",
    b"JPXDecode", b"Crypt",
}


def is_pdf(data: bytes) -> bool:
    return b"%PDF-" in data[:1024]  # readers accept the header anywhere in the first 1024 bytes


def decode_name(raw: bytes) -> tuple[bytes, int]:
    """The decoded name and how many of its #xx escapes were unnecessary, i.e. encoded a regular
    character that could have been written literally. Only whitespace, delimiters, '#' and bytes
    outside "!" to "~" need an escape (7.3.5). A '#' without two hex digits stays literal."""
    if b"#" not in raw:
        return raw, 0
    unnecessary = 0

    def replace(m: re.Match) -> bytes:
        nonlocal unnecessary
        byte = int(m.group(1), 16)
        unnecessary += byte in REGULAR
        return bytes((byte,))

    return _ESCAPE.sub(replace, raw), unnecessary


def _string_end(data: bytes, pos: int) -> int | None:
    """Offset just past the literal string whose "(" ends at `pos`, or None if it never ends."""
    depth = 1
    while m := _STRING_SPECIAL.search(data, pos):
        pos = m.end()
        if m.group() == b"\\":
            pos += 1  # the escaped character, whatever it is
        elif m.group() == b"(":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return pos
    return None


def tokens(data: bytes, file_body: bool, all_names: bool = False):
    """Yield ("name", raw, offset, context) and, in the file body, ("stream", keyword offset,
    body start, body end).

    By default only names containing '#' and /Encrypt are yielded, including those inside
    strings and comments (context "string" or "comment", otherwise ""). With all_names, every
    name outside strings and comments is yielded instead (for reading short dictionaries).
    In the file body an unterminated string or stream is malformed. Elsewhere the stream
    keyword means nothing, and an unterminated string yields ("truncated", offset) and ends
    the scan: data after it was not inspected."""
    pattern, inner = (_ALL_TOKENS, None) if all_names else (_ESCAPED_TOKENS, _ESCAPED_NAME)
    pos = 0
    while m := pattern.search(data, pos):
        kind, pos = m.lastgroup, m.end()
        if kind == "skip":
            continue
        if kind == "name":
            yield "name", m.group("name"), m.start(), ""
        elif kind in ("comment", "simple"):
            if inner and data.find(b"#", m.start(), m.end()) >= 0:
                for n in inner.finditer(data, m.start(kind), m.end(kind)):
                    yield "name", n.group(1), n.start(), "comment" if kind == "comment" else "string"
        elif kind == "string":
            end = _string_end(data, pos)
            if end is None:
                if file_body:
                    raise CustomScanError(f"literal string at byte {m.start()} is never closed")
                yield "truncated", m.start()
                return
            if inner and data.find(b"#", pos, end) >= 0:
                for n in inner.finditer(data, pos, end - 1):
                    yield "name", n.group(1), n.start(), "string"
            pos = end
        elif file_body:
            end = data.find(_ENDSTREAM, pos)
            if end < 0:
                raise CustomScanError(f"stream at byte {m.start()} has no endstream")
            yield "stream", m.start(), pos, end
            pos = end + len(_ENDSTREAM)


def inflate(body: bytes, limit: int) -> tuple[bytes, bool]:
    """FlateDecode with a hard output limit. Returns the decoded bytes and whether the stream
    decoded completely. Corrupt or truncated data is not an error (readers show what they can);
    the caller reports such a stream as only partly inspected."""
    d, out = zlib.decompressobj(), bytearray()
    try:
        for i in range(0, len(body), INFLATE_CHUNK):
            out += d.decompress(body[i:i + INFLATE_CHUNK], limit + 1 - len(out))
            if len(out) > limit:
                raise CustomScanError(f"an object stream decodes to more than {limit} bytes")
            if d.eof:
                break
    except zlib.error:
        return bytes(out), False
    return bytes(out), d.eof


class _Index:
    """Object headers, endobj and trailer keywords outside stream bodies, for locations."""

    def __init__(self, data: bytes, bodies: list[tuple[int, int]]):
        starts = [s for s, _ in bodies]
        self.offsets, self.labels, self.objects = [], [], 0
        for m in _EVENT.finditer(data):
            i = bisect_right(starts, m.start()) - 1
            if i >= 0 and m.start() < bodies[i][1]:
                continue  # inside a stream body: data, not syntax
            if m.group(1):
                self.objects += 1
                label = f"object {int(m.group(1))} {int(m.group(2))}"
            else:
                label = "trailer" if m.group(3) == b"trailer" else None
            self.offsets.append(m.start())
            self.labels.append(label)

    def locate(self, offset: int) -> str:
        i = bisect_right(self.offsets, offset) - 1
        return (self.labels[i] if i >= 0 else None) or f"byte offset {offset}"

    def start(self, offset: int) -> int:
        """Where the object (or other section) containing `offset` begins."""
        i = bisect_right(self.offsets, offset) - 1
        return self.offsets[i] if i >= 0 else 0


@dataclass
class PdfSyntax:
    escaped: list[tuple[bytes, str]] = field(default_factory=list)  # (raw name, location): names with '#'
    object_streams: int = 0  # object streams inspected
    not_inspected: Counter = field(default_factory=Counter)  # reason -> number of object streams
    partial: list[str] = field(default_factory=list)  # object streams only partly inspected
    encrypted: bool = False

    def add(self, raw: bytes, location: str) -> None:
        self.escaped.append((raw, location))
        if len(self.escaped) > MAX_ESCAPED_NAMES:
            raise CustomScanError(f"PDF has more than {MAX_ESCAPED_NAMES} #-escaped names")


def _where(location: str, context: str) -> str:
    return f"{location} (inside a {'literal string' if context == 'string' else 'comment'})" if context else location


def parse(data: bytes) -> PdfSyntax:
    """Every #-escaped name in the file body and in the object streams this lexer can read."""
    syntax, body_names, streams = PdfSyntax(), [], []
    for token in tokens(data, file_body=True):
        if token[0] == "stream":
            streams.append(token[1:])
            if len(streams) > MAX_STREAMS:
                raise CustomScanError(f"PDF has more than {MAX_STREAMS} streams")
            continue
        _, raw, offset, context = token
        if b"#" in raw:
            body_names.append((raw, offset, context))
        if not context and decode_name(raw)[0] == b"Encrypt":
            syntax.encrypted = True

    index = _Index(data, [(start, end) for _, start, end in streams])
    if not index.objects:
        raise CustomScanError("no indirect object (\"N G obj\") was found")
    for raw, offset, context in body_names:
        syntax.add(raw, _where(index.locate(offset), context))

    budget = MAX_DECODED_BYTES
    for keyword, start, end in streams:
        dictionary = data[index.start(keyword):keyword]
        names = [decode_name(t[1])[0] for t in tokens(dictionary, file_body=False, all_names=True)
                 if t[0] == "name"]
        if b"ObjStm" not in names:
            continue  # page content, fonts, images, metadata, embedded files: no object syntax
        location = f"object stream of {index.locate(keyword)}"
        if syntax.encrypted:
            syntax.not_inspected["the document is encrypted"] += 1
            continue
        filters = [n for n in names if n in FILTERS]
        body, complete = data[start:end], True
        if filters in ([b"FlateDecode"], [b"Fl"]):
            if budget <= 0:
                raise CustomScanError(f"object streams decode to more than {MAX_DECODED_BYTES} bytes")
            body, complete = inflate(body, min(MAX_STREAM_BYTES, budget))
            budget -= len(body)
        elif filters or b"Filter" in names:
            chain = " + ".join(f.decode() for f in filters) or "given by reference"
            syntax.not_inspected[f"filter {chain}"] += 1
            continue
        syntax.object_streams += 1
        for token in tokens(body, file_body=False):
            if token[0] == "truncated":
                complete = False
            elif b"#" in token[1]:
                syntax.add(token[1], _where(location, token[3]))
        if not complete:
            syntax.partial.append(location)
    return syntax
