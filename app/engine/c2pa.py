"""C2PA manifest stores (Content Credentials) without active content, from their bytes (custom engine).

A PDF embeds its C2PA manifest store as an attachment (C2PA 2.2, Annex A.4): one JUMBF superbox
(ISO/IEC 19566-5) holding manifests, each with an assertion store, a claim and a claim signature.
verify() reads every box of it under fixed limits and says whether every item is data or a picture
that can neither run nor load anything (docs/c2pa-accuracy-preregistration.md, section 2):

  - JUMBF: exactly one superbox from the first byte to the last, consistent lengths, nothing
    trailing; its description carries the manifest store's UUID and the label "c2pa"; every
    superbox starts with one well-formed description box (private box: only a c2sh salt).
  - Content boxes: cbor (one well-formed RFC 8949 item, no repeated map key), json (no NaN, no
    repeated key), bfdb + bidb (an embedded file: JPEG or PNG checked by structure, or a static
    SVG on an element and attribute allowlist; the declared media type must name what it is), free
    (zero padding). Anything else, a uuid box, a compressed (brob) manifest or an external
    reference, is not verified.
  - Text anywhere (CBOR and JSON strings and keys, labels, SVG values): no control or formatting
    character other than tab and line breaks, no markup a renderer could act on.
  - Pictures: no HTML or SVG markup in their bytes (a polyglot).

Limits: MAX_BOXES boxes, MAX_NESTING superboxes deep, MAX_ITEMS CBOR items MAX_CBOR_NESTING deep,
MAX_TEXT characters of text, MAX_ELEMENTS SVG elements. Nothing is decompressed, every check is
linear in the bytes, so the work is bounded by these counts and the bytes (the caller bounds
those), and the verdict never depends on the machine's speed.

Never examined: signatures, certificates, the hash binding, trust lists, what the claims assert.
"Verified" means no active content was found in a structure read completely; not that the
credentials are authentic, or the document safe.
"""

import io
import json
import re
import struct
import unicodedata
import zlib

import defusedxml.ElementTree as SafeET

from app.scanners.pdf import clean

STORE_UUID = bytes.fromhex("6332706100110010800000aa00389b71")  # "c2pa": the manifest store (C2PA 2.2, 11.1.4.2)
PNG = b"\x89PNG\r\n\x1a\n"
MEDIA = {"image/jpeg": "JPEG", "image/png": "PNG", "image/svg+xml": "SVG"}
MAX_BOXES, MAX_NESTING = 10_000, 8
MAX_ITEMS, MAX_CBOR_NESTING = 100_000, 64
MAX_TEXT, MAX_ELEMENTS = 1 << 20, 10_000
SVG = "{http://www.w3.org/2000/svg}"
SVG_ELEMENTS = {"svg", "g", "defs", "title", "desc", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
                "linearGradient", "radialGradient", "stop", "clipPath", "mask"}
SVG_ATTRIBUTES = {
    "id", "class", "version", "width", "height", "x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry", "fx",
    "fy", "fr", "d", "points", "pathLength", "viewBox", "preserveAspectRatio", "transform", "fill", "fill-rule",
    "fill-opacity", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit",
    "stroke-dasharray", "stroke-dashoffset", "stroke-opacity", "opacity", "color", "display", "visibility",
    "clip-path", "clip-rule", "clipPathUnits", "mask", "maskUnits", "maskContentUnits", "offset", "stop-color",
    "stop-opacity", "gradientUnits", "gradientTransform", "spreadMethod", "shape-rendering", "vector-effect", "overflow"}
# A geometry or presentation value: numbers, names, colours, percentages, transforms, url(#id).
SVG_VALUE = re.compile(r"[\w\s.,#%()+\-]*")
SVG_FUNCTION = re.compile(r"([A-Za-z-]+)\s*\(")
SVG_FUNCTIONS = {"rgb", "rgba", "hsl", "hsla", "matrix", "translate", "scale", "rotate", "skewX", "skewY", "url"}
LOCAL_URL = re.compile(r"url\(#[\w.-]+\)")
WHITESPACE = str.maketrans("", "", "\t\n\r")
# Markup a renderer could act on, in text: a tag, an event-handler attribute (after the space, quote
# or slash that ends the previous one: not "&online=" in a URL), a script URL.
TEXT_MARKUP = re.compile(r"<[A-Za-z/!?]|(?:^|[\s\"'/])on[a-z]+\s*=|(?:java|vb)script\s*:", re.IGNORECASE)
PICTURE_MARKUP = re.compile(rb"<\s*(?:script|html|svg|iframe|object|embed|body|meta|link|style|form|base|foreignobject)\b"
                            rb"|[\s\"'/]on[a-z]+\s*=|(?:java|vb)script\s*:", re.IGNORECASE)


class NotVerified(Exception):
    """The first item that is not data or a picture without active content, and why."""


def boxes(data: bytes, start: int, end: int):
    """(type, payload start, payload end) of each box in data[start:end] (ISO/IEC 19566-5 A.2)."""
    i = start
    while i < end:
        if end - i < 8:
            raise NotVerified(f"{end - i} bytes at byte {i} are not a whole box")
        n, kind = struct.unpack_from(">I4s", data, i)
        head = 8
        if n == 1:  # XLBox: a 64-bit length follows
            if end - i < 16:
                raise NotVerified(f"box {kind!r} at byte {i} is cut off")
            n, head = struct.unpack_from(">Q", data, i + 8)[0], 16
        if n < head or i + n > end:  # LBox 0 ("to the end") lands here too
            raise NotVerified(f"box {kind!r} at byte {i} declares {n} bytes, outside its parent")
        yield kind, i + head, i + n
        i += n


def verify(data: bytes) -> str:
    """What the manifest store holds, if it is one without active content; raises NotVerified."""
    try:
        return _Store(data).read()
    except NotVerified:
        raise
    except Exception as e:  # malformed UTF-8, numbers, XML or anything else: not verified
        raise NotVerified(f"could not be read ({type(e).__name__}: {clean(e, 80)})") from None


class _Store:
    def __init__(self, data: bytes):
        self.data, self.boxes, self.items, self.chars = data, 0, 0, 0
        self.manifests, self.assertions, self.pictures = 0, [], []

    def read(self) -> str:
        top = list(boxes(self.data, 0, len(self.data)))
        if len(top) != 1 or top[0][0] != b"jumb":
            raise NotVerified("not one JUMBF superbox from the first byte to the last")
        self.superbox(*top[0][1:], depth=1, parent="")
        shown = ", ".join(clean(a, 40) for a in self.assertions[:12]) + (", ..." if len(self.assertions) > 12 else "")
        # The caveat and the verdict first: evidence lines are cut at 300 characters (correlate.finding).
        return (f"a C2PA manifest store (Content Credentials) whose signature was not validated ({len(self.data)} "
                f"bytes): {self.manifests} manifest(s), no script, active markup or external reference; data in CBOR "
                f"or JSON and {len(self.pictures)} picture(s){': ' if self.pictures else ''}{', '.join(self.pictures)}; "
                f"assertions {shown}")

    def superbox(self, start: int, end: int, depth: int, parent: str) -> None:
        if depth > MAX_NESTING:
            raise NotVerified(f"superboxes nested more than {MAX_NESTING} deep")
        children = list(boxes(self.data, start, end))
        self.boxes += len(children)
        if self.boxes > MAX_BOXES:
            raise NotVerified(f"more than {MAX_BOXES} boxes")
        if not children or children[0][0] != b"jumd":
            raise NotVerified(f"in {clean(parent or 'the store', 60)}: a superbox without its description box first")
        uuid, label = self.description(*children[0][1:])
        where = clean(label, 60) or f"a superbox in {clean(parent or 'the store', 60)}"
        if depth == 1 and (uuid != STORE_UUID or label != "c2pa"):
            raise NotVerified("the outer superbox is not a C2PA manifest store (its UUID and label c2pa)")
        if depth == 2:
            self.manifests += 1
        if parent == "c2pa.assertions":
            self.assertions.append(label)
        rest = children[1:]
        for k, (kind, s, e) in enumerate(rest):
            if kind == b"jumb":
                self.superbox(s, e, depth + 1, label)
            elif kind == b"cbor":
                if self.item(s, e, 0, where) != e:
                    raise NotVerified(f"{where}: bytes after the CBOR data item")
            elif kind == b"json":
                self.json(s, e, where)
            elif kind == b"bfdb":
                if k + 1 == len(rest) or rest[k + 1][0] != b"bidb":
                    raise NotVerified(f"{where}: a file description without its data box")
                self.embedded(s, e, *rest[k + 1][1:], where)
            elif kind == b"bidb":
                if k == 0 or rest[k - 1][0] != b"bfdb":
                    raise NotVerified(f"{where}: embedded data without a file description")
            elif kind == b"free":
                if self.data[s:e].strip(b"\0"):
                    raise NotVerified(f"{where}: a padding box that is not all zero bytes")
            else:  # uuid, brob (Brotli: not decompressed), xml, jp2c, a second jumd, protection ...
                raise NotVerified(f"{where}: a {clean(kind.decode('latin-1'), 8)!r} box, not data this check can read")

    def description(self, s: int, e: int) -> tuple[bytes, str]:
        """(UUID, label) of a JUMBF description box (ISO/IEC 19566-5 A.3)."""
        d = self.data[s:e]
        if len(d) < 17 or d[16] & 0xE0:
            raise NotVerified("a description box that is too short or sets reserved toggles")
        toggles, i, label = d[16], 17, ""
        if toggles & 0x02:  # label, NUL-terminated UTF-8
            if (j := d.find(b"\0", i)) < 0:
                raise NotVerified("a description label without its terminating NUL")
            label, i = d[i:j].decode("utf-8"), j + 1
            self.text(label, "a description label")
        i += 4 * bool(toggles & 0x04) + 32 * bool(toggles & 0x08)  # ID, hash
        if i > len(d):
            raise NotVerified(f"{clean(label, 60)}: the description box is cut off")
        if toggles & 0x10:  # private box: C2PA uses it only for salt (c2sh, 16 or 32 bytes; C2PA 2.2, 8.4.2.3)
            private = list(boxes(self.data, s + i, e))
            if len(private) != 1 or private[0][0] != b"c2sh" or private[0][2] - private[0][1] not in (16, 32):
                raise NotVerified(f"{clean(label, 60)}: a private description box that is not a c2sh salt")
            i = len(d)
        if i != len(d):
            raise NotVerified(f"{clean(label, 60)}: bytes after the description")
        return d[:16], label

    def text(self, value: str, where: str) -> None:
        self.chars += len(value)
        if self.chars > MAX_TEXT:
            raise NotVerified(f"more than {MAX_TEXT} characters of text")
        if not (rest := value.translate(WHITESPACE)).isprintable() and any(
                unicodedata.category(c) in ("Cc", "Cf") for c in rest):
            raise NotVerified(f"{where}: text with a control or formatting character")
        if m := TEXT_MARKUP.search(value):
            raise NotVerified(f"{where}: text with markup ({clean(m.group(), 20)!r})")

    def head(self, i: int, end: int, where: str) -> tuple[int, int, int | None, int]:
        """(major type, additional information, argument or None if indefinite, next offset) (RFC 8949 3)."""
        if i >= end:
            raise NotVerified(f"{where}: CBOR data cut off")
        major, info = self.data[i] >> 5, self.data[i] & 31
        if info < 24:
            return major, info, info, i + 1
        if info < 28:
            n = 1 << (info - 24)
            if i + 1 + n > end:
                raise NotVerified(f"{where}: CBOR data cut off")
            return major, info, int.from_bytes(self.data[i + 1:i + 1 + n], "big"), i + 1 + n
        if info == 31 and major in (2, 3, 4, 5, 7):  # indefinite length, or (7) the break code
            return major, info, None, i + 1
        raise NotVerified(f"{where}: a reserved CBOR encoding")

    def item(self, i: int, end: int, depth: int, where: str) -> int:
        """Checks the well-formed CBOR data item at data[i:end]; returns the offset after it."""
        self.items += 1
        if self.items > MAX_ITEMS or depth > MAX_CBOR_NESTING:
            raise NotVerified(f"{where}: more than {MAX_ITEMS} CBOR items or nesting deeper than {MAX_CBOR_NESTING}")
        major, info, arg, i = self.head(i, end, where)
        if major in (0, 1):
            return i
        if major in (2, 3):  # byte or text string; indefinite: definite chunks of the same type, then a break
            chunks = [(i, arg)] if arg is not None else []
            i += arg or 0
            while arg is None:
                m, _, n, i = self.head(i, end, where)
                if m == 7 and n is None:
                    break
                if m != major or n is None:
                    raise NotVerified(f"{where}: a malformed indefinite-length CBOR string")
                chunks.append((i, n))
                i += n
            if i > end:
                raise NotVerified(f"{where}: a CBOR string longer than its box")
            if major == 3:  # each chunk valid UTF-8 (RFC 8949 3.2.3); checked as the consumer joins them
                self.text("".join(self.data[s:s + n].decode("utf-8") for s, n in chunks), where)
            return i
        if major in (4, 5):  # array or map, definite or until a break
            keys, n = set(), 0
            while arg is None or n < arg:
                if arg is None and i < end and self.data[i] == 0xFF:
                    return i + 1
                if major == 5:
                    k, i = i, self.item(i, end, depth + 1, where)
                    if self.data[k:i] in keys:
                        raise NotVerified(f"{where}: a CBOR map repeats a key")
                    keys.add(self.data[k:i])
                i, n = self.item(i, end, depth + 1, where), n + 1
            return i
        if major == 6:  # a tag and its one item
            return self.item(i, end, depth + 1, where)
        if arg is None:
            raise NotVerified(f"{where}: a CBOR break code outside an indefinite-length item")
        if info == 24 and arg < 32:
            raise NotVerified(f"{where}: a CBOR simple value in a reserved encoding")
        return i  # simple values and floats

    def json(self, s: int, e: int, where: str) -> None:
        def pairs(items):
            if len({k for k, _ in items}) != len(items):
                raise NotVerified(f"{where}: a JSON object repeats a key")
            return dict(items)

        def constant(name):
            raise NotVerified(f"{where}: JSON {name}")

        todo = [json.loads(self.data[s:e].decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)]
        while todo:  # every string and key, as a consumer would show it
            value = todo.pop()
            if isinstance(value, str):
                self.text(value, where)
            elif isinstance(value, dict):
                todo += [*value.keys(), *value.values()]
            elif isinstance(value, list):
                todo += value

    def embedded(self, ds: int, de: int, s: int, e: int, where: str) -> None:
        """An embedded file (ISO/IEC 19566-5 B.4): bfdb (toggles, media type, optional name), bidb (the bytes)."""
        d, body = self.data[ds:de], self.data[s:e]
        parts = d[1:].split(b"\0")
        if not d or d[0] not in (0, 1) or len(parts) != 2 + d[0] or parts[-1]:
            raise NotVerified(f"{where}: a file description that is malformed or points to an external file")
        media = parts[0].decode("utf-8")
        for value in parts[:-1]:
            self.text(value.decode("utf-8"), where)
        if body.startswith(b"\xff\xd8\xff"):
            found, why = "JPEG", jpeg_problem(body)
        elif body.startswith(PNG):
            found, why = "PNG", png_problem(body)
        elif body.lstrip()[:1] == b"<" or body.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
            found, why = "SVG", self.svg_problem(body, where)
        else:
            raise NotVerified(f"{where}: embedded data that is not a JPEG, PNG or SVG picture (it starts "
                              f"{body[:4].hex() or 'empty'})")
        if why:  # markup is called SVG only once it has passed the SVG check
            raise NotVerified(f"{where}: {'markup' if found == 'SVG' else found} {why}")
        if MEDIA.get(media.strip().lower()) != found:
            raise NotVerified(f"{where}: declares {clean(media, 40)!r} but holds {found}")
        if found != "SVG" and (m := PICTURE_MARKUP.search(body)):
            raise NotVerified(f"{where}: {found} bytes that contain markup "
                              f"({clean(m.group().decode('latin-1'), 20)!r}), a polyglot")
        self.pictures.append(f"{where} {'static SVG' if found == 'SVG' else found}")

    def svg_problem(self, body: bytes, where: str) -> str:
        """"" for a static SVG: shapes, gradients and clipping only, no script, style, link or animation."""
        count = 0
        try:
            for event, el in SafeET.iterparse(io.BytesIO(body), events=("start", "end", "pi"), forbid_dtd=True):
                if event == "pi":
                    return "with a processing instruction (it can load a style sheet)"
                if event == "end":
                    for value in (el.text, el.tail):
                        if value:
                            self.text(value, where)
                    continue
                count += 1
                tag = el.tag if isinstance(el.tag, str) else ""
                if count > MAX_ELEMENTS:
                    return f"with more than {MAX_ELEMENTS} elements"
                if not tag.startswith(SVG) or tag[len(SVG):] not in SVG_ELEMENTS or (count == 1 and tag != SVG + "svg"):
                    return f"with element {clean(tag.rsplit('}', 1)[-1] or el.tag, 40)!r}, which is not a static shape"
                for key, value in el.attrib.items():
                    functions = set(SVG_FUNCTION.findall(value))
                    if key not in SVG_ATTRIBUTES:
                        return f"with attribute {clean(key, 40)!r}, not a geometry or presentation attribute"
                    if not SVG_VALUE.fullmatch(value) or functions - SVG_FUNCTIONS or (
                            "url" in functions and LOCAL_URL.sub("", value).find("url") >= 0):
                        return f"with {clean(key, 40)}={clean(value, 40)!r}, which can refer outside the picture"
                    self.text(value, where)
        except NotVerified:
            raise
        except Exception as e:  # not XML, a DTD or entity, bad encoding
            return f"that could not be read as XML ({type(e).__name__})"
        return "" if count else "without elements"


def jpeg_problem(b: bytes) -> str:
    """"" if `b` is one JPEG from SOI to EOI: every segment inside, entropy-coded data stuffed, nothing after."""
    i, scans = 2, 0
    while True:
        if i + 2 > len(b) or b[i] != 0xFF:
            return "without a marker where one must be (cut off or malformed)"
        m = b[i + 1]
        if m == 0xFF:  # fill byte
            i += 1
            continue
        i += 2
        if m == 0xD9:
            if not scans:
                return "without image data"
            return "" if i == len(b) else f"with {len(b) - i} bytes after its end (EOI)"
        if 0xD0 <= m <= 0xD7 or m == 0x01:  # RSTn, TEM: no length
            continue
        if m in (0x00, 0xD8) or i + 2 > len(b):
            return "with a malformed marker"
        n = int.from_bytes(b[i:i + 2], "big")
        if n < 2 or i + n > len(b):
            return "with a segment longer than the picture"
        i += n
        if m == 0xDA:  # start of scan: entropy-coded data up to the next marker other than RSTn
            scans += 1
            while True:
                j = b.find(b"\xff", i)
                if j < 0 or j + 1 == len(b):
                    return "cut off inside its image data"
                if b[j + 1] == 0x00 or 0xD0 <= b[j + 1] <= 0xD7:
                    i = j + 2
                    continue
                i = j
                break


def png_problem(b: bytes) -> str:
    """"" if `b` is one PNG: chunks with valid CRC-32, IHDR first, IEND last, nothing after."""
    i, first = len(PNG), True
    while i + 12 <= len(b):
        n, kind = struct.unpack_from(">I4s", b, i)
        if n > 0x7FFFFFFF or i + 12 + n > len(b) or not kind.isalpha():
            return "with a malformed chunk"
        if zlib.crc32(b[i + 4:i + 8 + n]) != struct.unpack_from(">I", b, i + 8 + n)[0]:
            return f"with a chunk ({clean(kind.decode('latin-1'), 4)}) whose CRC does not match"
        if first and kind != b"IHDR":
            return "that does not start with IHDR"
        first, i = False, i + 12 + n
        if kind == b"IEND":
            return "" if i == len(b) else f"with {len(b) - i} bytes after IEND"
    return "cut off before IEND"
