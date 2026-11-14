"""C1: PDF name-token obfuscation.

PDF names may encode any byte as #xx (ISO 32000-1 7.3.5), but an escape is only needed for
whitespace, delimiters, '#' and bytes outside "!" to "~". Writing an ordinary letter that way
(/J#61vaScript for /JavaScript) changes nothing for a PDF reader; its only effect is that the
name no longer matches a plain-text search, such as a byte signature looking for "/JavaScript".
Generators do not do this to ordinary names, so an unnecessary escape is the signal, and a
necessary one (/text#2Fplain, /Arial#20Bold) is not.

Rules, each with a fixed severity (nothing is added up or escalated):
  CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME   MEDIUM  an active-content name (scripts, actions, forms,
                                              embedded or remote content) written with
                                              unnecessary escapes
  CUSTOM_PDF_UNNECESSARY_NAME_ESCAPES INFO    any other name written that way
  CUSTOM_PDF_COVERAGE_LIMITED         INFO    an encrypted document, or object streams this
                                              detector could not (fully) read: absence of
                                              findings there means nothing

The names come from app.scanners.custom.pdf_syntax (file body and object streams), which also
reports their locations.
"""

from collections import Counter

from app.models import Severity
from app.scanners.custom.indicators import Signal, clean
from app.scanners.custom.pdf_syntax import PdfSyntax, decode_name

# Names that introduce scripts, actions, forms, or embedded or remote content (ISO 32000-1
# 7.11.4 embedded files, 12.6 actions and triggers, 12.7 interactive forms, 13 multimedia).
ACTIVE_CONTENT_NAMES = {
    b"JavaScript", b"JS", b"OpenAction", b"AA", b"Launch", b"URI", b"SubmitForm", b"ImportData",
    b"GoToR", b"GoToE", b"Rendition", b"RichMedia", b"EmbeddedFile", b"EmbeddedFiles", b"AcroForm", b"XFA",
}


def text(name: bytes) -> str:
    return "/" + clean(name.decode("latin-1"), 60)


def name_obfuscation(syntax: PdfSyntax) -> list[Signal]:
    count, written, places = Counter(), {}, {}
    for raw, location in syntax.escaped:
        decoded, unnecessary = decode_name(raw)
        if not unnecessary:
            continue
        count[decoded] += 1
        written.setdefault(decoded, raw)  # first spelling seen
        seen = places.setdefault(decoded, [])
        if location not in seen:
            seen.append(location)

    def signal(names: list[bytes], rule_id: str, severity: Severity, summary: str) -> Signal:
        names.sort(key=lambda n: -count[n])
        evidence = tuple(f"{text(written[n])!r} decodes to {text(n)} ({count[n]}x)" for n in names)
        locations = tuple(dict.fromkeys(loc for n in names for loc in places[n]))
        return Signal(rule_id, "pdf-name-obfuscation", severity, summary, evidence, locations)

    active = [n for n in count if n in ACTIVE_CONTENT_NAMES]
    other = [n for n in count if n not in ACTIVE_CONTENT_NAMES]
    signals = []
    if active:
        signals.append(signal(active, "CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME", Severity.MEDIUM,
                              f"PDF writes {len(active)} active-content name(s) with unnecessary #-escapes, "
                              "which hides them from plain-text inspection without changing their meaning."))
    if other:
        signals.append(signal(other, "CUSTOM_PDF_UNNECESSARY_NAME_ESCAPES", Severity.INFO,
                              f"PDF writes {len(other)} other name(s) with unnecessary #-escapes."))
    return signals


def coverage(syntax: PdfSyntax) -> list[Signal]:
    if not (syntax.not_inspected or syntax.partial):
        return []
    evidence = [f"{n} object stream(s) not inspected: {reason}" for reason, n in syntax.not_inspected.most_common()]
    if syntax.partial:
        evidence.append(f"{len(syntax.partial)} object stream(s) only partly readable (corrupt or truncated data)")
    return [Signal("CUSTOM_PDF_COVERAGE_LIMITED", "pdf-coverage", Severity.INFO,
                   "The custom detector could not inspect every part of this PDF for obfuscated names.",
                   tuple(evidence), tuple(syntax.partial))]


def analyse(syntax: PdfSyntax) -> list[Signal]:
    return name_obfuscation(syntax) + coverage(syntax)
