"""FilesMagic signature rules (evaluated by app.engine.signatures).

A small, curated set of structural byte indicators for the file types FilesMagic converts. It is
not antivirus coverage and contains no malware payloads. Severity: HIGH/CRITICAL -> MALICIOUS,
LOW/MEDIUM -> SUSPICIOUS (app.decision).

Origin: each rule is a faithful port of a rule from the former YARA-X rule files
(app/rules/filesmagic.yar and app/engine/rules/pdf.yar at baseline b6774be); the YARA text is
quoted above each rule. Differences, all deliberate:
  - PDF_JavaScript_With_Automatic_Action (reference) is not ported. The engine always replaced it
    by ENGINE_PDF_JavaScript_With_Automatic_Trigger, which fires only where it fires; evaluating
    both was redundant work whose result correlation then discarded.
  - Header checks a YARA condition began with (uint32(0) == ...) are the rule's `applies`.

Known limitation (unchanged from YARA-X): rules see raw bytes only. Content inside compressed
streams (PDF FlateDecode, ZIP-compressed OOXML parts) and escaped PDF names (/J#61vaScript) are
not visible here; the PDF, Office and custom analyses parse those structures.
"""

from app.engine.signatures import MAX_MATCHES_PER_PATTERN as CAP
from app.engine.signatures import Rule, literal, regex
from app.models import Severity

PDF_HEADER = literal(b"%PDF-")  # readers accept the header anywhere in the first 1024 bytes


def pdf(m) -> bool:
    return m.within("pdf", 0, 1024)


# PDF delimiters and whitespace (ISO 32000-1 7.2.2): a name ends at one of these.
_WS = rb"[\x00\t\n\x0c\r ]"
_END = rb"[\x00\t\n\x0c\r ()<>\[\]{}/%]"
_USER_KEYS = rb"(K|F|V|C|E|X|D|U|Fo|Bl|PC|PI)"  # user-interaction /AA triggers (12.6.3, Table 194-197)
_REF = rb"[0-9]+" + _WS + rb"+[0-9]+" + _WS + rb"+R"
_FLAT_DICT = rb"<<([^<>]|<[^<>]*>)*>>"  # a dictionary with no nested dictionary (hex strings allowed)

RULES = [
    # rule PDF_Launch_Action: $pdf in (0..1024) and $launch
    Rule("PDF_Launch_Action",
         "PDF contains a /Launch action, which can start external programs or open files.",
         "pdf-active-content", Severity.HIGH,
         {"pdf": PDF_HEADER, "launch": literal(b"/Launch")},
         lambda m: m.has("launch"), applies=pdf),

    # rule ENGINE_PDF_JavaScript_With_Automatic_Trigger:
    #   $pdf in (0..1024) and any of ($js*) and (#open > #open_destination or #aa > #aa_user_only
    #   or #open >= 1000 or #aa >= 1000)
    # Count every /OpenAction and /AA, and separately those whose bytes PROVE they are not automatic:
    # an inline destination array, or a direct /AA dictionary whose every key is a user-interaction
    # trigger and every value an indirect reference or a dictionary without nested dictionaries. An
    # occurrence is discounted only if proven. At the match cap counts are not exact: nothing is
    # discounted. So this fires wherever the generic JavaScript + automatic-action signature would,
    # except where the bytes contradict it.
    Rule("ENGINE_PDF_JavaScript_With_Automatic_Trigger",
         "PDF contains JavaScript and an automatic trigger: an /OpenAction that is not a page destination, "
         "or an /AA dictionary not shown to hold only user-interaction triggers.",
         "pdf-active-content", Severity.MEDIUM,
         {"pdf": PDF_HEADER, "js1": literal(b"/JavaScript"), "js2": literal(b"/JS"),
          "open": regex(rb"/OpenAction" + _END, prefix=b"/OpenAction"), "aa": regex(rb"/AA" + _END, prefix=b"/AA"),
          "open_destination": regex(rb"/OpenAction" + _WS + rb"*\[", prefix=b"/OpenAction"),
          "aa_user_only": regex(rb"/AA" + _WS + rb"*<<(" + _WS + rb"*/" + _USER_KEYS + _WS + rb"*(" + _REF + rb"|"
                                + _FLAT_DICT + rb"))*" + _WS + rb"*>>", prefix=b"/AA")},
         lambda m: m.any("js1", "js2") and (
             m.count("open") > m.count("open_destination") or m.count("aa") > m.count("aa_user_only")
             or m.count("open") >= CAP or m.count("aa") >= CAP),
         applies=pdf),

    # rule PDF_Embedded_File: $pdf in (0..1024) and $embedded
    Rule("PDF_Embedded_File", "PDF carries an embedded file attachment.", "pdf-embedded-file", Severity.LOW,
         {"pdf": PDF_HEADER, "embedded": literal(b"/EmbeddedFile")},
         lambda m: m.has("embedded"), applies=pdf),

    # rule OLE_Office_VBA_Macros: uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1 and $vba
    Rule("OLE_Office_VBA_Macros", "Legacy Office (OLE) document contains a VBA macro project.",
         "office-macro", Severity.MEDIUM,
         {"vba": literal(b"_VBA_PROJECT", wide=True)},
         lambda m: m.has("vba"), applies=lambda m: m.u32(0) == 0xE011CFD0 and m.u32(4) == 0xE11AB1A1),

    # rule OOXML_VBA_Macros: uint32(0) == 0x04034B50 and $vba  (ZIP entry names are stored uncompressed)
    Rule("OOXML_VBA_Macros",
         "Office Open XML (ZIP-based) document contains a VBA macro project (vbaProject.bin).",
         "office-macro", Severity.MEDIUM,
         {"vba": literal(b"vbaProject.bin")},
         lambda m: m.has("vba"), applies=lambda m: m.u32(0) == 0x04034B50),

    # rule RTF_Auto_Updating_Embedded_Object: uint32(0) == 0x74725C7B and $object and $objupdate
    Rule("RTF_Auto_Updating_Embedded_Object",
         "RTF document contains an embedded object set to update automatically (\\objupdate), a technique "
         "used to trigger exploits on open.",
         "rtf-embedded-object", Severity.HIGH,
         {"objupdate": literal(b"\\objupdate", nocase=True), "object": literal(b"\\object", nocase=True)},
         lambda m: m.has("object") and m.has("objupdate"), applies=lambda m: m.u32(0) == 0x74725C7B),

    # rule RTF_DDE_Auto_Field: uint32(0) == 0x74725C7B and $dde
    Rule("RTF_DDE_Auto_Field",
         "RTF document contains a DDEAUTO field, which can run a command when the document is opened.",
         "office-dde", Severity.MEDIUM,
         {"dde": literal(b"DDEAUTO", nocase=True)},
         lambda m: m.has("dde"), applies=lambda m: m.u32(0) == 0x74725C7B),

    # rule SVG_Script_Content: $svg in (0..4096) and any of ($script, $handler, $js_uri)
    Rule("SVG_Script_Content",
         "SVG image contains script or event-handler attributes that can execute in a browser.",
         "svg-active-content", Severity.MEDIUM,
         {"svg": literal(b"<svg", nocase=True), "script": literal(b"<script", nocase=True),
          "handler": regex(rb"\son(load|error|click|mouseover|focus|begin)\s*=", nocase=True),
          "js_uri": literal(b"javascript:", nocase=True)},
         lambda m: m.within("svg", 0, 4096) and m.any("script", "handler", "js_uri")),

    # rule Native_Executable:
    #   (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or uint32(0) == 0x464C457F
    Rule("Native_Executable",
         "File is a native executable (Windows PE or Linux ELF), not a document or image.",
         "executable", Severity.MEDIUM, {},
         lambda m: (m.u16(0) == 0x5A4D and (e := m.u32(0x3C)) is not None and m.u32(e) == 0x00004550)
         or m.u32(0) == 0x464C457F),
]
