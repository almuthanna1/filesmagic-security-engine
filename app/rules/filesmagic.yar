/*
  FilesMagic Security Engine: initial YARA-X rule set.

  A small, curated set of structural indicators for file types a document/image
  converter receives. It is NOT antivirus coverage and contains no malware payloads.
  Detection effectiveness is to be measured empirically against labelled datasets.

  Every rule must declare (enforced at compile time by app/scanners/yara_x.py):
    description  human-readable explanation shown to the user
    category     short kebab-case label
    severity     INFO | LOW | MEDIUM | HIGH | CRITICAL
                 (HIGH/CRITICAL -> MALICIOUS, LOW/MEDIUM -> SUSPICIOUS)

  Known limitation: rules match raw bytes. Content inside compressed streams
  (PDF FlateDecode objects, ZIP-compressed OOXML parts) or obfuscated PDF names
  (e.g. /J#61vaScript) is not visible here; the planned PDF and Office analyzers
  parse those structures.
*/

// ---------------------------------------------------------------- PDF


rule PDF_Launch_Action
{
    meta:
        description = "PDF contains a /Launch action, which can start external programs or open files."
        category = "pdf-active-content"
        severity = "HIGH"
    strings:
        $pdf = "%PDF-"  // readers accept the header anywhere in the first 1024 bytes
        $launch = "/Launch"
    condition:
        $pdf in (0..1024) and $launch
}

rule PDF_JavaScript_With_Automatic_Action
{
    meta:
        description = "PDF contains JavaScript together with an automatic action (/OpenAction or /AA) that can run it when the document is opened."
        category = "pdf-active-content"
        severity = "MEDIUM"
    strings:
        $pdf = "%PDF-"  // readers accept the header anywhere in the first 1024 bytes
        $js1 = "/JavaScript"
        $js2 = "/JS"
        $auto1 = "/OpenAction"
        $auto2 = "/AA"
    condition:
        $pdf in (0..1024) and any of ($js*) and any of ($auto*)
}

rule PDF_Embedded_File
{
    meta:
        description = "PDF carries an embedded file attachment."
        category = "pdf-embedded-file"
        severity = "LOW"
    strings:
        $pdf = "%PDF-"  // readers accept the header anywhere in the first 1024 bytes
        $embedded = "/EmbeddedFile"
    condition:
        $pdf in (0..1024) and $embedded
}

// ---------------------------------------------------------------- Office

rule OLE_Office_VBA_Macros
{
    meta:
        description = "Legacy Office (OLE) document contains a VBA macro project."
        category = "office-macro"
        severity = "MEDIUM"
    strings:
        $vba = "_VBA_PROJECT" wide
    condition:
        uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1 and $vba  // OLE2 magic
}

rule OOXML_VBA_Macros
{
    meta:
        description = "Office Open XML (ZIP-based) document contains a VBA macro project (vbaProject.bin)."
        category = "office-macro"
        severity = "MEDIUM"
    strings:
        $vba = "vbaProject.bin"  // ZIP entry names are stored uncompressed
    condition:
        uint32(0) == 0x04034B50 and $vba  // "PK\x03\x04"
}

rule RTF_Auto_Updating_Embedded_Object
{
    meta:
        description = "RTF document contains an embedded object set to update automatically (\\objupdate), a technique used to trigger exploits on open."
        category = "rtf-embedded-object"
        severity = "HIGH"
    strings:
        $objupdate = "\\objupdate" nocase
        $object = "\\object" nocase
    condition:
        uint32(0) == 0x74725C7B and $object and $objupdate  // "{\rt"
}

rule RTF_DDE_Auto_Field
{
    meta:
        description = "RTF document contains a DDEAUTO field, which can run a command when the document is opened."
        category = "office-dde"
        severity = "MEDIUM"
    strings:
        $dde = "DDEAUTO" nocase
    condition:
        uint32(0) == 0x74725C7B and $dde  // "{\rt"
}

// ---------------------------------------------------------------- Images

rule SVG_Script_Content
{
    meta:
        description = "SVG image contains script or event-handler attributes that can execute in a browser."
        category = "svg-active-content"
        severity = "MEDIUM"
    strings:
        $svg = "<svg" nocase
        $script = "<script" nocase
        $handler = /\son(load|error|click|mouseover|focus|begin)\s*=/ nocase
        $js_uri = "javascript:" nocase
    condition:
        $svg in (0..4096) and any of ($script, $handler, $js_uri)
}

// ---------------------------------------------------------------- Executables

rule Native_Executable
{
    meta:
        description = "File is a native executable (Windows PE or Linux ELF), not a document or image."
        category = "executable"
        severity = "MEDIUM"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550)  // "MZ" ... "PE\0\0"
        or uint32(0) == 0x464C457F  // "\x7fELF"
}
