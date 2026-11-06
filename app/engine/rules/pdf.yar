/*
  FilesMagic custom engine: refined PDF signature (capstone, original rule).

  Refines the reference rule PDF_JavaScript_With_Automatic_Action (app/rules/filesmagic.yar),
  which fires on any "/OpenAction" or "/AA" bytes next to JavaScript. Two benign constructions
  match it although nothing runs automatically:
    - /OpenAction [3 0 R /Fit]   an inline destination: which page to show, not an action
                                 (ISO 32000-1 12.3.2.2, Table 28 /OpenAction)
    - /AA << /K ... >>           form-field keystroke (or format/validate/calculate) scripts,
                                 which run on user input (12.6.3, Table 196)

  Method: count every occurrence, and separately the occurrences whose bytes PROVE they are not
  automatic. An occurrence is discounted only if it is proven; anything else (an indirect
  /AA 9 0 R, a ">" inside a script, an unknown key, a literal string) still counts. So this rule
  fires only where the reference rule fires, and stays silent only where its bytes contradict it.
  The user-interaction keys are the complement of the PDF scanner's AUTO_TRIGGERS.

  Still bytes only: no parser is involved, so it stays independent of pypdf.
*/

rule ENGINE_PDF_JavaScript_With_Automatic_Trigger
{
    meta:
        description = "PDF contains JavaScript and an automatic trigger: an /OpenAction that is not a page destination, or an /AA dictionary not shown to hold only user-interaction triggers."
        category = "pdf-active-content"
        severity = "MEDIUM"
    strings:
        $pdf = "%PDF-"  // readers accept the header anywhere in the first 1024 bytes
        $js1 = "/JavaScript"
        $js2 = "/JS"
        // The whole name: followed by whitespace or a delimiter (7.2.2), so /AAx does not count.
        $open = /\/OpenAction[\x00\t\n\x0c\r ()<>\[\]{}\/%]/
        $aa = /\/AA[\x00\t\n\x0c\r ()<>\[\]{}\/%]/
        // Proven not automatic: an inline destination array.
        $open_destination = /\/OpenAction[\x00\t\n\x0c\r ]*\[/
        // Proven not automatic: a direct /AA dictionary whose every key is a user-interaction
        // trigger and whose every value is an indirect reference or a dictionary without nested
        // dictionaries (hex strings <..> allowed; any other "<" or ">" stops the proof).
        $aa_user_only = /\/AA[\x00\t\n\x0c\r ]*<<([\x00\t\n\x0c\r ]*\/(K|F|V|C|E|X|D|U|Fo|Bl|PC|PI)[\x00\t\n\x0c\r ]*([0-9]+[\x00\t\n\x0c\r ]+[0-9]+[\x00\t\n\x0c\r ]+R|<<([^<>]|<[^<>]*>)*>>))*[\x00\t\n\x0c\r ]*>>/
    condition:
        $pdf in (0..1024) and any of ($js*) and (
            #open > #open_destination or #aa > #aa_user_only
            // At the scanner's match cap (MAX_MATCHES_PER_PATTERN = 1000) counts are no longer
            // exact, so nothing is discounted.
            or #open >= 1000 or #aa >= 1000
        )
}
