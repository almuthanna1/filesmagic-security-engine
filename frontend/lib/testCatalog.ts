export type Verdict = "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "UNABLE_TO_SCAN";
export type TestGroup = "Benign controls" | "Suspicious indicators" | "High-severity indicators" | "Parser failure";
export type TestCase = {
  id: string;
  filename: string;
  format: string;
  group: TestGroup;
  expected: Verdict;
  note: string;
  rule: string;
};

// These fixtures are synthetic functional checks, not labelled real-world malware.
// Verdicts are expectations for the current production scanner rules, not ground truth.
export const TEST_CASES: TestCase[] = [
  { id: "benign-txt", filename: "01-benign-text.txt", format: "TXT", group: "Benign controls", expected: "SAFE", note: "Plain text, no threat indicators.", rule: "None" },
  { id: "benign-csv", filename: "02-benign-data.csv", format: "CSV", group: "Benign controls", expected: "SAFE", note: "Ordinary comma-separated data.", rule: "None" },
  { id: "benign-svg", filename: "03-benign-image.svg", format: "SVG", group: "Benign controls", expected: "SAFE", note: "Static vector graphics without scripting.", rule: "None" },
  { id: "benign-pdf", filename: "04-benign-document.pdf", format: "PDF", group: "Benign controls", expected: "SAFE", note: "Valid one-page PDF without active features.", rule: "None" },
  { id: "benign-docx", filename: "05-benign-document.docx", format: "DOCX", group: "Benign controls", expected: "SAFE", note: "Small valid Office Open XML document.", rule: "None" },
  { id: "benign-rtf", filename: "06-benign-rich-text.rtf", format: "RTF", group: "Benign controls", expected: "SAFE", note: "Ordinary text-only Rich Text Format file.", rule: "None" },

  { id: "svg-script", filename: "07-svg-script-indicator.svg", format: "SVG", group: "Suspicious indicators", expected: "SUSPICIOUS", note: "Empty script element; contains no executable code.", rule: "SVG_Script_Content" },
  { id: "svg-event", filename: "08-svg-event-indicator.svg", format: "SVG", group: "Suspicious indicators", expected: "SUSPICIOUS", note: "Empty onload attribute; tests event-handler matching.", rule: "SVG_Script_Content" },
  { id: "pdf-js", filename: "09-pdf-auto-javascript.pdf", format: "PDF", group: "Suspicious indicators", expected: "SUSPICIOUS", note: "Valid PDF with an automatic JavaScript action containing an empty script.", rule: "PDF_JavaScript_With_Automatic_Action / PDF_AUTO_JAVASCRIPT" },
  { id: "pdf-attachment", filename: "10-pdf-text-attachment.pdf", format: "PDF", group: "Suspicious indicators", expected: "SUSPICIOUS", note: "Valid PDF embedding a harmless plain-text attachment.", rule: "PDF_Embedded_File / PDF_EMBEDDED_FILE" },
  { id: "docx-autoload", filename: "11-docx-external-template.docx", format: "DOCX", group: "Suspicious indicators", expected: "SUSPICIOUS", note: "OOXML attached-template relationship pointing to example.invalid.", rule: "OFFICE_EXTERNAL_AUTOLOAD" },
  { id: "rtf-dde", filename: "12-rtf-dde-marker.rtf", format: "RTF", group: "Suspicious indicators", expected: "SUSPICIOUS", note: "Inert DDEAUTO marker in RTF text; no command supplied.", rule: "RTF_DDE_Auto_Field" },

  { id: "pdf-launch", filename: "13-pdf-launch-indicator.pdf", format: "PDF", group: "High-severity indicators", expected: "MALICIOUS", note: "Valid PDF containing a /Launch action with no executable or file target.", rule: "PDF_Launch_Action / PDF_LAUNCH_ACTION" },
  { id: "docx-protocol", filename: "14-docx-dangerous-scheme.docx", format: "DOCX", group: "High-severity indicators", expected: "MALICIOUS", note: "External relationship with a synthetic ms- URI; no exploit payload.", rule: "OFFICE_EXTERNAL_DANGEROUS_SCHEME" },
  { id: "rtf-object", filename: "15-rtf-object-update.rtf", format: "RTF", group: "High-severity indicators", expected: "MALICIOUS", note: "Inert object-update markers; no embedded object or command.", rule: "RTF_Auto_Updating_Embedded_Object" },

  { id: "invalid-pdf", filename: "16-corrupted-document.pdf", format: "PDF", group: "Parser failure", expected: "UNABLE_TO_SCAN", note: "Deliberately incomplete PDF, for fail-closed error handling.", rule: "PDF parser failure" },
];

export const CASE_BY_ID: Record<string, TestCase> =
  Object.fromEntries(TEST_CASES.map((t) => [t.id, t]));
