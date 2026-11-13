// Third-party file paths were confirmed in the source GitHub repositories at their pinned commits.
// Repository fixtures do not automatically establish that files are benign or malware.
// "PASS"/"FAIL" in veraPDF means PDF/A specification conformance only.
export type ValidationGroup = "Apache POI Office files" | "veraPDF PDF conformance" | "qpdf PDF parser cases" | "oletools Office controls" | "EICAR harmless AV controls";
export type ValidationHandling = "reviewed-benign-candidate" | "hosted-regression" | "offline-only";
export type ValidationFile = {
  id: string;
  group: ValidationGroup;
  repository: string;
  revision: string;
  path: string;
  filename: string;
  purpose: string;
  handling: ValidationHandling;
  // Required for hosted malformed/encrypted regression fixtures. A filename is not provenance.
  expectedSha256?: string;
  downloadOverride?: string;
  sourceOverride?: string;
};

export const VALIDATION_GROUPS: ValidationGroup[] = [
  "Apache POI Office files",
  "veraPDF PDF conformance",
  "qpdf PDF parser cases",
  "oletools Office controls",
  "EICAR harmless AV controls",
];

export const VALIDATION_FILES: ValidationFile[] = [
  {
    "id": "validation-01",
    "group": "Apache POI Office files",
    "repository": "apache/poi",
    "revision": "e0658769cb7f7da25ec09178805e04069dedc6ed",
    "path": "test-data/document/SampleDoc.docx",
    "filename": "SampleDoc.docx",
    "purpose": "Ordinary Word DOCX from Apache POI's document fixtures.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-02",
    "group": "Apache POI Office files",
    "repository": "apache/poi",
    "revision": "e0658769cb7f7da25ec09178805e04069dedc6ed",
    "path": "test-data/document/SampleDoc.doc",
    "filename": "SampleDoc.doc",
    "purpose": "Legacy binary Word format compatibility.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-03",
    "group": "Apache POI Office files",
    "repository": "apache/poi",
    "revision": "e0658769cb7f7da25ec09178805e04069dedc6ed",
    "path": "test-data/document/EmptyDocumentWithHeaderFooter.docx",
    "filename": "EmptyDocumentWithHeaderFooter.docx",
    "purpose": "Empty Word file with header/footer structures.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-04",
    "group": "Apache POI Office files",
    "repository": "apache/poi",
    "revision": "e0658769cb7f7da25ec09178805e04069dedc6ed",
    "path": "test-data/document/ComplexNumberedLists.docx",
    "filename": "ComplexNumberedLists.docx",
    "purpose": "Numbering and nested list structures.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-05",
    "group": "Apache POI Office files",
    "repository": "apache/poi",
    "revision": "e0658769cb7f7da25ec09178805e04069dedc6ed",
    "path": "test-data/document/Headers.docx",
    "filename": "Headers.docx",
    "purpose": "Word header content and relationships.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-06",
    "group": "Apache POI Office files",
    "repository": "apache/poi",
    "revision": "e0658769cb7f7da25ec09178805e04069dedc6ed",
    "path": "test-data/spreadsheet/SampleSS.xlsx",
    "filename": "SampleSS.xlsx",
    "purpose": "Ordinary Excel OOXML spreadsheet.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-07",
    "group": "Apache POI Office files",
    "repository": "apache/poi",
    "revision": "e0658769cb7f7da25ec09178805e04069dedc6ed",
    "path": "test-data/spreadsheet/SampleSS.xls",
    "filename": "SampleSS.xls",
    "purpose": "Legacy binary Excel workbook.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-08",
    "group": "Apache POI Office files",
    "repository": "apache/poi",
    "revision": "e0658769cb7f7da25ec09178805e04069dedc6ed",
    "path": "test-data/spreadsheet/ExcelTables.xlsx",
    "filename": "ExcelTables.xlsx",
    "purpose": "Excel table metadata and relationships.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-09",
    "group": "Apache POI Office files",
    "repository": "apache/poi",
    "revision": "e0658769cb7f7da25ec09178805e04069dedc6ed",
    "path": "test-data/slideshow/SampleShow.pptx",
    "filename": "SampleShow.pptx",
    "purpose": "Ordinary OOXML PowerPoint presentation.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-10",
    "group": "Apache POI Office files",
    "repository": "apache/poi",
    "revision": "e0658769cb7f7da25ec09178805e04069dedc6ed",
    "path": "test-data/slideshow/SampleShow.ppt",
    "filename": "SampleShow.ppt",
    "purpose": "Legacy PowerPoint presentation.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-11",
    "group": "Apache POI Office files",
    "repository": "apache/poi",
    "revision": "e0658769cb7f7da25ec09178805e04069dedc6ed",
    "path": "test-data/slideshow/bar-chart.pptx",
    "filename": "bar-chart.pptx",
    "purpose": "PowerPoint embedded chart structures.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-12",
    "group": "Apache POI Office files",
    "repository": "apache/poi",
    "revision": "e0658769cb7f7da25ec09178805e04069dedc6ed",
    "path": "test-data/slideshow/smartart-simple.pptx",
    "filename": "smartart-simple.pptx",
    "purpose": "PowerPoint SmartArt and relationships.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-13",
    "group": "veraPDF PDF conformance",
    "repository": "veraPDF/veraPDF-corpus",
    "revision": "bb75f4f0073d9350dfd058c0162a367e6fadf25e",
    "path": "PDF_A-3b/6.8 Embedded files/veraPDF test suite 6-8-t02-pass-a.pdf",
    "filename": "veraPDF test suite 6-8-t02-pass-a.pdf",
    "purpose": "PDF/A-3b embedded-file conformance PASS fixture; tests attachment handling.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-14",
    "group": "veraPDF PDF conformance",
    "repository": "veraPDF/veraPDF-corpus",
    "revision": "bb75f4f0073d9350dfd058c0162a367e6fadf25e",
    "path": "PDF_A-3b/6.8 Embedded files/veraPDF test suite 6-8-t02-pass-b.pdf",
    "filename": "veraPDF test suite 6-8-t02-pass-b.pdf",
    "purpose": "PDF/A-3b embedded-file conformance PASS variant.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-15",
    "group": "veraPDF PDF conformance",
    "repository": "veraPDF/veraPDF-corpus",
    "revision": "bb75f4f0073d9350dfd058c0162a367e6fadf25e",
    "path": "PDF_A-3b/6.8 Embedded files/veraPDF test suite 6-8-t02-pass-e.pdf",
    "filename": "veraPDF test suite 6-8-t02-pass-e.pdf",
    "purpose": "PDF/A-3b embedded-file conformance PASS variant.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-16",
    "group": "veraPDF PDF conformance",
    "repository": "veraPDF/veraPDF-corpus",
    "revision": "bb75f4f0073d9350dfd058c0162a367e6fadf25e",
    "path": "PDF_A-3b/6.8 Embedded files/veraPDF test suite 6-8-t02-fail-a.pdf",
    "filename": "veraPDF test suite 6-8-t02-fail-a.pdf",
    "purpose": "PDF/A-3b embedded-file conformance FAIL fixture; not a malware label.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-17",
    "group": "veraPDF PDF conformance",
    "repository": "veraPDF/veraPDF-corpus",
    "revision": "bb75f4f0073d9350dfd058c0162a367e6fadf25e",
    "path": "PDF_A-3b/6.8 Embedded files/veraPDF test suite 6-8-t02-fail-b.pdf",
    "filename": "veraPDF test suite 6-8-t02-fail-b.pdf",
    "purpose": "PDF/A-3b embedded-file conformance FAIL variant; not a malware label.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-18",
    "group": "veraPDF PDF conformance",
    "repository": "veraPDF/veraPDF-corpus",
    "revision": "bb75f4f0073d9350dfd058c0162a367e6fadf25e",
    "path": "PDF_A-3b/6.8 Embedded files/veraPDF test suite 6-8-t02-fail-d.pdf",
    "filename": "veraPDF test suite 6-8-t02-fail-d.pdf",
    "purpose": "PDF/A-3b embedded-file conformance FAIL variant; not a malware label.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-19",
    "group": "veraPDF PDF conformance",
    "repository": "veraPDF/veraPDF-corpus",
    "revision": "bb75f4f0073d9350dfd058c0162a367e6fadf25e",
    "path": "PDF_A-3b/6.8 Embedded files/veraPDF test suite 6-8-t02-pass-g.pdf",
    "filename": "veraPDF test suite 6-8-t02-pass-g.pdf",
    "purpose": "Additional PDF/A-3b conformance PASS variant.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-20",
    "group": "qpdf PDF parser cases",
    "repository": "qpdf/qpdf",
    "revision": "4eba95899886e851cc41d76886483b347612f2a8",
    "path": "qpdf/qtest/qpdf/11-pages.pdf",
    "filename": "11-pages.pdf",
    "purpose": "Ordinary multipage PDF for parser compatibility.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-21",
    "group": "qpdf PDF parser cases",
    "repository": "qpdf/qpdf",
    "revision": "4eba95899886e851cc41d76886483b347612f2a8",
    "path": "qpdf/qtest/qpdf/11-pages-with-labels.pdf",
    "filename": "11-pages-with-labels.pdf",
    "purpose": "Multipage PDF with page labels.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-22",
    "group": "qpdf PDF parser cases",
    "repository": "qpdf/qpdf",
    "revision": "4eba95899886e851cc41d76886483b347612f2a8",
    "path": "qpdf/qtest/qpdf/annotation-no-resources.pdf",
    "filename": "annotation-no-resources.pdf",
    "purpose": "PDF annotation with unusual resource structure.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-23",
    "group": "qpdf PDF parser cases",
    "repository": "qpdf/qpdf",
    "revision": "4eba95899886e851cc41d76886483b347612f2a8",
    "path": "qpdf/qtest/qpdf/add-attachments-1.pdf",
    "filename": "add-attachments-1.pdf",
    "purpose": "PDF attachment regression fixture; a warning may be a false positive.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-24",
    "group": "qpdf PDF parser cases",
    "repository": "qpdf/qpdf",
    "revision": "4eba95899886e851cc41d76886483b347612f2a8",
    "path": "qpdf/qtest/qpdf/V4-aes.pdf",
    "filename": "V4-aes.pdf",
    "purpose": "Encrypted PDF. Incomplete analysis should never silently return SAFE.",
    "handling": "hosted-regression",
    "expectedSha256": "1d8a812844b8d8c7ba085a627eb3b7ab52aa651c6143ca07315084220a113240"
  },
  {
    "id": "validation-25",
    "group": "qpdf PDF parser cases",
    "repository": "qpdf/qpdf",
    "revision": "4eba95899886e851cc41d76886483b347612f2a8",
    "path": "qpdf/qtest/qpdf/bad-data.pdf",
    "filename": "bad-data.pdf",
    "purpose": "Deliberately damaged PDF data; verify fail-closed parsing.",
    "handling": "hosted-regression",
    "expectedSha256": "919998d65cecd40f1c33cf56853a517acc0e18f438fcc098f4c17a086c875057"
  },
  {
    "id": "validation-26",
    "group": "qpdf PDF parser cases",
    "repository": "qpdf/qpdf",
    "revision": "4eba95899886e851cc41d76886483b347612f2a8",
    "path": "qpdf/qtest/qpdf/bad-xref.pdf",
    "filename": "bad-xref.pdf",
    "purpose": "Damaged cross-reference data; test parser error handling.",
    "handling": "hosted-regression",
    "expectedSha256": "5895dfedf978f600b12e29643617dbb111869b60526d957878e349571e1467d1"
  },
  {
    "id": "validation-27",
    "group": "qpdf PDF parser cases",
    "repository": "qpdf/qpdf",
    "revision": "4eba95899886e851cc41d76886483b347612f2a8",
    "path": "qpdf/qtest/qpdf/bad-direct-root.pdf",
    "filename": "bad-direct-root.pdf",
    "purpose": "Malformed PDF root dictionary; test parser resilience.",
    "handling": "hosted-regression",
    "expectedSha256": "0d7549c02c38717627deb10d1155c1b513d35036208e77d687597c77d04dc3b4"
  },
  {
    "id": "validation-28",
    "group": "qpdf PDF parser cases",
    "repository": "qpdf/qpdf",
    "revision": "4eba95899886e851cc41d76886483b347612f2a8",
    "path": "qpdf/qtest/qpdf/append-xref-loop.pdf",
    "filename": "append-xref-loop.pdf",
    "purpose": "Unusual cross-reference cycle; test resource bounds.",
    "handling": "hosted-regression",
    "expectedSha256": "7c67daccc433f574fbaf815d0d376cc79f40f95082ef1b231af436e9f7d27091"
  },
  {
    "id": "validation-29",
    "group": "oletools Office controls",
    "repository": "decalage2/oletools",
    "revision": "ec10260989dbc48b9109e3d05d22beee19cf2333",
    "path": "tests/test-data/msodde/harmless-clean.doc",
    "filename": "harmless-clean.doc",
    "purpose": "oletools clean-control legacy Word document.",
    "handling": "reviewed-benign-candidate"
  },
  {
    "id": "validation-30",
    "group": "oletools Office controls",
    "repository": "decalage2/oletools",
    "revision": "ec10260989dbc48b9109e3d05d22beee19cf2333",
    "path": "tests/test-data/msodde/harmless-clean.docm",
    "filename": "harmless-clean.docm",
    "purpose": "oletools clean-control macro-enabled Word format; verify behavior, not label alone.",
    "handling": "offline-only"
  },
  {
    "id": "validation-31",
    "group": "EICAR harmless AV controls",
    "repository": "Official EICAR",
    "revision": "Unversioned official test file",
    "path": "",
    "filename": "eicar.com.txt",
    "purpose": "Harmless 68-byte antivirus test string. The current custom rules may not contain an EICAR signature; SAFE would not by itself establish a malware detection defect.",
    "handling": "offline-only",
    "downloadOverride": "https://secure.eicar.org/eicar.com.txt",
    "sourceOverride": "https://www.eicar.org/download-anti-malware-testfile/"
  },
  {
    "id": "validation-32",
    "group": "EICAR harmless AV controls",
    "repository": "Official EICAR",
    "revision": "Unversioned official test file",
    "path": "",
    "filename": "eicar.com.zip",
    "purpose": "The same inert AV test string wrapped in ZIP. Used to check AV/archive support, which this research engine may not implement.",
    "handling": "offline-only",
    "downloadOverride": "https://secure.eicar.org/eicar.com.zip",
    "sourceOverride": "https://www.eicar.org/download-anti-malware-testfile/"
  }
] as ValidationFile[];

function encodeGitHubPath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}

export function directDownloadUrl(file: ValidationFile): string {
  if (file.downloadOverride) return file.downloadOverride;
  return `https://raw.githubusercontent.com/${file.repository}/${file.revision}/${encodeGitHubPath(file.path)}`;
}

export function pinnedSourceUrl(file: ValidationFile): string {
  if (file.sourceOverride) return file.sourceOverride;
  return `https://github.com/${file.repository}/blob/${file.revision}/${encodeGitHubPath(file.path)}`;
}


/**
 * The hosted inline Lab accepts unique catalog filenames that are either reviewed
 * benign candidates or pinned qpdf parser regression fixtures. This UI gate is not
 * a security boundary; the backend must still validate every file.
 */
export function hostedValidationCandidate(filename: string): ValidationFile | null {
  const matches = VALIDATION_FILES.filter(f => f.filename.toLowerCase() === filename.toLowerCase());
  return matches.length === 1 && matches[0].handling !== "offline-only"
    ? matches[0] : null;
}

/** Hosted stress-test fixtures must match the bytes from the pinned qpdf commit. */
export function matchesPinnedValidationHash(file: ValidationFile, actualSha256: string): boolean {
  return !file.expectedSha256 ||
    /^[a-f0-9]{64}$/i.test(actualSha256) &&
    file.expectedSha256.toLowerCase() === actualSha256.toLowerCase();
}
