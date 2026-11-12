export type ExternalLabel = "BENIGN" | "SUSPICIOUS FEATURE" | "MALWARE-LABELED";
export type ExternalTarget = "SAFE" | "NON_SAFE";
export type ExternalCase = {
  id: string;
  filename: string;
  format: string;
  source: string;
  githubUrl: string;
  sourceLabel: ExternalLabel;
  target: ExternalTarget;
  purpose: string;
  caveat: string;
};

// Revisions are pinned so the cited source file does not silently change.
// These are third-party artifacts, not generated fixtures or verified scanner outcomes.
const PDF = "https://github.com/tinytoolkit-org/pdf-sample-files/blob/4fd733c47ead5446b06372ab910cb78d1c7da55e/out";
const OLETOOLS = "https://github.com/decalage2/oletools/blob/ec10260989dbc48b9109e3d05d22beee19cf2333/tests/test-data";
const DIKE = "https://github.com/iosifache/DikeDataset/blob/5200762e5db1d33b77a125a6964fed49b3c2dd2d/files/malware";

export const EXTERNAL_TEST_CASES: ExternalCase[] = [
  {
    id: "external-01",
    filename: "sample-1-page.pdf",
    format: "PDF",
    source: "tinytoolkit PDF samples",
    githubUrl: PDF + "/sample-1-page.pdf",
    sourceLabel: "BENIGN",
    target: "SAFE",
    purpose: "Ordinary single-page PDF. Baseline PDF false-positive control.",
    caveat: "Benign according to the publisher; a scanner verdict is still independent.",
  },
  {
    id: "external-02",
    filename: "sample-scanned.pdf",
    format: "PDF",
    source: "tinytoolkit PDF samples",
    githubUrl: PDF + "/sample-scanned.pdf",
    sourceLabel: "BENIGN",
    target: "SAFE",
    purpose: "Image-only scanned pages, without a text layer.",
    caveat: "Tests benign PDF handling with non-text page content.",
  },
  {
    id: "external-03",
    filename: "harmless-clean.docx",
    format: "DOCX",
    source: "oletools fixtures",
    githubUrl: OLETOOLS + "/msodde/harmless-clean.docx",
    sourceLabel: "BENIGN",
    target: "SAFE",
    purpose: "Office document identified as clean in the oletools fixture set.",
    caveat: "Independent Office false-positive control.",
  },
  {
    id: "external-04",
    filename: "sample-with-attachments.pdf",
    format: "PDF",
    source: "tinytoolkit PDF samples",
    githubUrl: PDF + "/sample-with-attachments.pdf",
    sourceLabel: "SUSPICIOUS FEATURE",
    target: "NON_SAFE",
    purpose: "Benign PDF containing text/CSV embedded attachments.",
    caveat: "A non-SAFE result is a structural indicator, not proof of malware. This is a known-benign false-positive stress test.",
  },
  {
    id: "external-05",
    filename: "dde-test.docx",
    format: "DOCX",
    source: "oletools fixtures",
    githubUrl: OLETOOLS + "/msodde/dde-test.docx",
    sourceLabel: "SUSPICIOUS FEATURE",
    target: "NON_SAFE",
    purpose: "Office DDE field test. Look for DDE-related Office findings.",
    caveat: "Contains a risk indicator, not an independently confirmed malicious payload.",
  },
  {
    id: "external-06",
    filename: "sample_with_vba.ppt",
    format: "PPT",
    source: "oletools fixtures",
    githubUrl: OLETOOLS + "/olevba/sample_with_vba.ppt",
    sourceLabel: "SUSPICIOUS FEATURE",
    target: "NON_SAFE",
    purpose: "Legacy PowerPoint with a VBA macro. Look for Office macro findings.",
    caveat: "Macro presence alone is not proof of maliciousness.",
  },
  {
    id: "external-07",
    filename: "sample_with_lnk_file.doc",
    format: "DOC",
    source: "oletools fixtures",
    githubUrl: OLETOOLS + "/oleobj/sample_with_lnk_file.doc",
    sourceLabel: "SUSPICIOUS FEATURE",
    target: "NON_SAFE",
    purpose: "Legacy Word sample with an embedded LNK object.",
    caveat: "Do not open the document in Word. The expected non-SAFE result is a testing goal, not a confirmed outcome.",
  },
  {
    id: "external-08",
    filename: "000d7c0a7ef796e464de11a2488d918c73106f3ed67fa74aee98e048a3cfa570.ole",
    format: "OLE",
    source: "DikeDataset",
    githubUrl: DIKE + "/000d7c0a7ef796e464de11a2488d918c73106f3ed67fa74aee98e048a3cfa570.ole",
    sourceLabel: "MALWARE-LABELED",
    target: "NON_SAFE",
    purpose: "Independently malware-labeled OLE document. Measure Office/YARA-X detection.",
    caveat: "Dike labels are derived from antivirus votes; exact payload and expected rule match have not been independently verified.",
  },
  {
    id: "external-09",
    filename: "00403751b3d57bb7db3462a50f8d92445df3848c45c939fd24a81d763844e1b9.ole",
    format: "OLE",
    source: "DikeDataset",
    githubUrl: DIKE + "/00403751b3d57bb7db3462a50f8d92445df3848c45c939fd24a81d763844e1b9.ole",
    sourceLabel: "MALWARE-LABELED",
    target: "NON_SAFE",
    purpose: "Second malware-labeled OLE file, with different bytes and size.",
    caveat: "Scanner outcome is unknown until tested in the isolated local environment.",
  },
  {
    id: "external-10",
    filename: "004b9a020076d8317b6e57259eff30a147253aafc450379efc2c62a61fcd42ef.ole",
    format: "OLE",
    source: "DikeDataset",
    githubUrl: DIKE + "/004b9a020076d8317b6e57259eff30a147253aafc450379efc2c62a61fcd42ef.ole",
    sourceLabel: "MALWARE-LABELED",
    target: "NON_SAFE",
    purpose: "Third malware-labeled OLE file. Assess robustness across distinct samples.",
    caveat: "A SAFE result is a potential detection miss to investigate, not proof the source label is wrong.",
  },
];
