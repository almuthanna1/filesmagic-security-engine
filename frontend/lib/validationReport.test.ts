import { test } from "node:test";
import assert from "node:assert/strict";
import { VALIDATION_FILES } from "./additionalValidationCatalog.ts";
import { completeValidationReport, linkedCandidateCount, linkedHistory } from "./validationReport.ts";
import type { HistoryRecord } from "./history.ts";

const file = VALIDATION_FILES.find(f => f.id === "validation-01")!;
const sha1 = "ea2c517bd7be4628887eb97f630334b93b894f4522d2c0adae263e602d76df92";
const sha2 = "b".repeat(64);
const scan: HistoryRecord = {
  recorded_at: "2026-11-13T16:40:00Z", mode: "single", engine: "unified",
  commit: "ccdb462065fcf3140e5a2295f3754f3c19324ab0",
  request_id: "9ecd06000dc14b4e", filename: file.filename, sha256: sha1,
  size_bytes: 11600, detected_format: "zip", verdict: "SAFE", complete: true, coverage_complete: true, coverage_issues: [],
  duration_ms: 6659.1, message: "No known indicators.",
  scanners: [
    { name: "yara-x", status: "completed", duration_ms: 0.502, error: null, error_kind: null, error_type: null },
    { name: "office", status: "completed", duration_ms: 3.189, error: null, error_kind: null, error_type: null },
    { name: "pdf", status: "not_applicable", duration_ms: 0.003, error: null, error_kind: null, error_type: null },
  ],
  findings: [],
  versions: { engine: "0.2.0", commit: "ccdb462065fcf3140e5a2295f3754f3c19324ab0", "yara-x": "1.21.0" },
  isolation_required: true, isolation_missing: [], isolation: {
    network_verified: true, net_fallback_tunnel_inert: true, net_loopback_only: false,
    network_namespace: true, capabilities_dropped: true,
  },
};

test("links only the unified scan with an unambiguous filename and valid hash", () => {
  const ref = { ...scan, engine: "reference" as const, sha256: sha2 };
  assert.deepEqual(linkedHistory(file, [ref, scan]), scan);
  assert.equal(linkedCandidateCount(file, [ref, scan]), 1);
  assert.equal(linkedHistory(file, [scan], sha1), scan);
  assert.equal(linkedHistory(file, [scan], sha2), null);
  assert.equal(linkedHistory(file, [scan], "abc"), null);
  assert.equal(linkedHistory({ ...file, filename: "other.docx" }, [scan]), null);
});

test("different hashes for one filename require explicit SHA-256 selection", () => {
  const alternate = { ...scan, request_id: "different", sha256: sha2 };
  assert.equal(linkedCandidateCount(file, [alternate, scan]), 2);
  assert.equal(linkedHistory(file, [alternate, scan]), null);
  assert.equal(linkedHistory(file, [alternate, scan], sha1), scan);
  assert.equal(linkedHistory(file, [alternate, scan], sha2), alternate);
});

test("copies detailed scanner, isolation, finding and version data, not a manually asserted verdict", () => {
  const r = completeValidationReport(file, scan, "Reviewed the source");
  assert.ok(r.includes("Verdict: SAFE"));
  assert.ok(r.includes("Request ID: 9ecd06000dc14b4e"));
  assert.ok(r.includes("File SHA-256: " + sha1));
  assert.ok(r.includes("Total time: 6659.1 ms"));
  assert.ok(r.includes("yara-x: completed; time=0.502 ms"));
  assert.ok(r.includes("network_verified: true"));
  assert.ok(r.includes("net_loopback_only: false"));
  assert.ok(r.includes("Engine commit: ccdb4620"));
  assert.ok(r.includes("Findings (0):"));
  assert.ok(r.includes("No findings reported."));
  assert.ok(r.includes("Reviewed the source"));
  assert.ok(r.includes("upstream source bytes have NOT been independently hash-verified"));
});

test("reports missing historical isolation flags without pretending they were verified", () => {
  const old = { ...scan, isolation: undefined, findings: [
    { scanner: "vba-chains", category: "office-vba-source", severity: "INFO" as const,
      rule_id: "ENGINE_VBA_SOURCE", description: "VBA source extracted; source previews are not saved to history.", evidence: [] },
  ] };
  const r = completeValidationReport(file, old);
  assert.ok(r.includes("Individual isolation flags: NOT RECORDED"));
  assert.ok(r.includes("ENGINE_VBA_SOURCE"));
  assert.ok(!r.includes('MsgBox "private phrase"'));
});

test("a copied hosted qpdf report distinguishes pinned source bytes from unverified files", () => {
  const encrypted = VALIDATION_FILES.find(f => f.id === "validation-24")!;
  assert.equal(encrypted.handling, "hosted-regression");
  const matching = completeValidationReport(encrypted, {
    ...scan,
    filename: encrypted.filename,
    sha256: encrypted.expectedSha256!,
    verdict: "UNABLE_TO_SCAN",
  });
  assert.ok(matching.includes("Hosted validation fixture: pinned upstream SHA-256"));
  assert.ok(matching.includes("scanned file SHA-256 MATCHED the pinned upstream revision."));
  assert.ok(matching.includes("Verdict: UNABLE_TO_SCAN"));

  const mismatched = completeValidationReport(encrypted, { ...scan, filename: encrypted.filename });
  assert.ok(mismatched.includes("scanned file SHA-256 DID NOT MATCH"));
});

test("copied oletools clean DOCM result reports the true source revision and hash", () => {
  const docm = VALIDATION_FILES.find(f => f.id === "validation-30")!;
  assert.equal(docm.handling, "hosted-regression");
  const out = completeValidationReport(docm, {
    ...scan, filename: docm.filename, sha256: docm.expectedSha256!,
    detected_format: "zip", verdict: "SAFE",
  });
  assert.ok(out.includes("Case: validation-30 | harmless-clean.docm"));
  assert.ok(out.includes("ec10260989dbc48b9109e3d05d22beee19cf2333"));
  assert.ok(out.includes("scanned file SHA-256 MATCHED the pinned upstream revision."));
  assert.ok(out.includes("Verdict: SAFE"));
});

test("EICAR reports distinguish an unversioned control fingerprint from a pinned Git commit", () => {
  const txt = VALIDATION_FILES.find(f => f.id === "validation-31")!;
  const zip = VALIDATION_FILES.find(f => f.id === "validation-32")!;
  for (const file of [txt, zip]) {
    const report = completeValidationReport(file, {
      ...scan, filename: file.filename, sha256: file.expectedSha256!,
      detected_format: file.filename.endsWith(".zip") ? "zip" : "unknown",
    });
    assert.ok(report.includes("EICAR reference SHA-256: " + file.expectedSha256));
    assert.ok(report.includes("scanned file SHA-256 MATCHED the known EICAR control fingerprint."));
    assert.ok(report.includes("official download is unversioned"));
    assert.ok(!report.includes("MATCHED the pinned upstream revision"));
    const mismatch = completeValidationReport(file, { ...scan, filename: file.filename });
    assert.ok(mismatch.includes("DID NOT MATCH the known EICAR control fingerprint."));
  }
});
