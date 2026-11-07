import { test } from "node:test";
import assert from "node:assert/strict";
import type { Finding, ScanResult } from "./api.ts";
import { compareResults } from "./compare.ts";

const f = (scanner: string, rule_id: string, severity: Finding["severity"], evidence?: string[]): Finding =>
  ({ scanner, category: "x", severity, description: rule_id, rule_id, evidence });

function result(engine: ScanResult["engine"], verdict: ScanResult["verdict"], findings: Finding[],
                over: Partial<ScanResult> = {}): ScanResult {
  return {
    request_id: "r", engine, filename: "f", verdict, findings, message: "m", sha256: "a".repeat(64), size_bytes: 1,
    detected_format: "pdf", complete: true, duration_ms: 100, versions: {}, isolation: {},
    scanners: [{ name: "pdf", status: "completed", error: null, error_kind: null, error_type: null, duration_ms: 1.5 }],
    ...over,
  };
}

test("findings are retained, added or superseded, with the correlation note as the reason", () => {
  const reference = result("reference", "MALICIOUS", [
    f("pdf", "PDF_JAVASCRIPT", "MEDIUM"), f("pdf", "PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD", "HIGH")]);
  const unified = result("unified", "SUSPICIOUS", [
    f("pdf", "PDF_JAVASCRIPT", "MEDIUM"), f("pdf-chains", "ENGINE_PDF_AUTO_CHAIN_SCRIPT", "MEDIUM"),
    f("pdf-chains", "ENGINE_CORRELATION", "INFO", ["replaced PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD (PDF scanner)"])],
    { duration_ms: 112.34, scanners: [{ name: "pdf", status: "completed", error: null, error_kind: null, error_type: null, duration_ms: 2 }] });
  const c = compareResults(reference, unified);
  assert.deepEqual(c.findings.map((x) => [x.change, x.finding.rule_id]), [
    ["retained", "PDF_JAVASCRIPT"], ["superseded", "PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD"],
    ["added", "ENGINE_PDF_AUTO_CHAIN_SCRIPT"]]);
  assert.equal(c.findings[1].reason, "replaced PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD (PDF scanner)");
  assert.equal(c.verdictChanged, true);
  assert.equal(c.durationDeltaMs, 12.3);
  assert.deepEqual(c.scannerMs, { reference: 1.5, unified: 2 });
  assert.deepEqual(c.warnings, []);
});

test("incomplete analyses and undetermined findings become warnings", () => {
  const reference = result("reference", "UNABLE_TO_SCAN", [], {
    complete: false, message: "1 of 1 applicable scanners failed",
    scanners: [{ name: "pdf", status: "failed", error: "x", error_kind: "malformed_input", error_type: "E", duration_ms: 1 }] });
  const unified = result("unified", "SUSPICIOUS", [f("vba-chains", "ENGINE_VBA_CALL_PATH_UNDETERMINED", "INFO")]);
  assert.deepEqual(compareResults(reference, unified).warnings, [
    "Original Engine: analysis incomplete (1 of 1 applicable scanners failed)",
    "Original Engine: scanner pdf failed (malformed_input)",
    "Custom Unified Engine: ENGINE_VBA_CALL_PATH_UNDETERMINED"]);
});

test("results for different files are flagged", () => {
  assert.equal(compareResults(result("reference", "SAFE", []), result("unified", "SAFE", [], { sha256: "b".repeat(64) })).sameFile, false);
});
