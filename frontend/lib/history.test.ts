import { test } from "node:test";
import assert from "node:assert/strict";
import { csvCell, historyCsv, type HistoryRecord } from "./history.ts";

test("CSV cells are quoted and cannot start a spreadsheet formula", () => {
  assert.equal(csvCell('a "b"'), '"a ""b"""');
  assert.equal(csvCell("=HYPERLINK(1)"), `"'=HYPERLINK(1)"`);
  assert.equal(csvCell(null), '""');
});

test("history CSV has one row per record with engine, commit, hash, verdict, findings and timing", () => {
  const record = {
    recorded_at: "t", mode: "compare", engine: "unified", commit: "abc", request_id: "r", filename: "+x.pdf",
    sha256: "f".repeat(64), size_bytes: 3, detected_format: "pdf", verdict: "SUSPICIOUS", complete: true,
    duration_ms: 12.5, message: "m", isolation_required: false, isolation_missing: [],
    versions: { ruleset_sha256: "r1", engine_ruleset_sha256: "r2", engine: "0.2.0" },
    scanners: [{ name: "pdf", status: "completed", error: null, error_kind: null, error_type: null, duration_ms: 0.5 }],
    findings: [{ scanner: "pdf-chains", category: "c", severity: "MEDIUM", description: "d", rule_id: "ENGINE_PDF_AUTO_CHAIN_SCRIPT" }],
  } as HistoryRecord;
  const [header, row] = historyCsv([record]).trim().split("\r\n");
  assert.ok(header.startsWith("recorded_at,mode,engine,commit,request_id,filename,sha256"));
  assert.ok(row.includes('"unified","abc"') && row.includes(`"'+x.pdf"`) && row.includes('"SUSPICIOUS"'));
  assert.ok(row.includes('"pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT:MEDIUM"') && row.includes('"pdf=0.5"'));
});
