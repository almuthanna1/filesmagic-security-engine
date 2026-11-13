import type { HistoryRecord } from "./history";
import type { ValidationFile } from "./additionalValidationCatalog";
import { directDownloadUrl, pinnedSourceUrl } from "./additionalValidationCatalog.ts";

/**
 * Match only scans performed by this Lab against a downloaded fixture filename.
 * Multiple distinct hashes with the same filename are ambiguous unless the user
 * supplies the 64-digit hash from the actual scan. The source is not verified by
 * the match: that would require comparing against a trusted upstream SHA-256.
 */
export function linkedHistory(
  file: ValidationFile,
  records: HistoryRecord[],
  expectedHash = "",
): HistoryRecord | null {
  const candidates = records.filter(
    r => r.engine === "unified" && r.filename === file.filename &&
      /^[a-f0-9]{64}$/i.test(r.sha256),
  );
  const supplied = expectedHash.trim().toLowerCase();
  if (supplied) {
    if (!/^[a-f0-9]{64}$/.test(supplied)) return null;
    return candidates.find(r => r.sha256.toLowerCase() === supplied) ?? null;
  }
  if (new Set(candidates.map(r => r.sha256.toLowerCase())).size !== 1) return null;
  return candidates[0] ?? null;
}

export function linkedCandidateCount(file: ValidationFile, records: HistoryRecord[]): number {
  return new Set(records.filter(r => r.engine === "unified" && r.filename === file.filename)
    .map(r => r.sha256.toLowerCase())).size;
}

export function completeValidationReport(
  file: ValidationFile,
  scan: HistoryRecord,
  manualNotes = "",
): string {
  const counts = {
    completed: scan.scanners.filter(s => s.status === "completed").length,
    notApplicable: scan.scanners.filter(s => s.status === "not_applicable").length,
    failed: scan.scanners.filter(s => s.status === "failed").length,
  };
  const scannerLines = scan.scanners.map(s =>
    `- ${s.name}: ${s.status}; time=${typeof s.duration_ms === "number" ? s.duration_ms + " ms" : "not reported"}` +
      (s.error ? `; error=${s.error_kind ?? "unknown"}: ${s.error}` : ""),
  );
  const findingLines = scan.findings.flatMap((f, i) => [
    `Finding ${i + 1}: ${f.rule_id || f.category} | severity=${f.severity} | scanner=${f.scanner} | category=${f.category}`,
    `  Description: ${f.description}`,
    ...(f.evidence?.length ? f.evidence.map(e => `  Evidence: ${e}`) : []),
  ]);
  const isolation = scan.isolation === undefined
    ? ["Individual isolation flags: NOT RECORDED in this older browser history entry. Rescan to capture them."]
    : Object.entries(scan.isolation).sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => `- ${key}: ${value}`);
  return [
    "FilesMagic external validation: scan-history evidence",
    `Case: ${file.id} | ${file.filename}`,
    `Source: ${pinnedSourceUrl(file)}`,
    `Direct download: ${directDownloadUrl(file)}`,
    `Source revision: ${file.revision}`,
    `Purpose: ${file.purpose}`,
    `Lab handling: ${file.handling === "offline-only" ? "Offline VM only"
      : file.handling === "hosted-regression" ? "Hosted validation fixture: pinned upstream SHA-256"
      : "Benign candidate; review before testing"}`,
    file.expectedSha256
      ? `Upstream pinned SHA-256: ${file.expectedSha256}; scanned file SHA-256 ${scan.sha256.toLowerCase() === file.expectedSha256.toLowerCase() ? "MATCHED" : "DID NOT MATCH"} the pinned upstream revision.`
      : "Provenance caveat: Matched a local Security Lab history record by filename and, if specified, SHA-256. The upstream source bytes have NOT been independently hash-verified.",
    "",
    "SCAN RESULT (from saved Security Lab history)",
    `Recorded at: ${scan.recorded_at}`,
    `Request ID: ${scan.request_id}`,
    `Engine: ${scan.engine}`,
    `Verdict: ${scan.verdict}`,
    `Message: ${scan.message}`,
    `File SHA-256: ${scan.sha256}`,
    `File size: ${scan.size_bytes} bytes`,
    `Detected format: ${scan.detected_format}`,
    `Complete: ${scan.complete}`,
    `Total time: ${scan.duration_ms} ms`,
    `Scanner outcomes: ${counts.completed} completed / ${counts.notApplicable} not applicable / ${counts.failed} failed`,
    "Scanners:",
    ...scannerLines,
    "",
    "Isolation:",
    `Strict isolation required: ${scan.isolation_required}`,
    `Missing required controls: ${scan.isolation_missing.length ? scan.isolation_missing.join(", ") : "none reported"}`,
    ...isolation,
    "",
    "Versions:",
    `Engine commit: ${scan.commit}`,
    ...Object.entries(scan.versions || {}).sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `- ${key}: ${value}`),
    "",
    `Findings (${scan.findings.length}):`,
    ...(findingLines.length ? findingLines : ["No findings reported."]),
    ...(manualNotes.trim() ? ["", "Manual notes (not verified by the engine):", manualNotes.trim()] : []),
    "",
    "Note: History deliberately omits extracted VBA source previews. Use the live scan screen for those excerpts. Historical records may not have all isolation flags.",
    "A SAFE verdict does not guarantee a harmless document; no real-malware accuracy claim is implied.",
  ].join("\n");
}
