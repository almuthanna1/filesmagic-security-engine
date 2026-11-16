// Comparison of one file's results from the original and the custom unified engine.
// Pure functions (no React, no fetch), tested with `npm test` (node --test lib/*.test.ts).

import type { Finding, ScanResult } from "./api";

export type FindingChange = "retained" | "added" | "superseded";

export interface ComparedFinding {
  change: FindingChange;
  finding: Finding;
  // For superseded findings: the correlation note that names this rule, if any.
  reason: string | null;
}

export interface Comparison {
  sameFile: boolean;
  verdictChanged: boolean;
  findings: ComparedFinding[];
  correlation: string[];
  // Whole-scan time (worker start-up included) and detection work (sum of scanner times), unified minus original.
  durationDeltaMs: number;
  scannerMs: { reference: number; unified: number };
  warnings: string[];
}

const CORRELATION = "ENGINE_CORRELATION";

function key(f: Finding): string {
  return `${f.scanner}|${f.rule_id ?? f.category}|${f.severity}`;
}

export function scannerTime(r: ScanResult): number {
  return r.scanners.reduce((sum, s) => sum + (s.duration_ms ?? 0), 0);
}

function incomplete(label: string, r: ScanResult): string[] {
  const out: string[] = [];
  if (!r.complete) out.push(`${label}: analysis incomplete (${r.message})`);
  for (const s of r.scanners) {
    if (s.status === "failed") out.push(`${label}: scanner ${s.name} failed${s.error_kind ? ` (${s.error_kind})` : ""}`);
  }
  for (const f of r.findings) {
    if (f.rule_id && /UNDETERMINED|COVERAGE_LIMITED|CHAINS_REPAIRED/.test(f.rule_id)) {
      out.push(`${label}: ${f.rule_id}`);
    }
  }
  return out;
}

// The unified engine runs every original scanner, so an original finding missing from the unified
// result was removed by correlation ("superseded"); the correlation note names the rule.
export function compareResults(reference: ScanResult, unified: ScanResult): Comparison {
  const correlation = unified.findings.filter((f) => f.rule_id === CORRELATION)
    .flatMap((f) => (f.evidence?.length ? f.evidence : [f.description]));
  const unifiedKeys = new Set(unified.findings.map(key));
  const referenceKeys = new Set(reference.findings.map(key));
  const findings: ComparedFinding[] = [
    ...reference.findings.map((f) => unifiedKeys.has(key(f))
      ? { change: "retained" as const, finding: f, reason: null }
      : { change: "superseded" as const, finding: f,
          reason: correlation.find((note) => f.rule_id !== null && note.includes(f.rule_id)) ?? null }),
    ...unified.findings.filter((f) => f.rule_id !== CORRELATION && !referenceKeys.has(key(f)))
      .map((f) => ({ change: "added" as const, finding: f, reason: null })),
  ];
  return {
    sameFile: reference.sha256 === unified.sha256,
    verdictChanged: reference.verdict !== unified.verdict,
    findings,
    correlation,
    durationDeltaMs: Math.round((unified.duration_ms - reference.duration_ms) * 10) / 10,
    scannerMs: { reference: scannerTime(reference), unified: scannerTime(unified) },
    warnings: [...incomplete("Original Engine", reference), ...incomplete("Custom Unified Engine", unified)],
  };
}
