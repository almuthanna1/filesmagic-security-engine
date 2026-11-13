// Scan history of the Security Lab: results only (engine, commit, file hash, verdict, findings,
// timing), never file contents. Kept in this browser's localStorage until exported or cleared.

import { useMemo, useSyncExternalStore } from "react";
import type { Engine, Finding, ScanResult, ScannerStatus, Verdict } from "./api";

const STORAGE_KEY = "fm-scan-history-v1";
const MAX_RECORDS = 500;

export interface HistoryRecord {
  recorded_at: string;
  mode: "single" | "compare";
  engine: Engine;
  commit: string;
  request_id: string;
  filename: string;
  sha256: string;
  size_bytes: number;
  detected_format: string;
  verdict: Verdict;
  complete: boolean;
  duration_ms: number;
  findings: Finding[];
  scanners: ScannerStatus[];
  versions: Record<string, string>;
  isolation_required: boolean;
  isolation_missing: string[];
  // Older browser records do not include the detailed control flags.
  isolation?: Record<string, boolean>;
  message: string;
}

export function toRecord(r: ScanResult, mode: HistoryRecord["mode"]): HistoryRecord {
  return {
    recorded_at: new Date().toISOString(),
    mode,
    engine: r.engine,
    commit: r.versions.commit ?? "unknown",
    request_id: r.request_id,
    filename: r.filename,
    sha256: r.sha256,
    size_bytes: r.size_bytes,
    detected_format: r.detected_format,
    verdict: r.verdict,
    complete: r.complete,
    duration_ms: r.duration_ms,
    // Do not persist VBA contents or quoted literals from the uploaded document.
    // Show source only in the immediate scan view; history stores a presence marker.
    findings: r.findings.map((f) => f.rule_id === "ENGINE_VBA_SOURCE"
      ? { ...f, description: "VBA source extracted; source previews are not saved to history.", evidence: [] }
      : f),
    scanners: r.scanners,
    versions: r.versions,
    isolation_required: r.isolation_required ?? false,
    isolation_missing: r.isolation_missing ?? [],
    isolation: { ...r.isolation },
    message: r.message,
  };
}

// A tiny external store over localStorage. `cache` is this tab's latest JSON and the fallback
// when storage is unavailable (private mode, quota).
let cache: string | null = null;
const listeners = new Set<() => void>();

function snapshot(): string {
  if (cache === null) {
    try {
      cache = localStorage.getItem(STORAGE_KEY) ?? "[]";
    } catch {
      cache = "[]";
    }
  }
  return cache;
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function parse(raw: string): HistoryRecord[] {
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

// Returns false when the browser refused to store the records (they stay in this tab only).
function save(records: HistoryRecord[]): boolean {
  cache = JSON.stringify(records.slice(0, MAX_RECORDS));
  listeners.forEach((notify) => notify());
  try {
    localStorage.setItem(STORAGE_KEY, cache);
    return true;
  } catch {
    return false;
  }
}

export function useHistory(): HistoryRecord[] {
  const raw = useSyncExternalStore(subscribe, snapshot, () => "[]");
  return useMemo(() => parse(raw), [raw]);
}

export function addRecords(records: HistoryRecord[]): boolean {
  return save([...records, ...parse(snapshot())]);
}

export function clearHistory(): void {
  save([]);
}

export function csvCell(value: string | number | boolean | null): string {
  let text = value === null ? "" : String(value);
  // Filenames and scanner text are attacker-influenced: stop spreadsheets evaluating them as formulas.
  if (/^\s*[=+\-@]/.test(text) || /^[\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

export function download(name: string, type: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

const COLUMNS: [string, (r: HistoryRecord) => string | number | boolean | null][] = [
  ["recorded_at", (r) => r.recorded_at],
  ["mode", (r) => r.mode],
  ["engine", (r) => r.engine],
  ["commit", (r) => r.commit],
  ["request_id", (r) => r.request_id],
  ["filename", (r) => r.filename],
  ["sha256", (r) => r.sha256],
  ["size_bytes", (r) => r.size_bytes],
  ["detected_format", (r) => r.detected_format],
  ["verdict", (r) => r.verdict],
  ["complete", (r) => r.complete],
  ["duration_ms", (r) => r.duration_ms],
  ["scanner_ms", (r) => r.scanners.map((s) => `${s.name}=${s.duration_ms ?? ""}`).join(";")],
  ["scanner_status", (r) => r.scanners.map((s) => `${s.name}=${s.status}`).join(";")],
  ["findings", (r) => r.findings.map((f) => `${f.scanner}:${f.rule_id ?? f.category}:${f.severity}`).join(";")],
  ["isolation_required", (r) => r.isolation_required],
  ["isolation_missing", (r) => r.isolation_missing.join(";")],
  ["ruleset_sha256", (r) => r.versions.ruleset_sha256 ?? ""],
  ["engine_ruleset_sha256", (r) => r.versions.engine_ruleset_sha256 ?? ""],
  ["engine_version", (r) => r.versions.engine ?? ""],
];

export function historyCsv(records: HistoryRecord[]): string {
  const lines = [COLUMNS.map(([name]) => name).join(",")];
  for (const r of records) lines.push(COLUMNS.map(([, get]) => csvCell(get(r))).join(","));
  return lines.join("\r\n") + "\r\n";
}
