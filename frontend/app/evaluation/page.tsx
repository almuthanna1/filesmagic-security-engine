"use client";

import { useId, useMemo, useState, useSyncExternalStore } from "react";
import FileDropzone, { formatBytes } from "@/components/FileDropzone";
import IsolationReport from "@/components/IsolationReport";
import LabNav from "@/components/LabNav";
import ScanResultView from "@/components/ScanResultView";
import {
  ApiError,
  scanFile,
  sha256Hex,
  type Finding,
  type ScannerStatus,
  type ScanResult,
  type Verdict,
} from "@/lib/api";
import styles from "../page.module.css";
import table from "@/components/ScanResultView.module.css";

// Records hold scan RESULTS only (hashes, findings, metadata), never file contents. They stay in
// this browser's localStorage until exported or cleared; nothing is sent to any third party.
const STORAGE_KEY = "fm-evaluation-records-v1";

type Expected = "MALICIOUS" | "BENIGN";

interface EvaluationRecord {
  recorded_at: string;
  request_id: string;
  filename: string;
  sha256: string;
  size_bytes: number;
  detected_format: string;
  source_dataset: string;
  expected: Expected;
  verdict: Verdict | null;
  outcome: string;
  complete: boolean;
  duration_ms: number | null;
  rule_ids: string[];
  findings: Finding[];
  scanners: ScannerStatus[];
  errors: string[];
  versions: Record<string, string>;
  isolation_required: boolean;
  isolation: Record<string, boolean>;
  isolation_missing: string[];
  message: string;
}

function outcomeOf(expected: Expected, verdict: Verdict | null): string {
  if (verdict === null || verdict === "UNABLE_TO_SCAN") return "Inconclusive / unable to scan";
  if (expected === "MALICIOUS") {
    return { MALICIOUS: "Detected as malicious", SUSPICIOUS: "Detected as suspicious", SAFE: "Missed / SAFE" }[verdict];
  }
  return verdict === "SAFE" ? "Correct / SAFE" : `False positive (${verdict.toLowerCase()})`;
}

function fromResult(r: ScanResult, filename: string, source: string, expected: Expected): EvaluationRecord {
  return {
    recorded_at: new Date().toISOString(),
    request_id: r.request_id,
    filename,
    sha256: r.sha256,
    size_bytes: r.size_bytes,
    detected_format: r.detected_format,
    source_dataset: source,
    expected,
    verdict: r.verdict,
    outcome: outcomeOf(expected, r.verdict),
    complete: r.complete,
    duration_ms: r.duration_ms,
    rule_ids: [...new Set(r.findings.map((f) => f.rule_id ?? f.category))].sort(),
    findings: r.findings,
    scanners: r.scanners,
    errors: r.scanners.filter((s) => s.error).map((s) => `${s.name} [${s.error_kind ?? "error"}]: ${s.error}`),
    versions: r.versions,
    isolation_required: r.isolation_required ?? false,
    isolation: r.isolation,
    isolation_missing: r.isolation_missing ?? [],
    message: r.message,
  };
}

const CSV_COLUMNS: [string, (r: EvaluationRecord) => string | number | boolean | null][] = [
  ["recorded_at", (r) => r.recorded_at],
  ["request_id", (r) => r.request_id ?? ""],
  ["filename", (r) => r.filename],
  ["sha256", (r) => r.sha256],
  ["size_bytes", (r) => r.size_bytes],
  ["detected_format", (r) => r.detected_format],
  ["source_dataset", (r) => r.source_dataset],
  ["expected", (r) => r.expected],
  ["verdict", (r) => r.verdict],
  ["outcome", (r) => r.outcome],
  ["complete", (r) => r.complete],
  ["duration_ms", (r) => r.duration_ms],
  ["rule_ids", (r) => r.rule_ids.join(";")],
  ["findings", (r) => r.findings.map((f) => `${f.scanner}:${f.rule_id ?? f.category}:${f.severity}`).join(";")],
  ["scanner_status", (r) => r.scanners.map((s) => `${s.name}=${s.status}`).join(";")],
  ["errors", (r) => r.errors.join(" | ")],
  ["isolation_required", (r) => r.isolation_required ?? ""],
  ["isolation", (r) => Object.entries(r.isolation ?? {}).map(([k, v]) => `${k}=${v}`).join(";")],
  ["isolation_missing", (r) => (r.isolation_missing ?? []).join(";")],
  ["network_verified", (r) => r.isolation?.network_verified ?? ""],
  ["net_interfaces_safe", (r) => r.isolation?.net_interfaces_safe ?? ""],
  ["net_loopback_only", (r) => r.isolation?.net_loopback_only ?? ""],
  ["net_fallback_tunnel_inert", (r) => r.isolation?.net_fallback_tunnel_inert ?? ""],
  ["capabilities_dropped", (r) => r.isolation?.capabilities_dropped ?? ""],
  ["engine_version", (r) => r.versions?.engine ?? ""],
  ["ruleset_sha256", (r) => r.versions?.ruleset_sha256 ?? ""],
  ["scanner_versions", (r) => Object.entries(r.versions ?? {}).filter(([k]) => !["engine", "ruleset_sha256"].includes(k)).map(([k, v]) => `${k}=${v}`).join(";")],
];

function csvCell(value: string | number | boolean | null): string {
  let text = value === null ? "" : String(value);
  // Filenames and scanner text are attacker-influenced: stop spreadsheets evaluating them as formulas.
  if (/^\s*[=+\-@]/.test(text) || /^[\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function download(name: string, type: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

// Records as a tiny external store over localStorage. `cache` is this tab's latest JSON and the
// fallback when storage is unavailable (private mode, quota).
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

function parseRecords(raw: string): EvaluationRecord[] {
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export default function EvaluationPage() {
  const sourceId = useId();
  const expectedId = useId();
  const [file, setFile] = useState<File | null>(null);
  const [source, setSource] = useState("");
  const [expected, setExpected] = useState<Expected>("MALICIOUS");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [latest, setLatest] = useState<ScanResult | null>(null);
  const raw = useSyncExternalStore(subscribe, snapshot, () => "[]");
  const records = useMemo(() => parseRecords(raw), [raw]);

  function save(next: EvaluationRecord[]) {
    cache = JSON.stringify(next);
    listeners.forEach((notify) => notify());
    try {
      localStorage.setItem(STORAGE_KEY, cache);
    } catch {
      setError("Could not save records in this browser; export them before leaving the page.");
    }
  }

  async function handleScan() {
    if (!file || !source.trim()) return;
    setScanning(true);
    setError(null);
    setLatest(null);
    try {
      const result = await scanFile(file);
      setLatest(result);
      save([fromResult(result, file.name, source.trim(), expected), ...records]);
    } catch (e) {
      const reason = e instanceof ApiError ? e.message : "Unexpected error while scanning the file.";
      setError(reason);
      // The attempt is still a research outcome: the engine could not produce a verdict.
      save([
        {
          recorded_at: new Date().toISOString(),
          request_id: "",
          filename: file.name,
          sha256: await sha256Hex(file).catch(() => ""),
          size_bytes: file.size,
          detected_format: "not determined",
          source_dataset: source.trim(),
          expected,
          verdict: null,
          outcome: outcomeOf(expected, null),
          complete: false,
          duration_ms: null,
          rule_ids: [],
          findings: [],
          scanners: [],
          errors: [reason],
          versions: {},
          isolation_required: false,
          isolation: {},
          isolation_missing: [],
          message: "",
        },
        ...records,
      ]);
    } finally {
      setScanning(false);
    }
  }

  function exportCsv() {
    const lines = [CSV_COLUMNS.map(([name]) => name).join(",")];
    for (const r of records) lines.push(CSV_COLUMNS.map(([, get]) => csvCell(get(r))).join(","));
    download("filesmagic-evaluation.csv", "text/csv", lines.join("\r\n") + "\r\n");
  }

  function exportJson() {
    download("filesmagic-evaluation.json", "application/json", JSON.stringify(records, null, 2));
  }

  function clearRecords() {
    if (window.confirm(`Delete all ${records.length} records from this browser? Export them first if needed.`)) save([]);
  }

  return (
    <main className={styles.main}>
      <header className={styles.header}>
        <p className={styles.eyebrow}>Research workflow</p>
        <h1>Malware Evaluation</h1>
        <p className={styles.intro}>
          Scan independently labelled samples one at a time and record the expected classification next to the
          engine&apos;s observed verdict. Only results are kept (in this browser); file contents are never stored.
        </p>
        <p className={styles.intro}>Hosted research staging is for benign and inert test files only. Do not upload genuine malware; approved malicious-document studies must remain offline.</p>
        <LabNav />
      </header>


      <section className={`${styles.panel} ${styles.gap}`} aria-labelledby="sample-heading">
        <h2 id="sample-heading" className={styles.panelHeading}>
          Sample
        </h2>
        <FileDropzone file={file} disabled={scanning} onSelect={(f) => { setFile(f); setLatest(null); setError(null); }} />

        <div className={styles.actions}>
          <div>
            <label htmlFor={sourceId} className={styles.fieldLabel}>
              Source dataset
            </label>
            <input id={sourceId} className={styles.input} value={source} maxLength={200}
                   placeholder="e.g. MalwareBazaar 2026-10 export" onChange={(e) => setSource(e.target.value)} />
          </div>
          <div>
            <label htmlFor={expectedId} className={styles.fieldLabel}>
              Independently verified classification
            </label>
            <select id={expectedId} className={styles.input} value={expected}
                    onChange={(e) => setExpected(e.target.value as Expected)}>
              <option value="MALICIOUS">Malicious</option>
              <option value="BENIGN">Benign</option>
            </select>
          </div>
        </div>

        <div className={styles.actions}>
          <button type="button" className={styles.button} onClick={handleScan}
                  disabled={scanning || !file || !source.trim()}>
            {scanning ? "Scanning…" : "Scan and record"}
          </button>
          <p className={styles.status} role="status" aria-live="polite">
            {scanning ? "Uploading and analysing the sample…" : !file || !source.trim() ? "Select a file and name its source dataset." : ""}
          </p>
        </div>

        {error && (
          <div className={styles.error} role="alert">
            <strong>Scan failed; recorded as inconclusive.</strong> {error}
          </div>
        )}

        {latest && <ScanResultView result={latest} />}
      </section>

      <section className={styles.panel} aria-labelledby="records-heading">
        <h2 id="records-heading" className={styles.panelHeading}>
          Recorded results ({records.length})
        </h2>
        <div className={styles.actions} style={{ marginTop: 0, marginBottom: 16 }}>
          <button type="button" className={styles.button} onClick={exportCsv} disabled={!records.length}>
            Export CSV
          </button>
          <button type="button" className={styles.button} onClick={exportJson} disabled={!records.length}>
            Export JSON
          </button>
          <button type="button" className={styles.linkButton} onClick={clearRecords} disabled={!records.length}>
            Clear records
          </button>
        </div>
        {records.length === 0 ? (
          <p className={table.empty}>No samples recorded yet.</p>
        ) : (
          <div className={table.tableWrap}>
            <table className={table.table}>
              <thead>
                <tr>
                  <th scope="col">Sample</th>
                  <th scope="col">Expected</th>
                  <th scope="col">Verdict</th>
                  <th scope="col">Outcome</th>
                  <th scope="col">Rules</th>
                  <th scope="col">Complete</th>
                  <th scope="col">Time</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.recorded_at + r.sha256}>
                    <td>
                      <span className={table.mono}>{r.filename}</span>
                      <br />
                      <span className={table.mono} title={r.sha256}>{r.sha256.slice(0, 16)}…</span>
                      <br />
                      {formatBytes(r.size_bytes)} · {r.detected_format} · {r.source_dataset}
                      <details>
                        <summary>Request and isolation details</summary>
                        <p className={table.mono}>Request ID: {r.request_id || "not available"}</p>
                        <p className={table.mono}>Ruleset SHA-256: {r.versions?.ruleset_sha256 || "not available"}</p>
                        <p className={table.mono}>Scanner statuses: {(r.scanners ?? []).map((s) => `${s.name}=${s.status}`).join("; ") || "not available"}</p>
                        <IsolationReport isolation={r.isolation ?? {}} required={r.isolation_required} missing={r.isolation_missing} />
                      </details>
                    </td>
                    <td>{r.expected}</td>
                    <td>{r.verdict ?? "—"}</td>
                    <td>{r.outcome}</td>
                    <td className={table.mono}>{r.rule_ids.join(", ") || "—"}</td>
                    <td>{r.complete ? "yes" : "no"}{r.errors.length > 0 && <><br />{r.errors.join("; ")}</>}</td>
                    <td>{r.duration_ms === null ? "—" : `${r.duration_ms} ms`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}
