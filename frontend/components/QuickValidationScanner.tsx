"use client";

import { useEffect, useState } from "react";
import FileDropzone, { formatBytes } from "@/components/FileDropzone";
import ScanResultView from "@/components/ScanResultView";
import { ApiError, MAX_UPLOAD_BYTES, scanFile, sha256Hex, watchEngineHealth, type HealthResult, type ScanResult } from "@/lib/api";
import { VALIDATION_FILES, hostedValidationCandidate } from "@/lib/additionalValidationCatalog";
import { addRecords, toRecord, type HistoryRecord } from "@/lib/history";
import { completeValidationReport } from "@/lib/validationReport";
import styles from "./QuickValidationScanner.module.css";

type Props = { onFinished: (caseId: string, result: ScanResult) => void };

export default function QuickValidationScanner({ onFinished }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [health, setHealth] = useState<HealthResult | undefined>();
  const [retryRun, setRetryRun] = useState(0);
  const [waking, setWaking] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [copyRecord, setCopyRecord] = useState<HistoryRecord | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(
    () => watchEngineHealth(setHealth, (attempt, attempts) =>
      setWaking(`Engine waking up; checking connection (${attempt}/${attempts})…`)),
    [retryRun],
  );

  const catalogMatch = file
    ? VALIDATION_FILES.find(f => f.filename.toLowerCase() === file.name.toLowerCase())
    : undefined;
  const candidate = file ? hostedValidationCandidate(file.name) : null;
  const ready = !!health && !("error" in health) && health.engines.includes("unified");
  const oversized = !!file && file.size > MAX_UPLOAD_BYTES;

  function selectFile(selected: File) {
    if (busy) return;
    setFile(selected);
    setError(null);
    setNotice(null);
    setResult(null);
    setCopyRecord(null);
    setCopied(false);
  }

  async function runScan() {
    if (!file || busy) return;
    if (!candidate) {
      setError(catalogMatch?.handling === "offline-only"
        ? "Offline VM only: this file must not be uploaded to the public Lab."
        : "Choose a file from the 32-file catalog below. The filename must match a listed benign candidate.");
      return;
    }
    if (oversized) {
      setError("This file exceeds the 10 MB hosted scan limit.");
      return;
    }
    if (!ready) {
      setError("The unified Security Engine is not available yet. Retry the connection.");
      return;
    }

    setBusy(true);
    setError(null);
    setNotice(null);
    setResult(null);
    setCopyRecord(null);
    setCopied(false);
    try {
      // Reuse the exact signed-token and isolated scanner workflow from the main Lab.
      const scan = await scanFile(file, "unified");
      const uploadHash = await sha256Hex(file);
      if (scan.sha256.toLowerCase() !== uploadHash.toLowerCase()) {
        throw new Error("File hash verification failed: the scanner reported a different SHA-256.");
      }
      const recorded = toRecord(scan, "single");
      const saved = addRecords([recorded]);
      setResult(scan);
      setCopyRecord(recorded);
      onFinished(candidate.id, scan);
      if (!saved) setNotice("This browser refused to save history. You can still copy this scan's full report now.");
    } catch (e) {
      setError(e instanceof ApiError || e instanceof Error ? e.message : "Unexpected failure while scanning.");
    } finally {
      setBusy(false);
    }
  }

  async function copyFullResult() {
    if (!candidate || !copyRecord) return;
    try {
      await navigator.clipboard.writeText(completeValidationReport(candidate, copyRecord));
      setCopied(true);
      setError(null);
    } catch {
      setError("Clipboard access was blocked. Check browser permissions or use the full scan details below.");
    }
  }

  const reason = !file ? "Download a test file below, then drag it here."
    : catalogMatch?.handling === "offline-only" ? "Offline VM only: hosted scanning is disabled for this case."
    : !candidate ? "No unique approved catalog entry for this filename. Check the file name before scanning."
    : oversized ? `File exceeds the ${formatBytes(MAX_UPLOAD_BYTES)} limit.`
    : !ready ? "Waiting for the unified Security Engine." : "Ready to scan.";

  return (
    <section id="validation-quick-scan" className={styles.panel} aria-labelledby="validation-quick-scan-title">
      <div className={styles.heading}>
        <div>
          <p className={styles.eyebrow}>One-page testing workflow</p>
          <h3 id="validation-quick-scan-title">Scan and copy without leaving this page</h3>
          <p>Download a listed file, drag it below, run the unified engine, then copy the full evidence report. Repeat with the next file.</p>
        </div>
        <span className={styles.engineName}>Unified Engine</span>
      </div>

      <div className={styles.controls}>
        <div className={styles.dropzone}>
          <FileDropzone file={file} onSelect={selectFile} disabled={busy} />
        </div>
        <div className={styles.actionColumn}>
          <p className={styles.caseName}>{catalogMatch ? `${catalogMatch.id}: ${catalogMatch.filename}` : "No catalog file selected"}</p>
          <p className={styles.reason} role="status">{reason}</p>
          <button type="button" className={styles.scanButton} onClick={runScan}
            disabled={busy || !file || !candidate || !ready || oversized}>
            {busy ? "Scanning…" : "Run Scan"}
          </button>
          <p className={styles.health} role="status">
            {health === undefined ? (waking ?? "Checking engine status…")
              : "error" in health ? health.error
              : ready ? `Engine connected · ${health.commit.slice(0, 12)}`
              : "This API is not offering the unified engine."}
          </p>
          {health !== undefined && !ready && (
            <button type="button" className={styles.retry} onClick={() => {
              setHealth(undefined);
              setWaking(null);
              setRetryRun(n => n + 1);
            }}>Retry connection</button>
          )}
        </div>
      </div>

      {error && <p className={styles.error} role="alert">{error}</p>}
      {notice && <p className={styles.notice} role="status">{notice}</p>}

      {result && copyRecord && (
        <div className={styles.completed} aria-live="polite">
          <div className={styles.resultTop}>
            <div>
              <strong className={styles.resultVerdict}>Result: {result.verdict}</strong>
              <p>{result.filename} · {result.findings.length} findings · {result.duration_ms} ms · {result.complete ? "All applicable scanners completed" : "Incomplete analysis"}</p>
            </div>
            <button type="button" className={styles.copyButton} onClick={copyFullResult}>
              {copied ? "Copied full report" : "Copy full result"}
            </button>
          </div>
          <p className={styles.disclaimer}>Copies actual scanner results, SHA-256, findings, isolation controls and software versions. Filename matching does not verify the upstream GitHub bytes. No original document contents are saved in browser history.</p>
          <details className={styles.details}>
            <summary>View complete scan details</summary>
            <ScanResultView result={result} heading="Complete scan result" />
          </details>
        </div>
      )}
    </section>
  );
}
