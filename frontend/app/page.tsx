"use client";

import { useEffect, useRef, useState } from "react";
import FileDropzone from "@/components/FileDropzone";
import LabNav from "@/components/LabNav";
import ScanResultView from "@/components/ScanResultView";
import { ApiError, ENGINE_LABELS, scanFile, watchEngineHealth, type HealthResult, type ScanResult } from "@/lib/api";
import { addRecords, toRecord } from "@/lib/history";
import styles from "./page.module.css";

// The public research Lab offers only the unified engine. The four-scanner reference
// baseline remains available to the research CLI and preserved evaluation artifacts.
export default function SecurityLabPage() {
  const [file, setFile] = useState<File | null>(null);
  const [health, setHealth] = useState<HealthResult | undefined>(undefined);
  const [waking, setWaking] = useState<string | null>(null);
  const [healthRun, setHealthRun] = useState(0);
  const [scanning, setScanning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<ScanResult | null>(null);
  const resultHeading = useRef<HTMLHeadingElement>(null);
  const unifiedAvailable = !!health && !("error" in health) && health.engines.includes("unified");

  useEffect(
    () => watchEngineHealth(setHealth, (attempt, attempts) => setWaking(`The engine may be waking up; retrying (attempt ${attempt} of ${attempts})…`)),
    [healthRun],
  );

  function retryConnection() {
    setHealth(undefined);
    setWaking(null);
    setHealthRun(run => run + 1);
  }

  useEffect(() => {
    if (outcome) resultHeading.current?.focus();
  }, [outcome]);

  function selectFile(selected: File) {
    setFile(selected);
    setOutcome(null);
    setError(null);
    setNotice(null);
  }

  async function handleScan() {
    if (!file) {
      setError("Select a file before scanning.");
      return;
    }
    if (!unifiedAvailable) {
      setError("The unified engine is not available. Retry the connection and try again.");
      return;
    }
    setError(null);
    setNotice(null);
    setOutcome(null);
    try {
      setScanning(`Uploading and analysing with the ${ENGINE_LABELS.unified}…`);
      const result = await scanFile(file, "unified");
      setOutcome(result);
      if (!addRecords([toRecord(result, "single")])) {
        setNotice("This browser refused to store the history; export results from the History page before leaving.");
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Unexpected error while scanning the file.");
    } finally {
      setScanning(null);
    }
  }

  return (
    <main className={styles.main}>
      <header className={styles.header}>
        <p className={styles.eyebrow}>Standalone research demonstration</p>
        <h1>FilesMagic Security Lab</h1>
        <p className={styles.intro}>
          Upload a document for static analysis by the unified FilesMagic Security Engine. Its four reference scanners and five additional modules report structured findings under strict isolation.
        </p>
        <p className={styles.intro}>Research staging only: use benign or inert security-test files. Do not upload genuine malware or private documents. The public FilesMagic conversion pipeline is not connected to this research engine.</p>
        <LabNav />
      </header>

      <section className={styles.panel} aria-labelledby="upload-heading">
        <h2 id="upload-heading" className={styles.panelHeading}>Select a file</h2>
        <FileDropzone file={file} disabled={scanning !== null} onSelect={selectFile} />

        <div className={styles.engines}>
          <p className={styles.fieldLabel}>Security engine</p>
          <div className={styles.engineOption}>
            <span>
              <strong>{ENGINE_LABELS.unified}</strong>
              <span className={styles.status}>Nine analysis components with evidence correlation. No engine selection required.</span>
            </span>
          </div>
          <p className={styles.status} role="status">
            {health === undefined ? (waking ?? "Checking the unified engine's availability…") :
              "error" in health ? `Could not contact the Security Engine API: ${health.error}` :
              unifiedAvailable ? `Unified engine available (commit ${health.commit.slice(0, 12)}).` :
                "This API does not currently offer the unified engine. No scan will be submitted."}
          </p>
          {health !== undefined && (!unifiedAvailable) && (
            <button type="button" className={styles.linkButton} onClick={retryConnection}>Retry connection</button>
          )}
        </div>

        <div className={styles.actions}>
          <button type="button" className={styles.button} onClick={handleScan}
                  disabled={scanning !== null || !file || !unifiedAvailable} aria-describedby="scan-status">
            {scanning ? "Scanning…" : "Scan file"}
          </button>
          <p id="scan-status" className={styles.status} role="status" aria-live="polite">
            {scanning ?? (!file ? "Select a file to enable scanning." :
              !unifiedAvailable ? "Waiting for the unified engine." : "")}
          </p>
        </div>

        {error && <div className={styles.error} role="alert"><strong>Scan failed.</strong> {error}</div>}
        {notice && <p className={styles.status} role="status">{notice}</p>}
        {outcome && <ScanResultView ref={resultHeading} result={outcome} />}
      </section>
    </main>
  );
}
