"use client";

import { useEffect, useRef, useState } from "react";
import CompareView from "@/components/CompareView";
import FileDropzone from "@/components/FileDropzone";
import LabNav from "@/components/LabNav";
import ScanResultView from "@/components/ScanResultView";
import { ApiError, ENGINE_LABELS, engineHealth, scanFile, type Engine, type EngineHealth, type ScanResult } from "@/lib/api";
import { addRecords, toRecord } from "@/lib/history";
import styles from "./page.module.css";

type Mode = Engine | "compare";
type Outcome = { mode: "single"; result: ScanResult } | { mode: "compare"; reference: ScanResult; unified: ScanResult };

const MODES: { value: Mode; label: string; note: string }[] = [
  { value: "reference", label: ENGINE_LABELS.reference, note: "The four-scanner baseline FilesMagic uses: YARA-X, PDF, Office and custom detectors." },
  { value: "unified", label: ENGINE_LABELS.unified, note: "The baseline plus action-chain, call-graph and relationship analysis, with evidence correlation." },
  { value: "compare", label: "Compare both", note: "Scans the same file with each engine, one after the other, and shows the differences." },
];

export default function SecurityLabPage() {
  const [file, setFile] = useState<File | null>(null);
  const [mode, setMode] = useState<Mode>("reference");
  const [health, setHealth] = useState<EngineHealth | null | undefined>(undefined);
  const [scanning, setScanning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const resultHeading = useRef<HTMLHeadingElement>(null);
  const unifiedAvailable = health?.engines.includes("unified") ?? false;

  useEffect(() => {
    engineHealth().then(setHealth);
  }, []);

  // Move focus to the result so keyboard and screen-reader users land on it.
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
    setError(null);
    setNotice(null);
    setOutcome(null);
    try {
      if (mode === "compare") {
        // Sequential on purpose: the engine runs one scan at a time (MAX_CONCURRENT_SCANS).
        setScanning(`Scanning with the ${ENGINE_LABELS.reference} (1 of 2)…`);
        const reference = await scanFile(file, "reference");
        setScanning(`Scanning with the ${ENGINE_LABELS.unified} (2 of 2)…`);
        const unified = await scanFile(file, "unified");
        setOutcome({ mode: "compare", reference, unified });
        if (!addRecords([toRecord(unified, "compare"), toRecord(reference, "compare")])) {
          setNotice("This browser refused to store the history; export results from the History page before leaving.");
        }
      } else {
        setScanning(`Uploading and analysing with the ${ENGINE_LABELS[mode]}…`);
        const result = await scanFile(file, mode);
        setOutcome({ mode: "single", result });
        if (!addRecords([toRecord(result, "single")])) {
          setNotice("This browser refused to store the history; export results from the History page before leaving.");
        }
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Unexpected error while scanning the file.");
    } finally {
      setScanning(null);
    }
  }

  return (
    <main className={`${styles.main} ${outcome?.mode === "compare" ? styles.wide : ""}`}>
      <header className={styles.header}>
        <p className={styles.eyebrow}>Internal testing tool</p>
        <h1>FilesMagic Security Lab</h1>
        <p className={styles.intro}>
          Upload a file to run it through the FilesMagic Security Engine, the analysis layer that checks
          files before they reach the conversion pipeline. Choose the original engine, the custom unified
          engine, or compare both.
        </p>
        <p className={styles.intro}>Research staging only: use benign or inert security-test files. Do not upload genuine malware or private documents.</p>
        <LabNav />
      </header>

      <section className={styles.panel} aria-labelledby="upload-heading">
        <h2 id="upload-heading" className={styles.panelHeading}>
          Select a file
        </h2>
        <FileDropzone file={file} disabled={scanning !== null} onSelect={selectFile} />

        <fieldset className={styles.engines} disabled={scanning !== null}>
          <legend className={styles.fieldLabel}>Engine</legend>
          {MODES.map((m) => {
            const unavailable = m.value !== "reference" && !unifiedAvailable;
            return (
              <label key={m.value} className={styles.engineOption}>
                <input type="radio" name="engine" value={m.value} checked={mode === m.value} disabled={unavailable}
                       onChange={() => { setMode(m.value); setOutcome(null); setError(null); }} />
                <span>
                  <strong>{m.label}</strong>
                  <span className={styles.status}>{m.note}</span>
                </span>
              </label>
            );
          })}
          <p className={styles.status}>
            {health === undefined ? "Checking which engines this API accepts…" :
              health === null ? "Could not read the API's engine list; only the Original Engine is offered." :
                unifiedAvailable ? `This API accepts both engines (commit ${health.commit.slice(0, 12)}).` :
                  "This API runs the Original Engine only (the custom engine is research-only and not enabled here)."}
          </p>
        </fieldset>

        <div className={styles.actions}>
          <button
            type="button"
            className={styles.button}
            onClick={handleScan}
            disabled={scanning !== null || !file}
            aria-describedby="scan-status"
          >
            {scanning ? "Scanning…" : mode === "compare" ? "Scan with both engines" : "Scan file"}
          </button>
          <p id="scan-status" className={styles.status} role="status" aria-live="polite">
            {scanning ?? (!file ? "Select a file to enable scanning." : "")}
          </p>
        </div>

        {error && (
          <div className={styles.error} role="alert">
            <strong>Scan failed.</strong> {error}
          </div>
        )}
        {notice && <p className={styles.status} role="status">{notice}</p>}

        {outcome?.mode === "single" && <ScanResultView ref={resultHeading} result={outcome.result} />}
        {outcome?.mode === "compare" && (
          <CompareView ref={resultHeading} reference={outcome.reference} unified={outcome.unified} />
        )}
      </section>
    </main>
  );
}
