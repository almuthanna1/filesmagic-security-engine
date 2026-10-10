"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import FileDropzone from "@/components/FileDropzone";
import ScanResultView from "@/components/ScanResultView";
import { ApiError, scanFile, type ScanResult } from "@/lib/api";
import styles from "./page.module.css";

export default function SecurityLabPage() {
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const resultHeading = useRef<HTMLHeadingElement>(null);

  // Move focus to the result so keyboard and screen-reader users land on it.
  useEffect(() => {
    if (result) resultHeading.current?.focus();
  }, [result]);

  function selectFile(selected: File) {
    setFile(selected);
    setResult(null);
    setError(null);
  }

  async function handleScan() {
    if (!file) {
      setError("Select a file before scanning.");
      return;
    }
    setScanning(true);
    setError(null);
    setResult(null);
    try {
      setResult(await scanFile(file));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Unexpected error while scanning the file.");
    } finally {
      setScanning(false);
    }
  }

  return (
    <main className={styles.main}>
      <header className={styles.header}>
        <p className={styles.eyebrow}>Internal testing tool</p>
        <h1>FilesMagic Security Lab</h1>
        <p className={styles.intro}>
          Upload a file to run it through the FilesMagic Security Engine, the analysis layer that checks
          files before they reach the conversion pipeline.
        </p>
        <p style={{ marginTop: 16 }}><Link href="/test-files" style={{ color: "var(--accent)", fontWeight: 700 }}>Browse downloadable test files →</Link></p>
      </header>

      <section className={styles.panel} aria-labelledby="upload-heading">
        <h2 id="upload-heading" className={styles.panelHeading}>
          Select a file
        </h2>
        <FileDropzone file={file} disabled={scanning} onSelect={selectFile} />

        <div className={styles.actions}>
          <button
            type="button"
            className={styles.button}
            onClick={handleScan}
            disabled={scanning || !file}
            aria-describedby="scan-status"
          >
            {scanning ? "Scanning…" : "Scan file"}
          </button>
          <p id="scan-status" className={styles.status} role="status" aria-live="polite">
            {scanning ? "Uploading and analysing the file…" : !file ? "Select a file to enable scanning." : ""}
          </p>
        </div>

        {error && (
          <div className={styles.error} role="alert">
            <strong>Scan failed.</strong> {error}
          </div>
        )}

        {result && <ScanResultView ref={resultHeading} result={result} />}
      </section>
    </main>
  );
}
