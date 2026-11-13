"use client";

import { useEffect, useState } from "react";
import { VALIDATION_FILES, VALIDATION_GROUPS, directDownloadUrl, pinnedSourceUrl, type ValidationFile } from "@/lib/additionalValidationCatalog";
import type { Verdict } from "@/lib/testCatalog";
import styles from "./AdditionalValidationSection.module.css";

type Observation = { verdict: Verdict | ""; sha256: string; notes: string };
type Observations = Record<string, Observation>;
const KEY = "filesmagic-curated-validation-observed-v1";
const VERDICTS: Verdict[] = ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNABLE_TO_SCAN"];
const EMPTY: Observation = { verdict: "", sha256: "", notes: "" };

function report(file: ValidationFile, observation: Observation): string {
  return [
    "FilesMagic external validation (manual observation, not verified by the tracker)",
    `Case: ${file.id} | ${file.filename}`,
    `Source: ${pinnedSourceUrl(file)}`,
    `Download: ${directDownloadUrl(file)}`,
    `Source revision: ${file.revision}`,
    `Test purpose: ${file.purpose}`,
    `Testing location: ${file.handling === "offline-only" ? "Offline isolated VM recommended" : "Independent benign-candidate review required"}`,
    `Observed verdict: ${observation.verdict || "Not tested"}`,
    `Uploaded SHA-256: ${observation.sha256 || "Not recorded"}`,
    `Rule IDs / notes: ${observation.notes || "Not recorded"}`,
    "Confirm against the complete Security Engine result, including version, isolation and findings.",
  ].join("\n");
}

export default function AdditionalValidationSection() {
  const [observed, setObserved] = useState<Observations>({});
  const [hydrated, setHydrated] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    queueMicrotask(() => {
      if (!active) return;
      try {
        const raw = JSON.parse(window.localStorage.getItem(KEY) || "{}");
        if (raw && typeof raw === "object" && !Array.isArray(raw)) setObserved(raw as Observations);
      } catch {
        // Local storage is optional. The download links are still usable.
      }
      setHydrated(true);
    });
    return () => { active = false; };
  }, []);

  function change(id: string, patch: Partial<Observation>) {
    const next = { ...observed, [id]: { ...(observed[id] || EMPTY), ...patch } };
    setObserved(next);
    try { window.localStorage.setItem(KEY, JSON.stringify(next)); } catch { /* optional */ }
    setCopiedId(null);
  }

  async function copyResult(file: ValidationFile) {
    const entry = observed[file.id] || EMPTY;
    try {
      await navigator.clipboard.writeText(report(file, entry));
      setCopiedId(file.id);
    } catch {
      setCopiedId(null);
    }
  }

  async function copySummary() {
    const entries = VALIDATION_FILES.filter(file => observed[file.id]?.verdict);
    if (!entries.length) return;
    try {
      await navigator.clipboard.writeText(entries.map(file => report(file, observed[file.id])).join("\n\n---\n\n"));
      setCopiedId("all");
    } catch {
      setCopiedId(null);
    }
  }

  const count = VALIDATION_FILES.filter(file => !!observed[file.id]?.verdict).length;

  return (
    <section className={styles.section} aria-labelledby="additional-validation-heading">
      <header className={styles.header}>
        <p className={styles.eyebrow}>External validation / New testing batch</p>
        <h2 id="additional-validation-heading">32 additional source-pinned test files</h2>
        <p>Download one file at a time, scan it, and record the observed result. Each GitHub download targets a fixed commit rather than a moving branch. No target verdict has been assumed for these external fixtures.</p>
      </header>

      <div className={styles.warning}>
        <strong>Review files before testing.</strong> Third-party regression files are not independently malware-screened. Do not open downloaded documents in Office, Acrobat, or other viewers. Use only vetted benign candidates in the public Lab. Files marked <strong>Offline VM only</strong> are for your isolated research environment and must not be uploaded to the hosted Render endpoint. An EICAR file is a harmless AV test string, not a real malware sample; antivirus software may quarantine it.
      </div>

      <div className={styles.summary}>
        <div><strong>{VALIDATION_FILES.length}</strong><span>Download links</span></div>
        <div><strong>{hydrated ? count : "—"}</strong><span>Verdicts recorded</span></div>
        <button type="button" className={styles.copyAll} onClick={copySummary} disabled={!count}>
          {copiedId === "all" ? "Copied recorded results" : "Copy recorded results"}
        </button>
      </div>

      <p className={styles.instruction}>These are manually recorded observations, not automatically validated scan results. Copy one result to share it in chat, ideally with the full scanner report, its SHA-256, rule IDs, and the engine commit. If a PDF opens in a browser instead of downloading, use Save As.</p>

      {VALIDATION_GROUPS.map(group => {
        const files = VALIDATION_FILES.filter(file => file.group === group);
        return (
          <section key={group} className={styles.group} aria-label={group}>
            <div className={styles.groupHeader}>
              <h3>{group}</h3>
              <span>{files.filter(f => observed[f.id]?.verdict).length}/{files.length} recorded</span>
            </div>
            <div className={styles.tableWrap}>
              <table className={styles.table}>
                <thead><tr>
                  <th scope="col">File / source</th>
                  <th scope="col">What it tests</th>
                  <th scope="col">Observed verdict</th>
                  <th scope="col">Evidence notes</th>
                  <th scope="col">Download / share</th>
                </tr></thead>
                <tbody>
                  {files.map(file => {
                    const entry = observed[file.id] || EMPTY;
                    return (
                      <tr key={file.id}>
                        <td>
                          <strong className={styles.filename}>{file.filename}</strong>
                          <small>{file.repository} · {file.revision.slice(0, 10)}</small>
                          <small className={file.handling === "offline-only" ? styles.offline : styles.review}>
                            {file.handling === "offline-only" ? "Offline VM only" : "Benign candidate: review first"}
                          </small>
                        </td>
                        <td className={styles.purpose}>{file.purpose}<small>Evaluation outcome unknown. Do not count a match as malware detection without source-level evidence.</small></td>
                        <td>
                          <label htmlFor={file.id + "-verdict"} className={styles.srOnly}>Observed verdict for {file.filename}</label>
                          <select id={file.id + "-verdict"} value={entry.verdict} onChange={e => change(file.id, { verdict: e.target.value as Observation["verdict"] })}>
                            <option value="">Not tested</option>
                            {VERDICTS.map(v => <option key={v} value={v}>{v}</option>)}
                          </select>
                          {entry.verdict && <small className={styles.recorded}>Recorded, not verified</small>}
                        </td>
                        <td>
                          <label htmlFor={file.id + "-hash"} className={styles.srOnly}>SHA-256 for {file.filename}</label>
                          <input id={file.id + "-hash"} type="text" value={entry.sha256}
                            maxLength={64} placeholder="SHA-256 (optional)" spellCheck={false}
                            onChange={e => change(file.id, { sha256: e.target.value.replace(/[^a-fA-F0-9]/g, "").slice(0, 64) })}/>
                          <label htmlFor={file.id + "-notes"} className={styles.srOnly}>Findings / rule IDs for {file.filename}</label>
                          <textarea id={file.id + "-notes"} value={entry.notes} maxLength={400} rows={2}
                            placeholder="Rule IDs / observations" onChange={e => change(file.id, { notes: e.target.value })}/>
                        </td>
                        <td>
                          <a className={styles.download} href={directDownloadUrl(file)} target="_blank" rel="noopener noreferrer" download={file.filename}>
                            Download file
                          </a>
                          <a className={styles.source} href={pinnedSourceUrl(file)} target="_blank" rel="noopener noreferrer">View source</a>
                          <button type="button" className={styles.copy} disabled={!entry.verdict} onClick={() => copyResult(file)}>
                            {copiedId === file.id ? "Copied" : "Copy this result"}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        );
      })}
      <p className={styles.footer}>Source filenames and revisions are pinned where supported. The EICAR official links are unversioned. Record exact SHA-256 values from the Security Engine response for reproducibility. PDF/A conformance failures are not malware labels. Do not combine these exploratory results with the frozen November 9 evaluation without explicitly distinguishing the datasets.</p>
    </section>
  );
}
