"use client";

import Breakable from "@/components/Breakable";
import { formatBytes } from "@/components/FileDropzone";
import LabNav from "@/components/LabNav";
import table from "@/components/ScanResultView.module.css";
import { ENGINE_LABELS } from "@/lib/api";
import { clearHistory, download, historyCsv, useHistory } from "@/lib/history";
import styles from "../page.module.css";

// Every scan made on the Scanner page, newest first. Results only: no file contents are stored.
export default function HistoryPage() {
  const records = useHistory();

  function clear() {
    if (window.confirm(`Delete all ${records.length} history records from this browser? Export them first if needed.`)) {
      clearHistory();
    }
  }

  return (
    <main className={`${styles.main} ${styles.wide}`}>
      <header className={styles.header}>
        <p className={styles.eyebrow}>Research workflow</p>
        <h1>Scan History</h1>
        <p className={styles.intro}>
          Results of the scans run on the Scanner page in this browser: engine, commit, file hash, verdict,
          findings and timing. File contents are never stored. Export to keep them; clearing the browser&apos;s
          site data removes them.
        </p>
        <LabNav />
      </header>

      <section className={styles.panel} aria-labelledby="history-heading">
        <h2 id="history-heading" className={styles.panelHeading}>
          Recorded scans ({records.length})
        </h2>
        <div className={styles.actions} style={{ marginTop: 0, marginBottom: 16 }}>
          <button type="button" className={styles.button} disabled={!records.length}
                  onClick={() => download("filesmagic-scan-history.csv", "text/csv", historyCsv(records))}>
            Export CSV
          </button>
          <button type="button" className={styles.button} disabled={!records.length}
                  onClick={() => download("filesmagic-scan-history.json", "application/json", JSON.stringify(records, null, 2))}>
            Export JSON
          </button>
          <button type="button" className={styles.linkButton} onClick={clear} disabled={!records.length}>
            Clear history
          </button>
        </div>
        {records.length === 0 ? (
          <p className={table.empty}>No scans recorded yet. Results appear here after each scan on the Scanner page.</p>
        ) : (
          <div className={table.tableWrap}>
            <table className={table.table}>
              <thead>
                <tr>
                  <th scope="col">File</th>
                  <th scope="col">Engine</th>
                  <th scope="col">Verdict</th>
                  <th scope="col">Findings (non-INFO)</th>
                  <th scope="col">Complete</th>
                  <th scope="col">Time</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.recorded_at + r.request_id}>
                    <td>
                      <span className={table.mono}>{r.filename || "(no filename)"}</span>
                      <br />
                      <span className={table.mono} title={r.sha256}>{r.sha256.slice(0, 16)}…</span>
                      <br />
                      {formatBytes(r.size_bytes)} · {r.detected_format} · {new Date(r.recorded_at).toLocaleString()}
                    </td>
                    <td>
                      {ENGINE_LABELS[r.engine]}
                      {r.mode === "compare" && <> (comparison)</>}
                      <br />
                      <span className={table.mono} title={r.commit}>commit {r.commit.slice(0, 12)}</span>
                    </td>
                    <td><code className={table.verdictCell}>{r.verdict}</code></td>
                    <td className={table.ruleCell}>
                      <Breakable text={r.findings.filter((f) => f.severity !== "INFO")
                        .map((f) => `${f.rule_id ?? f.category} (${f.severity})`).join(", ") || "—"} />
                    </td>
                    <td>{r.complete ? "yes" : "no"}</td>
                    <td>{r.duration_ms} ms</td>
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
