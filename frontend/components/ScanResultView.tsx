import Breakable from "@/components/Breakable";
import type { Ref } from "react";
import { formatBytes } from "@/components/FileDropzone";
import EvidenceSections from "@/components/EvidenceSections";
import IsolationReport from "@/components/IsolationReport";
import { ENGINE_LABELS, type ScanResult, type Verdict } from "@/lib/api";
import styles from "./ScanResultView.module.css";

const VERDICT_LABELS: Record<Verdict, { title: string; className: string }> = {
  // "No known indicators", never "safe": a SAFE verdict is not a guarantee (see the result message).
  SAFE: { title: "No known indicators", className: styles.safe },
  SUSPICIOUS: { title: "Suspicious", className: styles.suspicious },
  MALICIOUS: { title: "Malicious", className: styles.malicious },
  UNABLE_TO_SCAN: { title: "Unable to scan", className: styles.unable },
};

// Shows exactly what the backend returned. The verdict is never derived from the findings here.
export default function ScanResultView({
  result,
  ref,
  heading = "Scan result",
}: {
  result: ScanResult;
  ref?: Ref<HTMLHeadingElement>;
  heading?: string;
}) {
  const verdict = VERDICT_LABELS[result.verdict];
  const headingId = `result-heading-${result.request_id}`;

  return (
    <section className={styles.result} aria-labelledby={headingId}>
      <h2 id={headingId} ref={ref} tabIndex={-1} className={styles.heading}>
        {heading}
      </h2>
      <p className={styles.engineBadge}>
        Engine: <strong>{ENGINE_LABELS[result.engine]}</strong> <code className={styles.mono}>{result.engine}</code>
      </p>

      <div className={`${styles.verdict} ${verdict.className}`}>
        <span className={styles.verdictLabel}>Verdict</span>
        <span className={styles.verdictValue}>{verdict.title}</span>
        <code className={styles.verdictCode}>{result.verdict}</code>
      </div>

      <dl className={styles.meta}>
        <div>
          <dt>Request ID</dt>
          <dd className={styles.mono}>{result.request_id}</dd>
        </div>
        <div>
          <dt>Filename</dt>
          <dd className={styles.mono}>{result.filename || "(no filename)"}</dd>
        </div>
        <div>
          <dt>Message</dt>
          <dd>{result.message}</dd>
        </div>
        <div>
          <dt>SHA-256</dt>
          <dd className={styles.mono}>{result.sha256}</dd>
        </div>
        <div>
          <dt>Size / format</dt>
          <dd>
            {formatBytes(result.size_bytes)} · {result.detected_format}
          </dd>
        </div>
        <div>
          <dt>Analysis</dt>
          <dd>
            {result.complete ? "All applicable scanners completed" : "Incomplete"} · {result.duration_ms} ms
          </dd>
        </div>
        <div>
          <dt>Scanners</dt>
          <dd>
            {result.scanners.map((s) => (
              <span key={s.name} className={styles.statusLine}>
                <span className={styles.mono}>{s.name}</span>: {s.status.replace("_", " ")}
                {typeof s.duration_ms === "number" && <> · {s.duration_ms} ms</>}
                {s.error && <> ({s.error_kind ? `${s.error_kind}: ` : ""}{s.error})</>}
              </span>
            ))}
          </dd>
        </div>
        <div>
          <dt>Coverage</dt>
          <dd>{result.coverage_complete ? "Required coverage complete" : result.coverage_issues.map((i) => i.code).join(", ")}</dd>
        </div>
        <div>
          <dt>Isolation</dt>
          <dd><IsolationReport isolation={result.isolation} required={result.isolation_required} missing={result.isolation_missing} /></dd>
        </div>
        <div>
          <dt>Commit</dt>
          <dd className={styles.mono}>{result.versions.commit ?? "not reported"}</dd>
        </div>
        <div>
          <dt>Versions</dt>
          <dd className={styles.mono}>
            {Object.entries(result.versions)
              .filter(([k]) => k !== "commit")
              .map(([k, v]) => `${k} ${k.endsWith("ruleset_sha256") ? v.slice(0, 12) : v}`)
              .join(" · ")}
          </dd>
        </div>
      </dl>

      <EvidenceSections findings={result.findings} />

      <h3 className={styles.subheading}>Findings ({result.findings.length})</h3>
      {result.findings.length === 0 ? (
        <p className={styles.empty}>The engine reported no findings for this file.</p>
      ) : (
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th scope="col">Severity</th>
                <th scope="col">Scanner</th>
                <th scope="col">Category</th>
                <th scope="col">Description</th>
                <th scope="col">Rule</th>
              </tr>
            </thead>
            <tbody>
              {result.findings.map((f, i) => (
                <tr key={i}>
                  <td>
                    <span className={`${styles.severity} ${styles[`sev${f.severity}`]}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td>{f.scanner}</td>
                  <td>{f.category}</td>
                  <td>{f.description}</td>
                  <td className={styles.ruleCell}>{f.rule_id ? <Breakable text={f.rule_id} /> : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
