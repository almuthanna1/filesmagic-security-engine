import type { Ref } from "react";
import type { ScanResult, Verdict } from "@/lib/api";
import styles from "./ScanResultView.module.css";

const VERDICT_LABELS: Record<Verdict, { title: string; className: string }> = {
  SAFE: { title: "Safe", className: styles.safe },
  SUSPICIOUS: { title: "Suspicious", className: styles.suspicious },
  MALICIOUS: { title: "Malicious", className: styles.malicious },
  UNABLE_TO_SCAN: { title: "Unable to scan", className: styles.unable },
};

// Shows exactly what the backend returned. The verdict is never derived from the findings here.
export default function ScanResultView({
  result,
  ref,
}: {
  result: ScanResult;
  ref?: Ref<HTMLHeadingElement>;
}) {
  const verdict = VERDICT_LABELS[result.verdict];

  return (
    <section className={styles.result} aria-labelledby="result-heading">
      <h2 id="result-heading" ref={ref} tabIndex={-1} className={styles.heading}>
        Scan result
      </h2>

      <div className={`${styles.verdict} ${verdict.className}`}>
        <span className={styles.verdictLabel}>Verdict</span>
        <span className={styles.verdictValue}>{verdict.title}</span>
        <code className={styles.verdictCode}>{result.verdict}</code>
      </div>

      <dl className={styles.meta}>
        <div>
          <dt>Filename</dt>
          <dd className={styles.mono}>{result.filename || "(no filename)"}</dd>
        </div>
        <div>
          <dt>Message</dt>
          <dd>{result.message}</dd>
        </div>
      </dl>

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
                  <td className={styles.mono}>{f.rule_id ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
