import Breakable from "@/components/Breakable";
import type { Ref } from "react";
import ScanResultView from "@/components/ScanResultView";
import type { ScanResult } from "@/lib/api";
import { compareResults, type FindingChange } from "@/lib/compare";
import styles from "./ScanResultView.module.css";

const CHANGE_LABELS: Record<FindingChange, string> = {
  retained: "Retained (both engines)",
  added: "Added by the unified engine",
  superseded: "Superseded by correlation (original only)",
};

const fmt = (ms: number) => `${ms > 0 ? "+" : ""}${ms.toFixed(1)} ms`;

// One file, scanned by both engines one after the other. Everything shown is computed from the
// two API responses (lib/compare.ts); nothing is re-judged here.
export default function CompareView({
  reference,
  unified,
  ref,
}: {
  reference: ScanResult;
  unified: ScanResult;
  ref?: Ref<HTMLHeadingElement>;
}) {
  const c = compareResults(reference, unified);
  return (
    <section className={styles.result} aria-labelledby="compare-heading">
      <h2 id="compare-heading" ref={ref} tabIndex={-1} className={styles.heading}>
        Engine comparison
      </h2>
      {!c.sameFile && (
        <p className={styles.isolationFailure} role="alert">The two results are for different files (SHA-256 differs).</p>
      )}

      <div className={styles.compareSummary}>
        <div>
          <span className={styles.verdictLabel}>Original Engine</span>
          <code className={styles.mono}>{reference.verdict}</code>
        </div>
        <div aria-hidden="true">→</div>
        <div>
          <span className={styles.verdictLabel}>Custom Unified Engine</span>
          <code className={styles.mono}>{unified.verdict}</code>
        </div>
        <p className={styles.compareVerdictNote}>
          {c.verdictChanged ? "The verdicts differ." : "Same verdict."}
        </p>
      </div>

      <dl className={styles.meta}>
        <div>
          <dt>Whole scan (worker start-up included)</dt>
          <dd>
            {reference.duration_ms} ms → {unified.duration_ms} ms ({fmt(c.durationDeltaMs)})
          </dd>
        </div>
        <div>
          <dt>Detection work inside the worker (sum of scanner times)</dt>
          <dd>
            {c.scannerMs.reference.toFixed(2)} ms → {c.scannerMs.unified.toFixed(2)} ms (
            {fmt(c.scannerMs.unified - c.scannerMs.reference)})
          </dd>
        </div>
        <div>
          <dt>Incomplete-analysis warnings</dt>
          <dd>
            {c.warnings.length === 0 ? "None: every applicable scanner completed in both engines." : (
              <ul className={styles.isolationList}>{c.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
            )}
          </dd>
        </div>
      </dl>
      <p className={styles.evidenceNote}>
        One scan per engine on this machine; timings vary from run to run, so a small difference is not a measurement.
      </p>

      {c.correlation.length > 0 && (
        <>
          <h3 className={styles.subheading}>Correlation explanations</h3>
          <ul className={styles.evidenceList}>{c.correlation.map((n, i) => <li key={i}>{n}</li>)}</ul>
        </>
      )}

      <h3 className={styles.subheading} style={{ marginTop: 20 }}>Findings, original vs unified</h3>
      {c.findings.length === 0 ? (
        <p className={styles.empty}>Neither engine reported findings for this file.</p>
      ) : (
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th scope="col">Change</th>
                <th scope="col">Severity</th>
                <th scope="col">Scanner</th>
                <th scope="col">Rule</th>
                <th scope="col">Why</th>
              </tr>
            </thead>
            <tbody>
              {c.findings.map((x, i) => (
                <tr key={i} className={styles[`change${x.change}`]}>
                  <td>{CHANGE_LABELS[x.change]}</td>
                  <td><span className={`${styles.severity} ${styles[`sev${x.finding.severity}`]}`}>{x.finding.severity}</span></td>
                  <td>{x.finding.scanner}</td>
                  <td className={styles.ruleCell}><Breakable text={x.finding.rule_id ?? x.finding.category} /></td>
                  <td>{x.reason ?? (x.finding.evidence?.length ? x.finding.evidence.join("; ") : x.finding.description)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className={styles.compareGrid}>
        <ScanResultView result={reference} heading="Original Engine result" />
        <ScanResultView result={unified} heading="Custom Unified Engine result" />
      </div>
    </section>
  );
}
