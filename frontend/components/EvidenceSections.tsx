import Breakable from "@/components/Breakable";
import type { Finding } from "@/lib/api";
import styles from "./ScanResultView.module.css";

// The custom engine's structured evidence, grouped by what it explains. Shows only groups that
// have findings, so a result from the original engine renders nothing here.
const GROUPS: { title: string; note: string; match: (f: Finding) => boolean }[] = [
  { title: "Correlation explanations", note: "How the unified engine reconciled the original scanners' findings.",
    match: (f) => f.rule_id === "ENGINE_CORRELATION" },
  { title: "PDF action chains", note: "Trigger → actions started through /Next, and the embedded files they use.",
    match: (f) => f.scanner === "pdf-chains" && f.rule_id !== "ENGINE_CORRELATION" },
  { title: "Extracted VBA source", note: "Exactly what the parser recovered for short macros; longer modules are clearly marked as excerpts. Code was not executed, and compiled VBA P-code was not verified.",
    match: (f) => f.rule_id === "ENGINE_VBA_SOURCE" || f.rule_id === "ENGINE_VBA_SOURCE_OMITTED" },
  { title: "VBA call paths", note: "Detected VBA entry points and any demonstrated paths to dangerous operations.",
    match: (f) => f.scanner === "vba-chains" && f.rule_id !== "ENGINE_VBA_SOURCE" && f.rule_id !== "ENGINE_VBA_SOURCE_OMITTED" },
  { title: "OOXML relationship evidence", note: "Which loaded part references each relationship, and when Office uses it.",
    match: (f) => f.scanner === "ooxml-links" },
];

export default function EvidenceSections({ findings }: { findings: Finding[] }) {
  const groups = GROUPS.map((g) => ({ ...g, items: findings.filter(g.match) })).filter((g) => g.items.length);
  if (!groups.length) return null;
  return (
    <div className={styles.evidence}>
      {groups.map((g) => (
        <section key={g.title} className={styles.evidenceGroup} aria-label={g.title}>
          <h3 className={styles.subheading}>{g.title}</h3>
          <p className={styles.evidenceNote}>{g.note}</p>
          {g.items.map((f, i) => (
            <div key={i} className={styles.evidenceItem}>
              <p>
                <span className={`${styles.severity} ${styles[`sev${f.severity}`]}`}>{f.severity}</span>{" "}
                {f.rule_id !== "ENGINE_CORRELATION" && <code className={styles.ruleCell}><Breakable text={f.rule_id ?? ""} /></code>}
              </p>
              {f.rule_id === "ENGINE_VBA_SOURCE" && <p className={styles.vbaExplanation}>{f.description}</p>}
              {f.evidence?.length ? (
                f.rule_id === "ENGINE_VBA_SOURCE" ? (
                  <div>
                    {f.evidence.map((e, j) => <pre key={j} className={styles.vbaSource}><code>{e}</code></pre>)}
                  </div>
                ) : (
                  <ul className={styles.evidenceList}>
                    {f.evidence.map((e, j) => <li key={j}>{e}</li>)}
                  </ul>
                )
              ) : (
                <p>{f.description}</p>
              )}
            </div>
          ))}
        </section>
      ))}
    </div>
  );
}
