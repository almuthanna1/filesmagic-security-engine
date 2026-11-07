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
  { title: "VBA call paths", note: "From an automatically running procedure to a dangerous operation, through demonstrated calls.",
    match: (f) => f.scanner === "vba-chains" },
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
              {f.evidence?.length ? (
                <ul className={styles.evidenceList}>
                  {f.evidence.map((e, j) => <li key={j}>{e}</li>)}
                </ul>
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
