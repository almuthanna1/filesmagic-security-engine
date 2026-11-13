"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { TEST_CASES, type Verdict } from "@/lib/testCatalog";
import ExternalTestSection from "@/components/ExternalTestSection";
import AdditionalValidationSection from "@/components/AdditionalValidationSection";
import styles from "./page.module.css";

type Observation = Verdict | "";
type Observations = Record<string, Observation>;
const SAVE_KEY = "filesmagic-test-files-observed-v1";
const ALL_VERDICTS: Verdict[] = ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNABLE_TO_SCAN"];
const GROUPS = ["Benign controls", "Suspicious indicators", "High-severity indicators", "Parser failure"] as const;

export default function TestFilesPage() {
  const [observed, setObserved] = useState<Observations>({});
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    let active = true;
    queueMicrotask(() => {
      if (!active) return;
      try {
        const data = JSON.parse(window.localStorage.getItem(SAVE_KEY) || "{}");
        if (data && typeof data === "object" && !Array.isArray(data)) setObserved(data as Observations);
      } catch { /* local storage can be blocked, so the list still works */ }
      setLoaded(true);
    });
    return () => { active = false; };
  }, []);

  function record(id: string, value: Observation) {
    const next = { ...observed, [id]: value };
    setObserved(next);
    try { window.localStorage.setItem(SAVE_KEY, JSON.stringify(next)); } catch { /* best effort */ }
  }

  const completed = TEST_CASES.filter((t) => observed[t.id]).length;
  const matched = TEST_CASES.filter((t) => observed[t.id] === t.expected).length;

  return (
    <main className={styles.main}>
      <nav className={styles.nav}><Link href="/">← Back to Security Lab scanner</Link></nav>
      <header className={styles.header}>
        <p className={styles.eyebrow}>FilesMagic Security Lab / Test library</p>
        <h1>Test Files</h1>
        <p>Test the original 10-file research set, 32 source-pinned validation downloads, or generated functional fixtures. For the new validation set, use the inline scanner to run each file and copy its actual findings without opening another scanner tab.</p>
      </header>
      <div className={styles.warning}>
        <strong>Controlled functional tests — not real malware.</strong> The expected “MALICIOUS” label means the scanner should flag an inert high-severity indicator. Do not count these as true-positive malware samples in your capstone dataset. Do not open active-content test files in PDF/Office viewers; download and upload them directly to the scanner. Real malware must never be uploaded to the public Render endpoint.
      </div>
      <div className={styles.overview}>
        <div><b>{TEST_CASES.length}</b><span>Downloadable fixtures</span></div>
        <div><b>{loaded ? completed : "—"}</b><span>Scanned & recorded</span></div>
        <div><b>{loaded ? matched : "—"}</b><span>Matched expectation</span></div>
      </div>
      <p className={styles.help}>Observed verdicts are saved only in this browser (inside the VM). Take a screenshot of this page to share results back in our chat. An unexpected verdict is useful evidence, not an automatic scanner failure.</p>
      <ExternalTestSection />
      <AdditionalValidationSection />
      <h2 className={styles.syntheticHeading}>Generated functional fixtures</h2>
      {GROUPS.map((group) => (
        <section className={styles.group} key={group} aria-label={group}>
          <h2>{group}</h2>
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead><tr>
                <th scope="col">Test file</th>
                <th scope="col">Expected</th>
                <th scope="col">Indicator / purpose</th>
                <th scope="col">Actual verdict</th>
                <th scope="col">File</th>
              </tr></thead>
              <tbody>
                {TEST_CASES.filter((t) => t.group === group).map((t) => {
                  const current = observed[t.id] || "";
                  return <tr key={t.id}>
                    <td><strong>{t.filename}</strong><small>{t.format} · {t.note}</small></td>
                    <td><span className={styles.verdict}>{t.expected}</span></td>
                    <td className={styles.rule}>{t.rule}</td>
                    <td>
                      <label className={styles.srOnly} htmlFor={"observed-" + t.id}>Observed verdict for {t.filename}</label>
                      <select id={"observed-" + t.id} value={current} onChange={(e) => record(t.id, e.target.value as Observation)}>
                        <option value="">Not tested</option>
                        {ALL_VERDICTS.map((verdict) => <option key={verdict} value={verdict}>{verdict}</option>)}
                      </select>
                      {current && <span className={current === t.expected ? styles.pass : styles.mismatch}>{current === t.expected ? "Matches" : "Different"}</span>}
                    </td>
                    <td><a className={styles.download} href={"/test-files/download/" + t.id} download={t.filename}>Download</a></td>
                  </tr>;
                })}
              </tbody>
            </table>
          </div>
        </section>
      ))}
      <footer className={styles.footer}>Fixture set v1 · Expected verdicts exercise the unified nine-component engine using inert indicators. These checks do not measure detection accuracy, recall, or false-positive rates on an independently labelled malware dataset.</footer>
    </main>
  );
}
