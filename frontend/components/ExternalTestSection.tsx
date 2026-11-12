"use client";

import { useEffect, useState } from "react";
import { EXTERNAL_TEST_CASES, type ExternalLabel, type ExternalTarget } from "@/lib/externalTestCatalog";
import type { Verdict } from "@/lib/testCatalog";
import styles from "./ExternalTestSection.module.css";

type Observation = Verdict | "";
type Observations = Record<string, Observation>;
const SAVE_KEY = "filesmagic-independent-corpus-observed-v1";
const VERDICTS: Verdict[] = ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNABLE_TO_SCAN"];
const GROUPS: ExternalLabel[] = ["BENIGN", "SUSPICIOUS FEATURE", "MALWARE-LABELED"];

function meetsTarget(target: ExternalTarget, actual: Observation): boolean {
  if (!actual) return false;
  return target === "SAFE"
    ? actual === "SAFE"
    : actual === "SUSPICIOUS" || actual === "MALICIOUS";
}

export default function ExternalTestSection() {
  const [observed, setObserved] = useState<Observations>({});
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let active = true;
    queueMicrotask(() => {
      if (!active) return;
      try {
        const data = JSON.parse(window.localStorage.getItem(SAVE_KEY) || "{}");
        if (data && typeof data === "object" && !Array.isArray(data)) {
          setObserved(data as Observations);
        }
      } catch { /* Browser storage is optional. */ }
      setLoaded(true);
    });
    return () => { active = false; };
  }, []);

  function record(id: string, value: Observation) {
    const next = { ...observed, [id]: value };
    setObserved(next);
    try { window.localStorage.setItem(SAVE_KEY, JSON.stringify(next)); } catch { /* best effort */ }
  }

  const completed = EXTERNAL_TEST_CASES.filter((test) => observed[test.id]).length;
  const met = EXTERNAL_TEST_CASES.filter((test) => meetsTarget(test.target, observed[test.id] || "")).length;

  return (
    <section className={styles.section} aria-labelledby="independent-tests-heading">
      <header className={styles.header}>
        <p className={styles.eyebrow}>Final evaluation / Independent sources</p>
        <h2 id="independent-tests-heading">10-file external test set</h2>
        <p>Source-revision-pinned GitHub file pages, proposed result targets, and a separate record of actual verdicts. These files are not generated or hosted by FilesMagic.</p>
      </header>

      <div className={styles.caution}>
        <strong>Safety and offline workflow.</strong> Files 08–10 are real, malware-labeled research samples, not harmless simulations. Do not open suspicious documents in Office or PDF viewers, execute them, or upload them to the public Render Security Engine. Run scans only against the locally hosted engine in the isolated VM. A fully offline VM cannot visit GitHub or the public Security Lab: obtain and checksum approved files before isolation, then transfer them using the established verified ISO workflow. Do not enable networking, shared folders, or clipboard just to access these links.
      </div>

      <div className={styles.stats} aria-label="Independent evaluation progress">
        <div><b>{EXTERNAL_TEST_CASES.length}</b><span>External files</span></div>
        <div><b>{loaded ? completed : "—"}</b><span>Verdicts recorded</span></div>
        <div><b>{loaded ? met : "—"}</b><span>Targets met</span></div>
      </div>
      <p className={styles.explainer}>For benign controls, target is SAFE. For suspicious-feature and malware-labeled cases, the detection target is SUSPICIOUS or MALICIOUS, but the actual verdict is unknown until testing. Source labels and scanner verdicts are not interchangeable. A suspicious finding in a benign attachment test is not a true-positive malware detection.</p>

      {GROUPS.map((group) => (
        <div className={styles.group} key={group}>
          <h3>{group === "BENIGN" ? "Benign controls" : group === "SUSPICIOUS FEATURE" ? "Suspicious structural features" : "Malware-labeled OLE documents"}</h3>
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th scope="col">File / provenance</th>
                  <th scope="col">Detection target</th>
                  <th scope="col">Purpose and labeling caveat</th>
                  <th scope="col">Actual verdict</th>
                  <th scope="col">GitHub link</th>
                </tr>
              </thead>
              <tbody>
                {EXTERNAL_TEST_CASES.filter((test) => test.sourceLabel === group).map((test) => {
                  const actual = observed[test.id] || "";
                  return (
                    <tr key={test.id}>
                      <td>
                        <strong className={styles.filename}>{test.filename}</strong>
                        <small>{test.format} · {test.source}</small>
                      </td>
                      <td>
                        <strong className={styles.target}>{test.target === "SAFE" ? "SAFE" : "SUSPICIOUS / MALICIOUS"}</strong>
                        <small>{group === "MALWARE-LABELED" ? "Desired detection, not assured" : "Proposed scanner behavior"}</small>
                      </td>
                      <td className={styles.purpose}>
                        {test.purpose}
                        <small>{test.caveat}</small>
                      </td>
                      <td>
                        <label className={styles.srOnly} htmlFor={"external-observed-" + test.id}>Observed verdict for {test.filename}</label>
                        <select
                          id={"external-observed-" + test.id}
                          value={actual}
                          onChange={(e) => record(test.id, e.target.value as Observation)}
                        >
                          <option value="">Not tested</option>
                          {VERDICTS.map((v) => <option value={v} key={v}>{v}</option>)}
                        </select>
                        {actual && <span className={meetsTarget(test.target, actual) ? styles.pass : styles.mismatch}>
                          {meetsTarget(test.target, actual) ? "Target met" : "Investigate"}
                        </span>}
                      </td>
                      <td>
                        <a className={styles.link} href={test.githubUrl} target="_blank" rel="noopener noreferrer" aria-label={"Open pinned GitHub source for " + test.filename}>
                          View source file ↗
                        </a>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ))}

      <p className={styles.footer}>Open a GitHub file page on a network-connected staging device, verify the file type and SHA-256, and retain the source URL and hash for the capstone report. Record YARA-X, Office, and PDF findings along with each final verdict and latency. Do not interpret this 10-file exploratory set as a statistically representative accuracy benchmark.</p>
    </section>
  );
}
