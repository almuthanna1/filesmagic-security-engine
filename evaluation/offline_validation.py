"""Phase 6 offline VM validation: both engines through the same isolated worker (app.worker.run,
as /scan runs it) on the 16 inert synthetic cases, the known-benign corpus (29 authored + 4 public
government documents, committed with the source), two truncated documents and the 6 inert C7 Word
field-code cases (evaluation.cases.field_cases). Inert and benign files only.

    SECURITY_ENGINE_REQUIRE_ISOLATION=1 /opt/filesmagic/venv/bin/python -B -m evaluation.offline_validation \\
        --expect-commit <sha> --out ~/fm-eval/results/phase6-<sha7>

Aborts (exit 3, run_status.json) unless: strict isolation is configured; on Linux the process is
confined by the AppArmor profile CONFINEMENT in enforce mode; the host has no usable route; the
expected commit is checked out with a clean tree; packages match requirements.txt; every corpus
file matches its manifest's SHA-256; and a preflight scan in each engine reports every required
isolation control and exactly that engine's scanners. Every later scan (every trial) is checked
the same way, and the first that fails stops the run.

Results: results.json, report.md, SHA256SUMS. Each result is compared with the committed Windows
evidence (EXPECTED; for the C7 cases, which postdate it, with the verdicts in field_cases), so differences from Windows/Render are listed by rule, not judged by eye,
and the named CHECKS of the contributions are evaluated from the results.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

from app import main, worker
from evaluation import cases as synthetic
from evaluation import lab_acceptance
from evaluation.benchmark import dependency_drift, host_network, research_checks
from evaluation.evaluate import environment

REPO = Path(__file__).resolve().parent.parent
ENGINES = ("reference", "unified")
CONFINEMENT = "filesmagic-eval-python (enforce)"
CORPUS = (REPO / "evaluation/benign_corpus/files", REPO / "evaluation/benign_corpus/independent")
MANIFESTS = (REPO / "evaluation/benign_corpus/manifest.json", REPO / "evaluation/benign_corpus/independent/manifest.json")
EVIDENCE = REPO / "docs/evidence"
EXPECTED = {"synthetic": {e: EVIDENCE / f"custom-engine-fp-fixes/{e}/results.json" for e in ENGINES},
            "corpus": (EVIDENCE / "benign-corpus/review-local.json",
                       EVIDENCE / "benign-corpus/independent-review-local.json")}
FAIL_CLOSED = "UNABLE_TO_SCAN"


def confinement() -> str | None:
    """This process's AppArmor label, or None where there is none to read (not Linux)."""
    for path in ("/proc/self/attr/apparmor/current", "/proc/self/attr/current"):
        try:
            return Path(path).read_text().strip().rstrip("\x00")
        except OSError:
            continue
    return None


def corpus_items() -> tuple[list[dict], list[str]]:
    items, problems = [], []
    for folder, manifest in zip(CORPUS, MANIFESTS):
        for row in json.loads(manifest.read_text(encoding="utf-8")):
            data = (folder / row["file"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != row["sha256"]:
                problems.append(f"{row['file']} does not match its manifest SHA-256")
            items.append({"id": row["file"], "ground_truth": "KNOWN_BENIGN", "data": data,
                          "indicator": "held-out government document" if folder.name == "independent" else
                          "authored benign document"})
    return items, problems


def corrupt_items() -> list[dict]:
    pdf = next(d for c, d, _ in lab_acceptance.items() if c == "corrupt-truncated-pdf")
    docx = (CORPUS[0] / "docx-01-word-plain.docx").read_bytes()
    return [{"id": i, "ground_truth": "SECURITY_TEST", "indicator": "truncated: must fail closed", "data": d}
            for i, d in (("corrupt-truncated-pdf", pdf), ("corrupt-truncated-docx", docx[: len(docx) // 2]))]


def gates(env: dict, expect_commit: str, problems: list[str]) -> list[str]:
    found = research_checks(env, expect_commit) + problems
    if not env["strict_isolation_configured"]:
        found.append("SECURITY_ENGINE_REQUIRE_ISOLATION=1 is not set")
    if env["confinement"] != CONFINEMENT:
        found.append(f"the interpreter is confined as {env['confinement']!r}, not {CONFINEMENT!r}")
    return found


def scan_problem(result: dict, engine: str) -> str:
    """Why a scan result is not acceptable evidence ("" if it is)."""
    if result["isolation_missing"]:
        return f"{result['id']} ({engine}): isolation controls missing {result['isolation_missing']}"
    if sorted(result["status"]) != sorted(main.engine_scanners(engine)):
        return f"{result['id']} ({engine}): the worker ran {sorted(result['status'])}, not the {engine} engine"
    return ""


def observed(result: dict) -> tuple[str, list[str]]:
    return result["verdicts"]["aggregate"], sorted(f"{f['scanner']}:{f['rule_id']}:{f['severity']}"
                                                   for f in result["findings"])


def expectations() -> dict[tuple[str, str, str], tuple[str, list[str]]]:
    """(set, id, engine) -> (verdict, findings) in the committed Windows evidence."""
    out = {}
    for engine, path in EXPECTED["synthetic"].items():
        for r in json.loads(path.read_text(encoding="utf-8"))["results"]:
            out["synthetic", r["id"], engine] = observed(r)
    for path in EXPECTED["corpus"]:
        for r in json.loads(path.read_text(encoding="utf-8")):
            for engine in ENGINES:
                out["corpus", r["file"], engine] = r[engine]["verdict"], sorted(r[engine]["findings"])
    for c in synthetic.field_cases():  # verdicts only; the rules each must report are in checks()
        for engine in ENGINES:
            out["c7", c["id"], engine] = c["expected"][engine][0], None
    return out


def compare(results: list[dict], expected: dict) -> list[dict]:
    rows = []
    for r in results:
        verdict, findings = observed(r)
        want = expected.get((r["set"], r["id"], r["engine"]))
        if r["set"] == "corrupt":
            want = (FAIL_CLOSED, None)
        rows.append({"set": r["set"], "id": r["id"], "engine": r["engine"], "verdict": verdict,
                     "expected_verdict": want[0] if want else None,
                     "only_here": sorted(set(findings) - set(want[1])) if want and want[1] is not None else [],
                     "only_expected": sorted(set(want[1]) - set(findings)) if want and want[1] is not None else [],
                     "same": bool(want) and verdict == want[0] and (want[1] is None or findings == want[1])})
    return rows


def _has(results: dict, key: tuple[str, str, str], rule: str) -> bool:
    return any(f"{f['scanner']}:{f['rule_id']}".endswith(rule) for f in results[key]["findings"])


def _field_case_holds(by: dict, case: dict, info_only: bool = False) -> bool:
    """Both engines give the expected verdict and report every expected rule; with info_only, C7
    reports nothing above INFO."""
    for engine in ENGINES:
        r, (verdict, required) = by["c7", case["id"], engine], case["expected"][engine]
        found = {f"{f['scanner']}:{f['rule_id']}" for f in r["findings"]}
        if r["verdicts"]["aggregate"] != verdict or not set(required) <= found:
            return False
        if info_only and any(f["scanner"] == "word-fields" and f["severity"] != "INFO" for f in r["findings"]):
            return False
    return True


def checks(results: list[dict]) -> list[tuple[str, bool]]:
    """The contributions, each a claim evaluated from this run's results."""
    by = {(r["set"], r["id"], r["engine"]): r for r in results}
    fields = {c["id"]: c for c in synthetic.field_cases()}
    v = lambda s, i, e: by[s, i, e]["verdicts"]["aggregate"]  # noqa: E731
    syn, cor = "synthetic", "corpus"
    auto = ("2c-pdf-open-at-page-page-open-js", "5a-pdf-auto-js-unrelated-attachment", "5b-pdf-auto-js-exports-attachment")
    return [
        ("5a: unified SUSPICIOUS (the attachment is not on the automatic chain); reference MALICIOUS",
         v(syn, "5a-pdf-auto-js-unrelated-attachment", "unified") == "SUSPICIOUS"
         and v(syn, "5a-pdf-auto-js-unrelated-attachment", "reference") == "MALICIOUS"),
        ("5b: unified MALICIOUS with ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT",
         v(syn, "5b-pdf-auto-js-exports-attachment", "unified") == "MALICIOUS"
         and _has(by, (syn, "5b-pdf-auto-js-exports-attachment", "unified"), ":ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT")),
        ("refined YARA-X rule fires on every automatic page-open/OpenAction script case (2c, 5a, 5b)",
         all(_has(by, (syn, c, "unified"), "yara-x-engine:ENGINE_PDF_JavaScript_With_Automatic_Trigger") for c in auto)),
        ("refined YARA-X rule is silent on the user-triggered cases (2, 2b), which the reference rule flags",
         all(not _has(by, (syn, c, "unified"), ":ENGINE_PDF_JavaScript_With_Automatic_Trigger")
             and _has(by, (syn, c, "reference"), "yara-x:PDF_JavaScript_With_Automatic_Action")
             for c in ("2-pdf-form-keystroke-js", "2b-pdf-open-at-page-click-js"))),
        ("VBA call graph: case 7 reports ENGINE_VBA_CALL_PATH_UNDETERMINED and keeps the reference macro findings",
         _has(by, (syn, "7-docx-macro-declaration-mismatch", "unified"), "vba-chains:ENGINE_VBA_CALL_PATH_UNDETERMINED")
         and _has(by, (syn, "7-docx-macro-declaration-mismatch", "unified"), "yara-x:OOXML_VBA_Macros")),
        ("OOXML correlation: 6c template used on open -> ENGINE_OFFICE_EXTERNAL_ON_OPEN; 6g file share keeps "
         "OFFICE_EXTERNAL_NETWORK_PATH; 6e/6f object displayed / not displayed",
         _has(by, (syn, "6c-docx-template-referenced-by-settings", "unified"), "ooxml-links:ENGINE_OFFICE_EXTERNAL_ON_OPEN")
         and _has(by, (syn, "6g-docx-linked-picture-file-share", "unified"), "office:OFFICE_EXTERNAL_NETWORK_PATH")
         and _has(by, (syn, "6e-docx-embedded-object-displayed", "unified"), ":ENGINE_OFFICE_EMBEDDED_OBJECT_DISPLAYED")
         and _has(by, (syn, "6f-docx-embedded-object-not-displayed", "unified"), ":ENGINE_OFFICE_EMBEDDED_OBJECT_NOT_DISPLAYED")),
        ("false-positive corrections: docx-04, xlsx-04 (local targets) and pdf-07 (verified attachment) SAFE in "
         "unified, SUSPICIOUS in reference",
         all(v(cor, f, "unified") == "SAFE" and v(cor, f, "reference") == "SUSPICIOUS" and _has(by, (cor, f, "unified"), rule)
             for f, rule in (("docx-04-word-linked-picture.docx", ":ENGINE_OFFICE_LOCAL_FILE_TARGETS"),
                             ("xlsx-04-excel-external-workbook-link.xlsx", ":ENGINE_OFFICE_LOCAL_FILE_TARGETS"),
                             ("pdf-07-libreoffice-hybrid.pdf", ":ENGINE_PDF_ATTACHMENTS_VERIFIED")))),
        ("docx-05 local template lowered to LOW but not cleared (SUSPICIOUS)",
         v(cor, "docx-05-word-custom-template.docx", "unified") == "SUSPICIOUS"
         and _has(by, (cor, "docx-05-word-custom-template.docx", "unified"), ":ENGINE_OFFICE_LOCAL_TEMPLATE")),
        ("C7 positives: c7a nested DDEAUTO MALICIOUS, c7c remote INCLUDETEXT and c7d file-share INCLUDEPICTURE "
         "SUSPICIOUS (reference SAFE on all three), each with its C7 rule; c7b keeps OFFICE_DDEAUTO_FIELD",
         all(_field_case_holds(by, fields[i]) for i in ("c7a-docx-nested-ddeauto", "c7b-docx-ddeauto-cmd",
                                                        "c7c-docx-remote-includetext", "c7d-docx-remote-includepicture"))),
        ("C7 negatives: c7e DDEAUTO only in a tracked deletion and c7f ordinary fields SAFE in both engines, "
         "C7 evidence INFO only",
         all(_field_case_holds(by, fields[i], info_only=True) for i in ("c7e-docx-deleted-ddeauto",
                                                                         "c7f-docx-ordinary-fields"))),
        ("corrupted documents fail closed (UNABLE_TO_SCAN) in both engines",
         all(v("corrupt", c, e) == FAIL_CLOSED for c in ("corrupt-truncated-pdf", "corrupt-truncated-docx") for e in ENGINES)),
    ]


def report(env: dict, status: dict, comparison: list[dict], named: list[tuple[str, bool]], results: list[dict]) -> str:
    lines = ["# Offline VM validation", "",
             f"- Status: **{status['status']}**" + (f" ({'; '.join(status['problems'])})" if status["problems"] else ""),
             f"- Commit `{env['engine_commit']}`, clean tree: {env['working_tree_dirty'] is False}; engine "
             f"{env['engine_version']}; rules `{env['ruleset_sha256']}`, engine rules `{env['engine_ruleset_sha256']}`",
             f"- {env['platform']}, Python {env['python']}; confinement `{env['confinement']}`; strict isolation "
             f"{env['strict_isolation_configured']}; host network {env['host_network']}; drift {env['dependency_drift']}",
             f"- Trials: synthetic {env['trials']['synthetic']}, corpus and corrupt {env['trials']['corpus']}", ""]
    if named:
        lines += ["## Contributions", "", "| Claim | Result |", "|---|---|"]
        lines += [f"| {claim} | {'PASS' if ok else '**FAIL**'} |" for claim, ok in named] + [""]
    if comparison:
        same = sum(r["same"] for r in comparison)
        old = [r for r in comparison if r["set"] != "c7"]
        lines += ["## Against the expected results", "",
                  f"Windows evidence: {sum(r['same'] for r in old)} of {len(old)} scan results identical (verdict and "
                  "every finding, INFO included).",
                  f"C7 cases: {same - sum(r['same'] for r in old)} of {len(comparison) - len(old)} verdicts as expected "
                  "(evaluation.cases.field_cases; the rules are checked in Contributions).", ""]
        if diff := [r for r in comparison if not r["same"]]:
            lines += ["| Set | File | Engine | Verdict here | Expected | Only here | Only expected |", "|---|---|---|---|---|---|---|"]
            lines += [f"| {r['set']} | {r['id']} | {r['engine']} | {r['verdict']} | {r['expected_verdict']} | "
                      f"{', '.join(r['only_here'])} | {', '.join(r['only_expected'])} |" for r in diff]
        lines.append("")
    if results:
        lines += ["## Results", "", "| Set | File | Engine | Verdict | Failed scanners | Wall p50 ms | Scanner p50 ms |",
                  "|---|---|---|---|---|---|---|"]
        for r in results:
            t = r["timing_ms"]
            per = ", ".join(f"{k} {t[k]['median_ms']}" for k in r["status"] if r["status"][k] != "not_applicable")
            failed = ", ".join(k for k, s in r["status"].items() if s == "failed") or "-"
            lines.append(f"| {r['set']} | {r['id']} | {r['engine']} | {r['verdicts']['aggregate']} | {failed} | "
                         f"{t['harness_wall']['median_ms']} | {per} |")
    return "\n".join(lines) + "\n"


def write(out: Path, env, status, preflight, results, comparison, named) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "run_status.json").write_text(json.dumps(status | {"preflight": preflight}, indent=2) + "\n")
    (out / "results.json").write_text(json.dumps({"environment": env, "run_status": status, "preflight": preflight,
                                                  "checks": [{"claim": c, "pass": ok} for c, ok in named],
                                                  "comparison": comparison, "results": results}, indent=2) + "\n")
    (out / "report.md").write_text(report(env, status, comparison, named, results))
    sums = [f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}" for n in ("report.md", "results.json", "run_status.json")]
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n")


def main_(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--expect-commit", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=20, help="per synthetic case and engine")
    parser.add_argument("--corpus-trials", type=int, default=5, help="per corpus or corrupt file and engine")
    args = parser.parse_args(argv)
    if args.out.exists():
        print(f"STOPPED: {args.out} exists; results are never overwritten", file=sys.stderr)
        return 3

    env = environment(None) | {"host_network": host_network(), "dependency_drift": dependency_drift(),
                               "confinement": confinement(), "worker_command": worker.command()[3:],
                               "engine_ruleset_sha256": main.VERSIONS.get("engine_ruleset_sha256"),
                               "trials": {"synthetic": args.trials, "corpus": args.corpus_trials}}
    corpus, problems = corpus_items()
    status, preflight, results = {"status": "aborted", "problems": gates(env, args.expect_commit, problems)}, {}, []
    sets = [("synthetic", synthetic.cases(), args.trials), ("corpus", corpus, args.corpus_trials),
            ("corrupt", corrupt_items(), args.corpus_trials), ("c7", synthetic.field_cases(), args.trials)]
    if not status["problems"]:
        for engine in ENGINES:  # preflight: an empty input, so nothing is parsed if isolation is not complete
            probe = synthetic.scan_case({"id": "preflight", "ground_truth": "-", "indicator": "-", "data": b""}, 1,
                                        worker.command() + worker.ENGINE_ARGS[engine])
            preflight[engine] = {"isolation_missing": probe["isolation_missing"], "status": probe["status"]}
            if why := scan_problem(probe, engine):
                status["problems"].append(f"preflight: {why}")
    if not status["problems"]:
        for name, items, trials in sets:
            for item in items:
                for engine in ENGINES:
                    r = synthetic.scan_case(item, trials, worker.command() + worker.ENGINE_ARGS[engine])
                    results.append({"set": name, "engine": engine, **r})
                    print(f"{name:9} {r['id']:45} {engine:9} {r['verdicts']['aggregate']:14} "
                          f"{r['timing_ms']['harness_wall']['median_ms']} ms", flush=True)
                    if why := scan_problem(r, engine):
                        status["problems"].append(why)
                        break
                if status["problems"]:
                    break
            if status["problems"]:
                break
        else:
            status["status"] = "completed"
    complete = status["status"] == "completed"
    comparison = compare(results, expectations()) if complete else []
    named = checks(results) if complete else []
    write(args.out, env, status, preflight, results, comparison, named)
    print((args.out / "report.md").read_text())
    return 3 if not complete else 0 if all(ok for _, ok in named) else 1  # 1: completed, a claim failed


if __name__ == "__main__":
    raise SystemExit(main_())
