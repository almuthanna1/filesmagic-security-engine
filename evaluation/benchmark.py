"""Batch scanning and benchmarking: which detection method finds which known feature, and how fast.

Runs every sample of a prepared manifest (evaluation.prepare_samples) through the engine's
/scan code path, repeated `--trials` times, with the existing harness's strict-isolation
preflight and per-sample isolation check (evaluation.evaluate). For each sample it records, per
scanner (YARA-X, PDF Analysis, Office Analysis, Custom): applicable or not, completed or failed,
rule IDs and severities, coverage limits, and the scanner's own duration inside the isolated
worker; plus the worker's total latency (engine duration_ms) and the harness wall-clock time.
PDFiD (Didier Stevens, pinned and reviewed) is run as an independent reference on PDF samples,
outside the engine, and reported separately from FilesMagic's results.

A research run (the default) refuses to start unless: the evaluation host itself has no usable
network route, the expected commit is checked out with a clean tree, installed packages match
requirements.txt, and the strict-isolation preflight passes. Samples are labelled by what they
are: generated documents are BENIGN even when they carry an indicator; EICAR is SECURITY_TEST.
Nothing here measures malware detection accuracy.

    python -m evaluation.benchmark --manifest ~/fm-eval/eicar-didier/manifest.csv \
        --samples-root ~/fm-eval/eicar-didier --acquired ~/fm-acquired \
        --expect-commit <sha> --trials 20 --out ~/fm-eval/results/eicar-didier-run1
"""

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from importlib import metadata
from pathlib import Path

from evaluation import prepare_samples
from evaluation.evaluate import (
    REPO_ROOT, EvaluationAborted, ManifestError, environment, failure_reason, isolation_verified, latency,
    load_manifest, make_client, post_scan, sha256_of, strict_preflight, write_status,
)

SCANNERS = ["yara-x", "pdf", "office", "custom"]
REFERENCE = "pdfid"
# Which rule IDs count as a scanner identifying a feature. A scanner without an entry for a
# feature was not designed to detect it ("—" in the tables), which is different from missing it.
FEATURES = {
    "pdf-javascript": {"yara-x": {"PDF_JavaScript_With_Automatic_Action"},
                       "pdf": {"PDF_JAVASCRIPT", "PDF_AUTO_JAVASCRIPT", "PDF_JAVASCRIPT_EXPLOIT_API"}},
    "pdf-auto-action": {"yara-x": {"PDF_JavaScript_With_Automatic_Action"}, "pdf": {"PDF_AUTO_JAVASCRIPT"}},
    "pdf-name-obfuscation": {"custom": {"CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME", "CUSTOM_PDF_UNNECESSARY_NAME_ESCAPES"}},
    "pdf-embedded-file": {"yara-x": {"PDF_Embedded_File"}, "pdf": {"PDF_EMBEDDED_FILE", "PDF_EMBEDDED_EXECUTABLE"}},
    "office-external-autoload": {"office": {"OFFICE_EXTERNAL_AUTOLOAD", "OFFICE_EXTERNAL_DANGEROUS_SCHEME"}},
    "office-macro-project": {"yara-x": {"OOXML_VBA_Macros", "OLE_Office_VBA_Macros"},
                             "office": {"OFFICE_MACROS_PRESENT", "OFFICE_VBA_UNPARSED"}},
    "office-macro-declaration-mismatch": {"custom": {"CUSTOM_OFFICE_MACRO_DECLARATION_MISMATCH"}},
    "eicar-test-string": {},  # no FilesMagic scanner has an EICAR rule, by design; the result is recorded as is
}
# PDFiD keywords that indicate each feature (count > 0); name obfuscation = any keyword's hexcodecount > 0.
PDFID_FEATURES = {"pdf-javascript": ("/JS", "/JavaScript"), "pdf-auto-action": ("/OpenAction", "/AA"),
                  "pdf-embedded-file": ("/EmbeddedFile",)}
PDFID_DRIVER = (
    "import sys, pdfid\n"
    "p = sys.argv[1]\n"
    "if not p.lower().endswith('.pdf') or '://' in p: sys.exit(2)\n"  # local PDFs only: no URL, no ZIP path
    "print(pdfid.PDFiD2JSON(pdfid.PDFiD(p, allNames=False, extraData=False, disarm=False, force=False), False))\n"
)


# ----------------------------------------------------------------------------- research-run checks


def host_network(read=None) -> dict:
    """Is the evaluation host itself offline: no usable IPv4/IPv6 route outside lo? (Linux)"""
    from app.worker import usable_routes

    if read is None:
        if not sys.platform.startswith("linux"):
            return {"checked": False, "offline": None, "reason": "not Linux: cannot verify"}
        read = lambda p: Path(p).read_text() if Path(p).exists() else ""  # noqa: E731
    v4 = usable_routes(read("/proc/net/route"), 3, 0, header=True)
    v6 = usable_routes(read("/proc/net/ipv6_route"), 8, 9, header=False)
    return {"checked": True, "offline": v4 == 0 and v6 == 0, "usable_routes_v4": v4, "usable_routes_v6": v6}


def dependency_drift(requirements: Path = REPO_ROOT / "requirements.txt") -> list[str]:
    """Installed versions that differ from requirements.txt pins (platform-conditional pins skipped)."""
    drift = []
    for line in requirements.read_text(encoding="utf-8").splitlines():
        if m := re.match(r"^([A-Za-z0-9_.-]+)==([^\s;]+)\s*$", line.strip()):
            try:
                installed = metadata.version(m.group(1))
            except metadata.PackageNotFoundError:
                installed = None
            if installed != m.group(2):
                drift.append(f"{m.group(1)}: required {m.group(2)}, installed {installed}")
    return drift


def research_checks(env: dict, expect_commit: str | None) -> list[str]:
    problems = []
    if not env["host_network"]["offline"]:
        problems.append(f"the evaluation host is not verifiably offline: {env['host_network']}")
    if expect_commit and env["engine_commit"] != expect_commit:
        problems.append(f"checked-out commit {env['engine_commit']} is not the expected {expect_commit}")
    if env["working_tree_dirty"]:
        problems.append("the working tree has uncommitted changes")
    if env["dependency_drift"]:
        problems.append(f"dependencies differ from requirements.txt: {'; '.join(env['dependency_drift'])}")
    return problems


# ----------------------------------------------------------------------------- PDFiD reference


def pdfid_tools(acquired: Path | None, work: Path) -> Path | None:
    if not acquired:
        return None
    cache = prepare_samples.verified_cache(acquired)
    if "ds-pdfid" not in cache:
        return None
    tools = work / "pdfid"
    tools.mkdir()
    shutil.copyfile(cache["ds-pdfid"], tools / "pdfid.py")
    return tools


def pdfid_reference(tools: Path, pdf: Path) -> dict:
    from app.worker import child_env

    try:
        done = subprocess.run([sys.executable, "-E", "-s", "-c", PDFID_DRIVER, str(pdf.resolve())], cwd=tools,
                              env=child_env(), stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=prepare_samples.TOOL_TIMEOUT_SECONDS, check=True)
        line = next(x for x in reversed(done.stdout.decode("utf-8", "replace").splitlines()) if x.startswith("[{"))
        data = json.loads(line)[0]["pdfid"]
    except (subprocess.SubprocessError, StopIteration, ValueError, KeyError, IndexError) as e:
        return {"error": type(e).__name__}
    keywords = {k["name"]: {"count": k["count"], "hexcodecount": k["hexcodecount"]} for k in data["keywords"]["keyword"]}
    return {"is_pdf": data.get("isPdf"), "keywords": {k: v for k, v in keywords.items() if v["count"]},
            "error": data.get("errorMessage") or None}


def pdfid_features(ref: dict | None) -> dict[str, str]:
    if not ref or ref.get("error") and not ref.get("keywords"):
        return {}
    kw = ref.get("keywords", {})
    found = {f: "yes" if any(kw.get(k, {}).get("count") for k in names) else "no" for f, names in PDFID_FEATURES.items()}
    found["pdf-name-obfuscation"] = "yes" if any(v["hexcodecount"] for v in kw.values()) else "no"
    return found


# ----------------------------------------------------------------------------- scanning


def expected(row: dict) -> list[str]:
    return [t.split(":", 1)[1] for t in row["tags"].split(";") if t.startswith("expect:") and t != "expect:none"]


def cell(feature: str, scanner: dict, name: str) -> str:
    rules = FEATURES.get(feature, {}).get(name)
    if not rules:
        return "—"  # not designed to detect this feature
    if scanner["status"] == "not_applicable":
        return "n/a"
    if scanner["status"] != "completed":  # failed, or no report at all (worker or HTTP error)
        return "failed"
    return "yes" if rules & set(scanner["rule_ids"]) else "no"


def values(xs: list) -> list:
    return [x for x in xs if x is not None]


def scanner_ms(body: dict | None, name: str) -> float | None:
    return next((s.get("duration_ms") for s in body["scanners"] if s["name"] == name), None) if body else None


def sample_result(row: dict, trials: list[dict]) -> dict:
    bodies = [t["body"] for t in trials if t["body"]]
    first = bodies[0] if bodies else None
    scanners = {}
    for name in SCANNERS:
        status = next((s for s in first["scanners"] if s["name"] == name), {}) if first else {}
        found = [f for f in first["findings"] if f["scanner"] == name] if first else []
        scanners[name] = {
            "status": status.get("status", "unknown"), "error_kind": status.get("error_kind"),
            "error_type": status.get("error_type"),
            "rule_ids": sorted({f["rule_id"] for f in found if f["rule_id"]}),
            "findings": [{"rule_id": f["rule_id"], "severity": f["severity"], "category": f["category"]} for f in found],
            "non_info_findings": sum(f["severity"] != "INFO" for f in found),
            "coverage_limited": any((f["rule_id"] or "").endswith("_COVERAGE_LIMITED") for f in found),
            # One entry per trial, aligned with timing_ms; None where the trial produced no report.
            "duration_ms": [scanner_ms(t["body"], name) for t in trials],
        }
    signature = {(b["verdict"], tuple(sorted((f["scanner"], f["rule_id"] or "") for f in b["findings"]))) for b in bodies}
    engine = [t["body"]["duration_ms"] if t["body"] else None for t in trials]
    scanner_sums = [sum(s.get("duration_ms") or 0 for s in t["body"]["scanners"]) if t["body"] else None for t in trials]
    want = expected(row)
    detected = {f for f in FEATURES for n in SCANNERS if cell(f, scanners[n], n) == "yes"}
    return {
        "sample_id": row["sample_id"], "source": row["source"], "file_type": row["file_type"],
        "ground_truth": row["ground_truth"], "sha256": row["sha256"], "size_bytes": row["_size"],
        "expected": want, "control": "negative" if not want else "indicator",
        "verdict": first["verdict"] if first else "ERROR", "complete": first["complete"] if first else False,
        "failure_reason": trials[0]["failure_reason"], "deterministic": len(signature) <= 1,
        "trials": len(trials), "scanners": scanners,
        "timing_ms": {"harness_wall": [t["wall_ms"] for t in trials], "worker_total": engine,
                      "worker_overhead": [round(e - s, 3) if e is not None else None for e, s in zip(engine, scanner_sums)]},
        "features": {f: {n: cell(f, scanners[n], n) for n in SCANNERS} for f in sorted(set(want) | detected)},
        "unexpected_features": sorted(detected - set(want)),
    }


def scan(rows: list[dict], trials: int, client, key, require_isolation: bool) -> tuple[list[dict], str, list[str]]:
    """Results, the run status, and the samples never scanned because isolation was lost."""
    results, status = [], "completed"
    todo = [r for r in rows if not r["duplicate_of"] and r["ground_truth"] != "EXCLUDED"]
    for index, row in enumerate(todo):
        data, records = row["_path"].read_bytes(), []
        for _ in range(trials):
            start = time.perf_counter()
            response = post_scan(client, key, data, row["sample_id"])
            body = response.json() if response.status_code == 200 else None
            reason = failure_reason(response.status_code, body)
            records.append({"wall_ms": round((time.perf_counter() - start) * 1000, 3), "body": body,
                            "failure_reason": reason})
            if require_isolation and body and reason != "worker_failure" and not isolation_verified(body):
                status = "failed_isolation_lost"
                break
        results.append(sample_result(row, records))
        if status != "completed":
            return results, status, [r["sample_id"] for r in todo[index + 1:]]
    return results, status, []


# ----------------------------------------------------------------------------- comparisons


def detection_counts(results: list[dict], names: list[str]) -> dict:
    """feature -> method -> {expected, detected, applicable}, over samples that carry the feature."""
    table = {}
    for r in results:
        for f in r["expected"]:
            pdfid_feature = f in PDFID_FEATURES or f == "pdf-name-obfuscation"
            row = table.setdefault(f, {n: {"expected": 0, "detected": 0,
                                           "designed": pdfid_feature if n == REFERENCE else bool(FEATURES[f].get(n))}
                                       for n in names})
            for n in names:
                value = r.get("pdfid_features", {}).get(f) if n == REFERENCE else r["features"].get(f, {}).get(n)
                row[n]["expected"] += value not in (None, "—", "n/a")
                row[n]["detected"] += value == "yes"
    return table


def comparisons(results: list[dict]) -> dict:
    by_control = {}
    for group in ("negative", "indicator"):
        rs = [r for r in results if r["control"] == group]
        by_control[group] = {"samples": len(rs), "verdicts": dict(Counter(r["verdict"] for r in rs)),
                             "non_info_findings": {n: sum(r["scanners"][n]["non_info_findings"] for r in rs) for n in SCANNERS}}
    only_custom = [(r["sample_id"], f) for r in results for f, cells in r["features"].items()
                   if cells["custom"] == "yes" and not any(cells[n] == "yes" for n in ("yara-x", "pdf", "office"))]
    pdfs = [r for r in results if r["file_type"] == "pdf"]
    disagreements = [(r["sample_id"], f, cells["yara-x"], cells["pdf"]) for r in pdfs for f, cells in r["features"].items()
                     if {cells["yara-x"], cells["pdf"]} <= {"yes", "no"} and cells["yara-x"] != cells["pdf"]]
    return {
        "detection": detection_counts(results, SCANNERS + [REFERENCE]),
        "yara_vs_pdf_disagreements": disagreements,
        "detected_only_by_custom": only_custom,
        "clean_vs_indicator": by_control,
        "false_positive_candidates": [{"sample_id": r["sample_id"], "verdict": r["verdict"],
                                       "non_info": {n: r["scanners"][n]["rule_ids"] for n in SCANNERS
                                                    if r["scanners"][n]["non_info_findings"]}}
                                      for r in results if r["control"] == "negative"
                                      and any(r["scanners"][n]["non_info_findings"] for n in SCANNERS)],
        "unexpected_feature_detections": [(r["sample_id"], r["unexpected_features"]) for r in results if r["unexpected_features"]],
        "incomplete": [{"sample_id": r["sample_id"], "failure_reason": r["failure_reason"],
                        "coverage_limited": [n for n in SCANNERS if r["scanners"][n]["coverage_limited"]]}
                       for r in results if r["failure_reason"] or any(r["scanners"][n]["coverage_limited"] for n in SCANNERS)],
        "nondeterministic": [r["sample_id"] for r in results if not r["deterministic"]],
    }


def timing(results: list[dict]) -> dict:
    out = {k: latency(values([v for r in results for v in r["timing_ms"][k]]))
           for k in ("worker_total", "worker_overhead", "harness_wall")}
    for n in SCANNERS:
        applicable = [v for r in results if r["scanners"][n]["status"] != "not_applicable" for v in r["scanners"][n]["duration_ms"]]
        out[f"scanner:{n}"] = latency(values(applicable))
    out["by_file_type"] = {t: latency(values([v for r in results if r["file_type"] == t for v in r["timing_ms"]["worker_total"]]))
                           for t in sorted({r["file_type"] for r in results})}
    return out


# ----------------------------------------------------------------------------- output


def mark(v: str | None) -> str:
    return {"yes": "✔", "no": "✘", "n/a": "n/a", "failed": "FAILED", "—": "—", None: "–"}.get(v, str(v))


def report(results: list[dict], comp: dict, times: dict, env: dict, status: dict) -> str:
    valid = status["status"] == "completed" and status["strict_isolation_required"]
    lines = ["# FilesMagic: EICAR and Didier Stevens feature-detection study", ""]
    if not valid:
        lines += [f"> **NOT A VALID RESEARCH RUN** (status `{status['status']}`, strict isolation required: "
                  f"{status['strict_isolation_required']}). Functional output only; do not report these numbers.", ""]
    lines += [
        f"- Engine commit `{env['engine_commit']}`{' (DIRTY tree)' if env['working_tree_dirty'] else ''}, rule set "
        f"`{env['ruleset_sha256']}`; Python {env['python']} on {env['platform']}",
        f"- Strict isolation: preflight request `{status['preflight'].get('request_id', '–')}`; evaluation host network: "
        f"{env['host_network']}", f"- Manifest SHA-256 `{env['manifest_sha256']}`; {len(results)} samples × "
        f"{status['trials']} trials; PDFiD reference: {env['pdfid']}", "",
        "Ground truth: generated documents are **BENIGN** (inert, the indicator is present by construction); EICAR is "
        "**SECURITY_TEST**. A detection here shows that a method recognises a *structure*, not that it detects malware.", "",
        "## Samples", "", "| Sample | Source | Expected features | Verdict | YARA-X | PDF | Office | Custom |",
        "|---|---|---|---|---|---|---|---|"]
    for r in results:
        cells = [", ".join(r["scanners"][n]["rule_ids"]) or {"not_applicable": "n/a", "completed": "no findings"}.get(
            r["scanners"][n]["status"], r["scanners"][n]["status"].upper()) for n in SCANNERS]
        lines.append(f"| {r['sample_id']} | {r['source']} | {', '.join(r['expected']) or 'none (control)'} | "
                     f"{r['verdict']} | " + " | ".join(cells) + " |")
    lines += ["", "## Which method identifies which feature", "", "Counts: detected / samples where the method applies. "
              "— = not designed for this feature.", "", "| Feature | " + " | ".join(SCANNERS) + " | PDFiD (reference) |",
              "|---|" + "---|" * (len(SCANNERS) + 1)]
    pdfid_ran = not env["pdfid"].startswith("not available")
    for f, methods in comp["detection"].items():
        row = [("—" if not m["designed"] else "not run" if n == REFERENCE and not pdfid_ran else f"{m['detected']}/{m['expected']}")
               for n, m in methods.items()]
        lines.append(f"| {f} | " + " | ".join(row) + " |")
    lines += ["", "## Comparisons", "",
              f"1. **YARA-X vs PDF Analysis** (PDF samples), disagreements: {comp['yara_vs_pdf_disagreements'] or 'none'}",
              f"2. **YARA-X vs Office Analysis**: see the office-* rows above.",
              f"3. **Detected only by the custom scanner**: {comp['detected_only_by_custom'] or 'none'}",
              f"4. **Clean vs indicator-bearing**: {json.dumps(comp['clean_vs_indicator'])}",
              f"- Negative controls with non-INFO findings (false-positive candidates): {comp['false_positive_candidates'] or 'none'}",
              f"- Detections of features not expected: {comp['unexpected_feature_detections'] or 'none'}",
              f"- Incomplete scans or coverage limits: {comp['incomplete'] or 'none'}",
              f"- Non-deterministic results across trials: {comp['nondeterministic'] or 'none'}", "",
              "## Timing (ms)", "", "Scanner durations are measured inside the isolated worker; worker total is the "
              "engine's duration_ms (process start, isolation set-up and all scanners); overhead = total − scanners.", "",
              "| Measure | n | median | p95 | max |", "|---|---|---|---|---|"]
    for name, t in times.items():
        if name != "by_file_type" and t:
            lines.append(f"| {name} | {t['n']} | {t['median_ms']} | {t['p95_ms']} | {t['max_ms']} |")
    lines += [f"| worker_total [{t}] | {v['n']} | {v['median_ms']} | {v['p95_ms']} | {v['max_ms']} |"
              for t, v in times["by_file_type"].items() if v]
    lines += ["", "## Limits of this study", "",
              "- Synthetic and test-file inputs only; no claim about real-world malware detection rates.",
              "- EICAR is an agreed anti-malware test string, not a document: no FilesMagic scanner has an EICAR rule, "
              "and PDF/Office analysis do not apply to it. Its result is recorded as it is.",
              "- PDFiD runs outside FilesMagic's isolated worker, as an independent reference on the PDF samples only."]
    return "\n".join(lines) + "\n"


def write(out: Path, results, comp, times, env, status) -> None:
    (out / "results.json").write_text(json.dumps({"run_status": status, "environment": env, "samples": results},
                                                 indent=2), encoding="utf-8")
    with (out / "per_sample.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sample_id", "source", "file_type", "ground_truth", "expected", "verdict", "complete", "failure_reason",
                    "deterministic"] + [f"{n}_{c}" for n in SCANNERS for c in ("status", "rules", "median_ms")]
                   + ["worker_median_ms", "worker_p95_ms", "pdfid_keywords"])
        for r in results:
            wt = latency(values(r["timing_ms"]["worker_total"])) or {}
            w.writerow([r["sample_id"], r["source"], r["file_type"], r["ground_truth"], ";".join(r["expected"]),
                        r["verdict"], r["complete"], r["failure_reason"], r["deterministic"]]
                       + [v for n in SCANNERS for v in (r["scanners"][n]["status"], ";".join(r["scanners"][n]["rule_ids"]),
                                                        (latency(values(r["scanners"][n]["duration_ms"])) or {}).get("median_ms", ""))]
                       + [wt.get("median_ms", ""), wt.get("p95_ms", ""),
                          ";".join(f"{k}={v['count']}/{v['hexcodecount']}" for k, v in (r.get("pdfid") or {}).get("keywords", {}).items())])
    with (out / "features.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sample_id", "source", "feature", "expected"] + SCANNERS + [REFERENCE])
        for r in results:
            for feat, cells in r["features"].items():
                w.writerow([r["sample_id"], r["source"], feat, feat in r["expected"]] + [cells[n] for n in SCANNERS]
                           + [r.get("pdfid_features", {}).get(feat, "")])
    with (out / "timings.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sample_id", "trial", "harness_wall_ms", "worker_total_ms", "worker_overhead_ms"] + [f"{n}_ms" for n in SCANNERS])
        for r in results:
            t = r["timing_ms"]
            for i in range(len(t["worker_total"])):
                w.writerow([r["sample_id"], i + 1, t["harness_wall"][i], t["worker_total"][i], t["worker_overhead"][i]]
                           + [r["scanners"][n]["duration_ms"][i] for n in SCANNERS])
    (out / "summary.json").write_text(json.dumps({"run_status": status, "environment": env, "comparisons": comp,
                                                  "timing": times}, indent=2, default=list), encoding="utf-8")
    (out / "report.md").write_text(report(results, comp, times, env, status), encoding="utf-8")
    write_status(out, status)


def run(manifest: Path, samples_root: Path, out: Path, trials: int = 5, acquired: Path | None = None,
        expect_commit: str | None = None, client=None, key=None, require_isolation: bool = True) -> dict:
    """require_isolation=False exists only for functional tests; such output is marked invalid."""
    out.mkdir(parents=True, exist_ok=True)
    env = environment(None)  # the manifest is hashed only after the research checks, below
    env.update(host_network=host_network(), dependency_drift=dependency_drift(), trials=trials)
    status = {"status": "completed", "strict_isolation_required": require_isolation, "preflight": {}, "trials": trials}
    if client is None:
        client, key = make_client()
    if require_isolation:  # before the manifest or any sample is read
        if problems := research_checks(env, expect_commit):
            status.update(status="aborted_environment", reason=problems)
            write_status(out, status)
            raise EvaluationAborted("; ".join(problems), status)
        try:
            status["preflight"] = strict_preflight(client, key)
        except EvaluationAborted as e:
            status.update(status="aborted_preflight", reason=e.args[0], preflight=e.args[1])
            write_status(out, status)
            raise
    rows = load_manifest(manifest, samples_root)
    env["manifest_sha256"] = sha256_of(manifest)
    results, status["status"], status["not_run"] = scan(rows, trials, client, key, require_isolation)
    with tempfile.TemporaryDirectory() as tmp:
        tools = pdfid_tools(acquired, Path(tmp))
        env["pdfid"] = "pdfid.py 0.2.10 (DidierStevensSuite@7d625d0)" if tools else "not available (no verified cache)"
        paths = {r["sample_id"]: r["_path"] for r in rows}
        for r in results:
            if tools and r["file_type"] == "pdf":
                r["pdfid"] = pdfid_reference(tools, paths[r["sample_id"]])
                r["pdfid_features"] = pdfid_features(r["pdfid"])
    comp, times = comparisons(results), timing(results)
    write(out, results, comp, times, env, status)
    if status["status"] != "completed":
        raise EvaluationAborted("required isolation was lost during the run; scanning stopped", status)
    return {"comparisons": comp, "timing": times}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--samples-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--acquired", type=Path, help="verified acquisition cache, for the PDFiD reference")
    parser.add_argument("--expect-commit", help="abort unless this commit is checked out (clean tree)")
    args = parser.parse_args(argv)
    try:
        run(args.manifest, args.samples_root, args.out, args.trials, args.acquired, args.expect_commit)
    except ManifestError as e:
        print(e, file=sys.stderr)
        return 2
    except (EvaluationAborted, prepare_samples.PreparationError) as e:
        print(f"Benchmark aborted: {e.args[0]}. See {args.out / 'run_status.json'}.", file=sys.stderr)
        return 3
    print(f"Wrote {args.out}: report.md, results.json, per_sample.csv, features.csv, timings.csv, summary.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
