"""Combined-build accuracy regression: one candidate tree against baseline trees, each scanned with
its OWN Python environment, over the 252-sample corpus of the C2PA accuracy study
(evaluation.c2pa_accuracy.samples: public C2PA corpus, PDF accuracy corpus, benign corpus,
synthetic constructions and evaluation.cases). Every sample is benign or an inert synthetic
construction; there is no malware in this corpus.

    python -m evaluation.combined_regression --public <c2pa downloads> --local dev.json --local heldout.json \
        --tree candidate=<tree>=<python> --tree 90718ff=<tree>=<python> --tree 840a300=<tree>=<python> \
        --trials 3 --out <dir>

The first --tree is the candidate. Verdicts are computed exactly as /scan does, INCLUDING the
unified engine's coverage gate (evaluation.cases.verdicts ignores coverage, so it understates
UNABLE_TO_SCAN on builds since PR #21). Each scan runs in a fresh worker process (worker.run).
A second pass scans each sample once in a fresh process per sample for the candidate's unified
engine and records that process's peak memory.

Writes results.json (full findings: keep it local, it quotes private documents) and
summary.json / summary.md (sample IDs, rule IDs, codes and counts only).
"""

import argparse
import json
import platform
import statistics
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from evaluation import c2pa_accuracy, pdf_accuracy
from evaluation.pdf_accuracy import BENIGN, REQUIRED, outcome, rules

ROOT = Path(__file__).resolve().parents[1]
ENGINES = ("reference", "unified")
RANK = {"SAFE": 0, "UNABLE_TO_SCAN": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}
POSITIVE = {c for c, v in REQUIRED.items() if v != "SAFE"}
NEGATIVE = BENIGN | {c for c, v in REQUIRED.items() if v == "SAFE"}
FROZEN = ROOT / "docs" / "evidence" / "custom-engine-fp-fixes"

# Runs inside each tree (cwd), so it must work on trees before and after PR #21 and this contract.
SCAN = r"""
import asyncio, json, sys, time
from app import worker
from app.decision import decide
try:
    from app.decision import classify
except ImportError:
    classify = None
trials, rows = int(sys.argv[1]), []

def api_verdict(report, engine):
    applicable = sum(s.status != "not_applicable" for s in report.scanners)
    failed = sum(s.status == "failed" for s in report.scanners)
    coverage = getattr(report, "coverage_complete", True) if engine == "unified" else True
    try:
        verdict = decide(report.findings, scanners_run=applicable, scanners_failed=failed, coverage_complete=coverage)
    except TypeError:  # trees before PR #21
        verdict = decide(report.findings, scanners_run=applicable, scanners_failed=failed)
    return verdict, coverage, applicable

for path in json.load(sys.stdin):
    data, row = open(path, "rb").read(), {}
    for engine in ("reference", "unified"):
        runs, errors = [], []
        for _ in range(trials):
            start = time.perf_counter()
            try:
                report = asyncio.run(worker.run(data, engine=engine))
            except worker.WorkerError as e:
                errors.append(getattr(e, "code", "WORKER_FAILED"))
                continue
            runs.append(((time.perf_counter() - start) * 1000, report))
        if not runs:
            row[engine] = {"verdict": "UNABLE_TO_SCAN", "worker_errors": errors, "coverage_complete": False,
                           "coverage_codes": [], "status": {}, "failures": [], "findings": [],
                           "deterministic": False, "wall_ms": []}
            continue
        first = runs[0][1]
        verdict, coverage, applicable = api_verdict(first, engine)
        key = lambda r: (api_verdict(r, engine)[0].value,
                         sorted((f.scanner, f.rule_id, f.severity.value, f.description) for f in r.findings))
        issues = list(getattr(first, "coverage_issues", [])) if engine == "unified" else []
        out = {"verdict": verdict.value, "worker_errors": errors, "coverage_complete": coverage,
               "coverage_codes": sorted({i.code for i in issues}),
               "status": {s.name: s.status for s in first.scanners},
               "failures": [[s.name, s.error_kind] for s in first.scanners if s.status == "failed"],
               "findings": [[f.scanner, f.rule_id, f.severity.value, f.description, list(f.evidence)]
                            for f in first.findings],
               "deterministic": not errors and all(key(r) == key(first) for _, r in runs),
               "wall_ms": [round(w, 2) for w, _ in runs]}
        if classify and engine == "unified":  # as /scan would answer on a host with verified isolation
            reasons, authorization, _ = classify(verdict, first.scanners, issues,
                                                 [] if applicable else ["UNSUPPORTED_FILE_TYPE"])
            out["authorization"], out["reasons"] = authorization, [r.code for r in reasons]
        row[engine] = out
    rows.append(row)
json.dump(rows, sys.stdout)
"""

# One sample, in-process, in a fresh interpreter: the work a unified worker does (analyse + correlate).
MEMORY = r"""
import json, os, sys
from app import worker
from app.engine import SCANNERS, correlate

def peak():
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        class PMC(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (n, ctypes.c_size_t) for n in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage",
                "PeakPagefileUsage", "PrivateUsage")]
        c = PMC(cb=ctypes.sizeof(PMC))
        k32 = ctypes.WinDLL("kernel32")  # declared types: an undeclared HANDLE is truncated to 32 bits on x64
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        k32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
        if not k32.K32GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(c), c.cb):
            raise OSError("GetProcessMemoryInfo failed")
        return {"peak_working_set_mib": c.PeakWorkingSetSize / 2**20, "peak_private_mib": c.PeakPagefileUsage / 2**20}
    import resource
    return {"peak_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024}

for s in SCANNERS:  # the worker's warm-up
    try:
        s.scan("", b"")
    except Exception:
        pass
loaded = peak()
correlate(worker.analyse(SCANNERS, open(sys.argv[1], "rb").read()))
print(json.dumps({"loaded": loaded, "after": peak()}))
"""


def scan(tree: Path, python: str, paths: list[str], trials: int) -> list[dict]:
    done = subprocess.run([python, "-B", "-c", SCAN, str(trials)], cwd=tree, input=json.dumps(paths),
                          capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def memory(tree: Path, python: str, path: str) -> dict:
    done = subprocess.run([python, "-B", "-c", MEMORY, path], cwd=tree, capture_output=True, text=True, check=True)
    return json.loads(done.stdout.strip().splitlines()[-1])


def expected_case_verdicts() -> dict[str, str]:
    """The unified verdict each evaluation case is expected to keep (frozen matrix + field cases)."""
    frozen = json.loads((FROZEN / "unified" / "results.json").read_text())["results"]
    out = {r["id"]: r["verdicts"]["aggregate"] for r in frozen}
    out.update({c["id"]: c["expected"]["unified"][0] for c in pdf_accuracy.field_cases()})
    return out


def binary(rows: list[dict], tag: str, flagged: set[str]) -> dict:
    tp = fp = tn = fn = 0
    for r in rows:
        hit = r[tag]["unified"]["verdict"] in flagged
        if r["cls"] in POSITIVE:
            tp, fn = tp + hit, fn + (not hit)
        elif r["cls"] in NEGATIVE:
            fp, tn = fp + hit, tn + (not hit)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else None
    rnd = lambda x: None if x is None else round(x, 4)  # noqa: E731
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "precision": rnd(precision), "recall": rnd(recall),
            "f1": rnd(f1), "false_positive_rate": rnd(fp / (fp + tn) if fp + tn else None)}


def pct(values: list[float], q: float) -> float:
    s = sorted(values)
    return round(s[min(len(s) - 1, max(0, round(q * len(s) + 0.5) - 1))], 1)  # nearest-rank


def measure(rows: list[dict], tag: str, cases: dict[str, str]) -> dict:
    u = [r[tag]["unified"] for r in rows]
    walls = [statistics.median(x["wall_ms"]) for x in u if x["wall_ms"]]
    out = {
        "samples": len(rows),
        "verdicts": {e: dict(Counter(r[tag][e]["verdict"] for r in rows)) for e in ENGINES},
        "by_class": {c: dict(Counter(r[tag]["unified"]["verdict"] for r in rows if r["cls"] == c))
                     for c in sorted({r["cls"] for r in rows})},
        "detection (SUSPICIOUS or MALICIOUS)": binary(rows, tag, {"SUSPICIOUS", "MALICIOUS"}),
        "gate (anything but SAFE stops automatic conversion)": binary(rows, tag, {"SUSPICIOUS", "MALICIOUS", "UNABLE_TO_SCAN"}),
        "outcomes": dict(Counter(outcome(r["cls"], r[tag]["unified"]["verdict"]) for r in rows if r["cls"] != "case")),
        "case_mismatches": [{"id": r["id"], "expected": cases.get(r["id"]), "got": r[tag]["unified"]["verdict"]}
                            for r in rows if r["cls"] == "case" and cases.get(r["id"]) != r[tag]["unified"]["verdict"]],
        "scanner_failures": sorted({(r["id"], n, k or "-") for r in rows for n, k in r[tag]["unified"]["failures"]}),
        "worker_errors": sorted({(r["id"], c) for r in rows for c in r[tag]["unified"]["worker_errors"]}),
        "incomplete_coverage": {"samples": sum(not x["coverage_complete"] for x in u),
                                "codes": dict(Counter(c for x in u for c in x["coverage_codes"]))},
        "not_deterministic": [r["id"] for r in rows if not (r[tag]["unified"]["deterministic"]
                                                            and r[tag]["reference"]["deterministic"])],
        "unified_latency_ms (per-sample median of trials, incl. worker start)": {
            "median": round(statistics.median(walls), 1), "p95": pct(walls, 0.95), "max": round(max(walls), 1)},
    }
    if "authorization" in u[0]:
        out["authorization"] = {c: dict(Counter(r[tag]["unified"]["authorization"] for r in rows if r["cls"] == c))
                                for c in sorted({r["cls"] for r in rows})}
        out["reason_codes"] = dict(Counter(code for x in u for code in x["reasons"]))
        out["malicious_not_denied"] = [r["id"] for r in rows if r[tag]["unified"]["verdict"] == "MALICIOUS"
                                       and r[tag]["unified"]["authorization"] != "deny"]
    return out


def compare(rows: list[dict], base: str, cand: str) -> dict:
    changes = [{"id": r["id"], "class": r["cls"], "engine": e, "before": r[base][e]["verdict"],
                "after": r[cand][e]["verdict"],
                "removed": sorted(set(rules(r[base][e])) - set(rules(r[cand][e]))),
                "added": sorted(set(rules(r[cand][e])) - set(rules(r[base][e])))}
               for r in rows for e in ENGINES
               if r[base][e]["verdict"] != r[cand][e]["verdict"] or rules(r[base][e]) != rules(r[cand][e])]
    weaker = [c for c in changes if c["engine"] == "unified" and RANK[c["after"]] < RANK[c["before"]]]
    return {"changed": changes, "unified_weaker_verdicts": weaker,
            "flagged_now_safe": [c for c in weaker if c["after"] == "SAFE"]}


def markdown(summary: dict) -> str:
    lines = [f"# Combined-build accuracy regression", "",
             f"{summary['environment']['platform']}, {summary['environment']['trials']} trials per scan. "
             "Every sample is benign or an inert synthetic construction (no malware).", ""]
    for name, tree in summary["trees"].items():
        lines.append(f"- **{name}**: `{tree['commit'][:12]}` (dirty: {tree['dirty']}), pypdf {tree['pypdf']}")
    lines += ["", "| Measure | " + " | ".join(summary["trees"]) + " |", "|---|" + "---|" * len(summary["trees"])]
    m = summary["measures"]
    row = lambda label, f: lines.append(f"| {label} | " + " | ".join(str(f(m[t])) for t in summary["trees"]) + " |")  # noqa: E731
    row("Samples", lambda x: x["samples"])
    for v in RANK:
        row(f"Unified {v}", lambda x, v=v: x["verdicts"]["unified"].get(v, 0))
    for view in ("detection (SUSPICIOUS or MALICIOUS)", "gate (anything but SAFE stops automatic conversion)"):
        for k in ("TP", "FP", "TN", "FN", "precision", "recall", "f1", "false_positive_rate"):
            row(f"{view.split(' ')[0]} {k}", lambda x, k=k, view=view: x[view][k])
    row("Scanner failures (sample, scanner)", lambda x: len(x["scanner_failures"]))
    row("Worker errors", lambda x: len(x["worker_errors"]))
    row("Incomplete coverage (samples)", lambda x: x["incomplete_coverage"]["samples"])
    row("Case mismatches vs frozen", lambda x: len(x["case_mismatches"]))
    row("Not deterministic", lambda x: len(x["not_deterministic"]))
    for k in ("median", "p95", "max"):
        row(f"Unified latency {k} (ms)", lambda x, k=k: x["unified_latency_ms (per-sample median of trials, incl. worker start)"][k])
    for name, c in summary["comparisons"].items():
        lines += ["", f"## {name}", "", f"- changed sample-engine results: {len(c['changed'])}",
                  f"- unified verdicts weaker than the baseline: {len(c['unified_weaker_verdicts'])}",
                  f"- flagged by the baseline, SAFE now: {len(c['flagged_now_safe'])}", ""]
        lines += [f"  - `{x['id']}` ({x['class']}, {x['engine']}): {x['before']} -> {x['after']}; "
                  f"removed {x['removed'] or '-'}; added {x['added'] or '-'}" for x in c["changed"]]
    if "memory" in summary:
        mem = summary["memory"]
        lines += ["", "## Peak memory, candidate unified engine (one fresh process per sample)", "",
                  f"- after loading scanners: {mem['loaded_max']}",
                  f"- peak over the corpus: {mem['peak']} (sample `{mem['peak_sample']}`)",
                  f"- median per sample: {mem['median']}"]
    return "\n".join(lines) + "\n"


def memory_summary(rows: list[dict], mem: list[dict]) -> dict:
    key = "peak_working_set_mib" if "peak_working_set_mib" in mem[0]["after"] else "peak_rss_mib"
    peaks = [m["after"][key] for m in mem]
    top = max(range(len(peaks)), key=peaks.__getitem__)
    return {"measure": key, "loaded_max": round(max(m["loaded"][key] for m in mem), 1),
            "peak": round(peaks[top], 1), "peak_sample": rows[top]["id"], "median": round(statistics.median(peaks), 1),
            "peak_private_mib": round(max(m["after"].get("peak_private_mib", 0) for m in mem), 1)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--local", type=Path, action="append", default=[])
    parser.add_argument("--tree", action="append", required=True, help="name=tree=python; the first is the candidate")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--no-memory", action="store_true")
    parser.add_argument("--memory-only", action="store_true", help="only the memory pass (first --tree); writes memory.json")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    trees = [(n, Path(t), p) for n, t, p in (x.split("=", 2) for x in args.tree)]
    cand = trees[0][0]
    with tempfile.TemporaryDirectory() as tmp:
        rows = c2pa_accuracy.samples(args.local, args.public, Path(tmp))
        paths = [r["path"] for r in rows]
        if args.memory_only:
            mem = [memory(trees[0][1], trees[0][2], p) for p in paths]
            args.out.mkdir(parents=True, exist_ok=True)
            out = {"tree": {"commit": pdf_accuracy.git(trees[0][1], "rev-parse", "HEAD"), "platform": platform.platform()},
                   **memory_summary(rows, mem), "samples": {r["id"]: m for r, m in zip(rows, mem)}}
            (args.out / "memory.json").write_text(json.dumps(out, indent=1))
            print(json.dumps({k: v for k, v in out.items() if k != "samples"}, indent=1))
            return 0
        for name, tree, python in trees:
            for r, result in zip(rows, scan(tree, python, paths, args.trials)):
                r[name] = result
        mem = None if args.no_memory else [memory(trees[0][1], trees[0][2], p) for p in paths]
    pkg = lambda py: subprocess.run([py, "-c", "from importlib.metadata import version; print(version('pypdf'))"],  # noqa: E731
                                    capture_output=True, text=True).stdout.strip()
    cases = expected_case_verdicts()
    summary = {
        "environment": {"platform": platform.platform(), "trials": args.trials},
        "trees": {n: {"commit": pdf_accuracy.git(t, "rev-parse", "HEAD"),
                      "dirty": bool(pdf_accuracy.git(t, "status", "--porcelain", "--untracked-files=no")),
                      "pypdf": pkg(p)} for n, t, p in trees},
        "measures": {n: measure(rows, n, cases) for n, _, _ in trees},
        "comparisons": {f"{base} -> {cand}": compare(rows, base, cand) for base, _, _ in trees[1:]},
    }
    if mem:
        summary["memory"] = memory_summary(rows, mem)
        for r, m in zip(rows, mem):
            r["memory"] = m
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps([{k: v for k, v in r.items() if k != "path"} for r in rows], indent=1))
    (args.out / "summary.json").write_text(json.dumps(summary, indent=1))
    (args.out / "summary.md").write_text(markdown(summary), encoding="utf-8")
    print(markdown(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
