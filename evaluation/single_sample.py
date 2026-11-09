"""Single-sample offline evaluation: one local, already-authorized file through both engines, compared
with its pre-registered expectations (docs/offline-results-viewer-plan.md).

    cd ~/filesmagic-security-engine
    SECURITY_ENGINE_REQUIRE_ISOLATION=1 /opt/filesmagic/venv/bin/python -B -m evaluation.single_sample \\
        --sample ~/fm-eval/samples/malicious/<id>.bin --sha256 <64 hex> \\
        --expectations evaluation/expectations/<id>.json --expect-commit <sha> --trials 5 \\
        --out ~/fm-eval/results/single-<id>-<sha7>

It stops (exit 3, run_status.json) before reading the sample unless every gate of
evaluation.offline_validation holds (strict isolation configured; AppArmor filesmagic-eval-python
in enforce mode; no usable route; expected commit, clean tree; packages = requirements.txt) and
app/ and requirements.txt are the frozen release's (by git object ID, so no tag is needed in the
VM). The expectations must be committed and name the same SHA-256 as --sha256. The sample is read
once, by this confined process, into memory (regular file, no symlink, at most the upload limit) and
its SHA-256 checked before any scan; it is never copied, renamed or written anywhere.

Each engine then gets a preflight (empty input) and N trials in fresh isolated workers
(evaluation.cases.scan_case, as offline_validation). A missing isolation control or a worker that
ran another engine's scanners stops the run; a worker error is recorded (defect D3) and the other
engine still runs.

Output (metadata only: no sample bytes, finding text redacted by redact()): results.json,
report.html (no JavaScript, no external resources), run_status.json, SHA256SUMS. The expectations
file is read, never written; actual results go only to --out.

`--write-inert DIR` writes the inert validation fixtures (evaluation/expectations/inert-*.json).
"""

import argparse
import hashlib
import html
import json
import re
import subprocess
import sys
from pathlib import Path

from app import main, worker
from evaluation import cases as synthetic
from evaluation import offline_validation as ov
from evaluation.benchmark import dependency_drift, host_network
from evaluation.evaluate import environment

REPO = Path(__file__).resolve().parent.parent
ENGINES = ov.ENGINES
# custom-engine-freeze-2026-11-09 (2d586f6): `git rev-parse <tag>:app <tag>:requirements.txt`
FROZEN = {"app": "c50b66c1eca593f17926f81d7d55dff6f9474c40", "requirements.txt": "5089f11d0ab103614d999bd51fa9bfe0a1b3e76e"}
MAX_BYTES = main.MAX_UPLOAD_BYTES
RANK = {"SAFE": 0, "UNABLE_TO_SCAN": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}  # UNABLE_TO_SCAN still blocks the file

# ----------------------------------------------------------------------------- redaction

# Finding text can quote the document (procedure names, targets, field instructions). Everything
# after "Evidence:"/"Entries:", every quoted literal, URL, UNC/file path and IPv4 address is replaced
# by its length and a short hash, so results can be matched without exposing the indicator.
_TAIL = re.compile(r"(?:Evidence|Entries):.*", re.S)
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
_INDICATOR = re.compile(r"[a-z][a-z0-9+.-]*://\S+|\\\\\S+|\bfile:\S*|\bwww\.\S+|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.I)
MAX_TEXT = 300


def _withheld(m: re.Match) -> str:
    return f"[withheld {len(m.group())} chars sha256:{hashlib.sha256(m.group().encode()).hexdigest()[:12]}]"


def redact(text: str) -> str:
    text = _INDICATOR.sub(_withheld, _QUOTED.sub(_withheld, _TAIL.sub(_withheld, text)))
    text = re.sub(r"[\x00-\x1f\x7f]", "?", text)
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 1] + "…"


# ----------------------------------------------------------------------------- gates


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True, timeout=30).stdout.strip()


def frozen_problems() -> list[str]:
    """app/ and requirements.txt must be the frozen release's (the clean-tree gate covers the files)."""
    return [f"{path} differs from the frozen release" for path, oid in FROZEN.items() if git("rev-parse", f"HEAD:{path}") != oid]


def tracked(path: Path) -> bool:
    try:
        relative = path.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return False
    return git("ls-files", "--", relative) == relative


def collect_env() -> dict:
    return environment(None) | {"host_network": host_network(), "dependency_drift": dependency_drift(),
                                "confinement": ov.confinement(), "worker_command": worker.command()[3:],
                                "engine_ruleset_sha256": main.VERSIONS.get("engine_ruleset_sha256")}


def read_sample(path: Path, sha256: str) -> tuple[bytes | None, str]:
    """(the bytes, "") or (None, why). Read once; never a symlink, a directory or over the upload limit."""
    if path.is_symlink() or not path.is_file():
        return None, f"{path.name} is not a regular file"
    if path.stat().st_size > MAX_BYTES:
        return None, f"{path.name} is larger than the {MAX_BYTES} byte upload limit"
    data = path.read_bytes()
    observed = hashlib.sha256(data).hexdigest()
    return (data, "") if observed == sha256 else (None, f"{path.name}: SHA-256 {observed} is not the expected {sha256}")


# ----------------------------------------------------------------------------- scanning


def scan(item: dict, engine: str, trials: int) -> dict:
    try:
        r = synthetic.scan_case(item, trials, worker.command() + worker.ENGINE_ARGS[engine])
    except worker.WorkerError as e:  # no report came back: crash, timeout or oversized output
        return {"engine": engine, "id": item["id"], "worker_error": redact(f"{type(e).__name__}: {e}")}
    for f in r["findings"]:
        f["description"] = redact(f["description"])
    return {"engine": engine, **r}


def rules(r: dict) -> set[str]:
    return {f"{f['scanner']}:{f['rule_id']}:{f['severity']}" for f in r.get("findings", [])}


def assess(results: list[dict], exp: dict) -> dict:
    """Each pre-registered prediction (held or not) and the acceptance outcome of the pre-registration."""
    by = {r["engine"]: r for r in results}
    checks, defects = [], []

    def check(engine: str, what: str, held: bool, detail: str = "") -> None:
        checks.append({"engine": engine, "prediction": what, "held": held, "observed": detail})

    for engine, want in exp["engines"].items():
        r = by.get(engine, {})
        if r.get("worker_error"):
            check(engine, f"verdict {want['verdict']}", False, r["worker_error"])
            continue
        got, verdict = rules(r), r["verdicts"]["aggregate"]
        check(engine, f"verdict {want['verdict']}", verdict == want["verdict"], verdict)
        for rule in want.get("rules", []):
            check(engine, f"finding {rule}", rule in got, "present" if rule in got else "absent")
        for primary, alternative in want.get("alternatives", []):
            seen = primary if primary in got else alternative if alternative in got else "neither"
            check(engine, f"finding {primary} (alternative {alternative})", seen == primary, seen)
        for name in want.get("not_applicable", []):
            status = r["status"].get(name, "not run")
            check(engine, f"{name} not applicable", status == "not_applicable", status)
        check(engine, "deterministic across trials", r["deterministic"], str(r["deterministic"]))
        check(engine, "strict isolation complete in every trial", not r["isolation_missing"],
              ", ".join(r["isolation_missing"]) or "complete")
        if "max_wall_ms" in exp:
            slowest = r["timing_ms"]["harness_wall"]["max_ms"]
            check(engine, f"slowest trial below {exp['max_wall_ms']} ms", slowest < exp["max_wall_ms"], f"{slowest} ms")

    ok = {e: r for e, r in by.items() if not r.get("worker_error")}
    verdicts = {e: r["verdicts"]["aggregate"] for e, r in ok.items()}
    failed = {e: sorted(n for n, s in r["status"].items() if s == "failed") for e, r in ok.items()}
    defects += [f"D3 robustness: {e} worker error ({r['worker_error']})" for e, r in by.items() if r.get("worker_error")]
    defects += [f"D4 non-determinism: {e}" for e, r in ok.items() if not r["deterministic"]]
    if exp["ground_truth"] == "MALICIOUS":
        if {"reference", "unified"} <= verdicts.keys() and RANK[verdicts["unified"]] < RANK[verdicts["reference"]]:
            defects.append(f"D1 safety regression: unified {verdicts['unified']} is lower than reference "
                           f"{verdicts['reference']}")
        defects += [f"D5 coverage gap: {e} SAFE on a malicious sample" for e, v in verdicts.items() if v == "SAFE"]

    objective = exp.get("objective")
    objective_held = {e: all(x in rules(r) for x in objective["all_of"]) and any(x in rules(r) for x in objective["any_of"])
                      for e, r in ok.items()} if objective else {}
    expected = {e: w["verdict"] for e, w in exp["engines"].items()}
    complete = not exp.get("require_complete") or not any(failed.values())
    if defects:
        outcome = "FAIL"
    elif verdicts == expected and complete and all(objective_held.values()) and all(r["deterministic"] for r in ok.values()):
        outcome = "PASS"
    elif exp["ground_truth"] == "MALICIOUS" and set(verdicts.values()) == {"SUSPICIOUS"}:
        outcome = "PARTIAL"  # detected, not convicted: a documented limitation, not a defect
    else:
        outcome = "NOT AS PREDICTED"
    return {"outcome": outcome, "defects": defects, "checks": checks, "verdicts": verdicts,
            "failed_scanners": failed, "objective_held": objective_held}


# ----------------------------------------------------------------------------- report

CSS = """body{font:15px/1.45 system-ui,sans-serif;margin:24px;max-width:1100px;color:#1a1a1a;background:#fff}
table{border-collapse:collapse;margin:8px 0 20px;width:100%}td,th{border:1px solid #bbb;padding:4px 8px;
text-align:left;vertical-align:top}th{background:#eee}code{font-size:13px}.no{background:#fde2e2}
.yes{background:#e3f4e3}.out{font-size:22px;font-weight:600}"""


def _table(head: list[str], rows: list[list], marks: list[str] | None = None) -> str:
    e = lambda v: html.escape(str(v))  # noqa: E731
    body = "".join(f"<tr{f' class={marks[i]}' if marks and marks[i] else ''}>" + "".join(f"<td>{e(c)}</td>" for c in row)
                   + "</tr>" for i, row in enumerate(rows))
    return "<table><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr>" + body + "</table>"


def report_html(doc: dict) -> str:
    e = lambda v: html.escape(str(v))  # noqa: E731
    s, env, a = doc["sample"], doc["environment"], doc.get("assessment")
    parts = [f"<h1>Single-sample evaluation: {e(s['id'])}</h1>",
             f"<p class=out>Run: {e(doc['run_status']['status'])}" + (f" · Outcome: {e(a['outcome'])}" if a else "") + "</p>"]
    if doc["run_status"].get("problems"):
        parts.append("<h2>Stopped</h2>" + _table(["problem"], [[p] for p in doc["run_status"]["problems"]]))
    parts.append("<h2>Sample and environment</h2>" + _table(["field", "value"], [
        ["SHA-256 expected", s["sha256_expected"]], ["SHA-256 observed", s.get("sha256_observed", "not read")],
        ["size (bytes)", s.get("size_bytes", "")], ["ground truth", doc["expectations"]["ground_truth"]],
        ["pre-registration", f"{doc['expectations'].get('preregistration', '')} sha256:{doc.get('preregistration_sha256')}"],
        ["expectations", f"{doc['expectations_path']} sha256:{doc['expectations_sha256']}"],
        ["commit", env.get("engine_commit")], ["rules / engine rules", f"{env.get('ruleset_sha256')} / {env.get('engine_ruleset_sha256')}"],
        ["AppArmor", env.get("confinement")], ["host network offline", env.get("host_network", {}).get("offline")],
        ["strict isolation configured", env.get("strict_isolation_configured")], ["trials per engine", doc.get("trials")]]))
    if a:
        if a["defects"]:
            parts.append("<h2>Defects</h2>" + _table(["defect"], [[d] for d in a["defects"]]))
        parts.append("<h2>Pre-registered predictions vs actual</h2>" + _table(
            ["engine", "prediction", "held", "observed"],
            [[c["engine"], c["prediction"], "yes" if c["held"] else "no", c["observed"]] for c in a["checks"]],
            ["yes" if c["held"] else "no" for c in a["checks"]]))
    for r in doc.get("results", []):
        parts.append(f"<h2>{e(r['engine'])} engine</h2>")
        if r.get("worker_error"):
            parts.append(f"<p>No report: {e(r['worker_error'])}</p>")
            continue
        t = r["timing_ms"]
        parts.append(_table(["verdict", "deterministic", "isolation missing", "wall median / p95 / max ms"],
                            [[r["verdicts"]["aggregate"], r["deterministic"], ", ".join(r["isolation_missing"]) or "none",
                              f"{t['harness_wall']['median_ms']} / {t['harness_wall']['p95_ms']} / {t['harness_wall']['max_ms']}"]]))
        parts.append(_table(["scanner", "status", "verdict", "median ms"],
                            [[n, st, r["verdicts"].get(n, ""), (t.get(n) or {}).get("median_ms", "")] for n, st in r["status"].items()]))
        parts.append(_table(["scanner", "rule", "severity", "description (redacted)"],
                            [[f["scanner"], f["rule_id"], f["severity"], f["description"]] for f in r["findings"]] or [["", "no findings", "", ""]]))
    return ("<!doctype html><html lang=en><head><meta charset=utf-8>"
            "<meta http-equiv=Content-Security-Policy content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            f"<title>Single-sample evaluation</title><style>{CSS}</style></head><body>{''.join(parts)}</body></html>\n")


def write(out: Path, doc: dict) -> None:
    out.mkdir(parents=True)
    files = {"run_status.json": json.dumps(doc["run_status"], indent=2) + "\n",
             "results.json": json.dumps(doc, indent=2) + "\n", "report.html": report_html(doc)}
    for name, text in files.items():  # bytes, so SHA256SUMS matches on every platform (no newline translation)
        (out / name).write_bytes(text.encode())
    (out / "SHA256SUMS").write_bytes("".join(f"{hashlib.sha256(t.encode()).hexdigest()}  {n}\n"
                                             for n, t in files.items()).encode())


# ----------------------------------------------------------------------------- run


def run(args, env: dict) -> int:
    if args.out.exists():
        print(f"STOPPED: {args.out} exists; results are never overwritten", file=sys.stderr)
        return 3
    exp_text = args.expectations.read_text(encoding="utf-8")
    exp = json.loads(exp_text)
    prereg = REPO / exp["preregistration"] if exp.get("preregistration") else None
    doc = {"sample": {"id": exp["sample_id"], "sha256_expected": args.sha256}, "environment": env, "trials": args.trials,
           "expectations_path": str(args.expectations), "expectations_sha256": hashlib.sha256(exp_text.encode()).hexdigest(),
           "expectations": exp, "preregistration_sha256": hashlib.sha256(prereg.read_bytes()).hexdigest() if prereg else None}
    problems = ov.gates(env, args.expect_commit, frozen_problems())
    if not re.fullmatch(r"[0-9a-f]{64}", args.sha256) or exp["sample_sha256"] != args.sha256:
        problems.append("--sha256 is not the SHA-256 the expectations were registered for")
    problems += [f"{p} is not committed" for p in (args.expectations, prereg) if p and not tracked(p)]
    status, results = {"status": "stopped", "problems": problems}, []
    data = None
    if not problems:
        data, why = read_sample(args.sample, args.sha256)
        problems += [why] if why else []
    if data is not None:
        doc["sample"] |= {"sha256_observed": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
        for engine in ENGINES:  # preflight: empty input, nothing is parsed if isolation is incomplete
            probe = synthetic.scan_case({"id": "preflight", "ground_truth": "-", "indicator": "-", "data": b""}, 1,
                                        worker.command() + worker.ENGINE_ARGS[engine])
            doc.setdefault("preflight", {})[engine] = {"isolation_missing": probe["isolation_missing"], "status": probe["status"]}
            problems += [f"preflight: {why}"] if (why := ov.scan_problem(probe, engine)) else []
    if data is not None and not problems:
        item = {"id": exp["sample_id"], "ground_truth": exp["ground_truth"], "indicator": "single sample", "data": data}
        for engine in ENGINES:
            r = scan(item, engine, args.trials)
            results.append(r)
            if not r.get("worker_error") and (why := ov.scan_problem(r, engine)):
                problems.append(why)  # isolation lost or the wrong engine: not evidence, stop
                break
            print(f"{engine:9} {r.get('worker_error') or r['verdicts']['aggregate']}", flush=True)
        else:
            status["status"] = "completed"
    doc |= {"run_status": status, "results": results}
    if status["status"] == "completed":
        doc["assessment"] = assess(results, exp)
    write(args.out, doc)
    outcome = doc.get("assessment", {}).get("outcome")
    print(f"{status['status']}{f' · {outcome}' if outcome else ''}: {args.out / 'report.html'}")
    for p in problems:
        print(f"STOPPED: {p}", file=sys.stderr)
    return 3 if status["status"] != "completed" else 0 if outcome == "PASS" else 1


# ----------------------------------------------------------------------------- inert fixtures


def inert_fixtures() -> dict[str, bytes]:
    """The inert validation documents (no code, no exploit): see evaluation/expectations/inert-*.json."""
    from tests.office_fixtures import make_ole

    docx = (ov.CORPUS[0] / "docx-01-word-plain.docx").read_bytes()
    return {"inert-ole-vba-storage": make_ole({"WordDocument": b"inert", "Macros/VBA/_VBA_PROJECT": b"inert",
                                               "Macros/VBA/dir": b"inert"}),
            "inert-benign-docx": docx, "inert-truncated-docx": docx[: len(docx) // 2]}


def main_(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--write-inert", type=Path, metavar="DIR", help="write the inert fixtures and exit")
    parser.add_argument("--sample", type=Path)
    parser.add_argument("--sha256")
    parser.add_argument("--expectations", type=Path)
    parser.add_argument("--expect-commit")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if args.write_inert:
        args.write_inert.mkdir(parents=True)
        for name, data in inert_fixtures().items():
            (args.write_inert / f"{name}.bin").write_bytes(data)
            print(f"{hashlib.sha256(data).hexdigest()}  {name}.bin")
        return 0
    missing = [n for n in ("sample", "sha256", "expectations", "expect_commit", "out") if getattr(args, n) is None]
    if missing:
        parser.error("required: " + ", ".join(f"--{n.replace('_', '-')}" for n in missing))
    if args.trials < 1:
        parser.error("--trials must be at least 1")
    return run(args, collect_env())


if __name__ == "__main__":
    raise SystemExit(main_())
