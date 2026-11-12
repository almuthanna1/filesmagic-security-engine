"""Dependency regression: the same code tree scanned under two Python environments.

A dependency upgrade (here pypdf) must not change what the engine reports. This scans every sample
of the C2PA accuracy study (evaluation.c2pa_accuracy.samples: its own corpus plus the whole PDF
accuracy corpus, the benign corpus and evaluation.cases) with both engines, once with each
interpreter, through evaluation.pdf_accuracy's worker subprocess, and compares per sample and
engine: the verdict, every finding (scanner, rule, severity, description, evidence), every
scanner's status, and determinism across trials.

    python -m evaluation.dependency_regression --before-python <venv>/python --after-python <venv>/python \
        --public <download dir> --local dev.json --local heldout.json --trials 3 --out <dir>

Writes results.json (full findings: keep it local, it quotes private documents) and summary.md /
summary.json (sample IDs, rule IDs and counts only).
"""

import argparse
import json
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from evaluation import c2pa_accuracy, pdf_accuracy

ROOT = Path(__file__).resolve().parents[1]
ENGINES = ("reference", "unified")


def scan(python: str, paths: list[str], trials: int) -> list[dict]:
    done = subprocess.run([python, "-B", "-c", pdf_accuracy.SCAN, str(trials)], cwd=ROOT, input=json.dumps(paths),
                          capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def version(python: str, package: str) -> str:
    code = f"from importlib.metadata import version; print(version({package!r}))"
    return subprocess.run([python, "-c", code], capture_output=True, text=True, check=True).stdout.strip()


def compare(before: dict, after: dict) -> list[str]:
    """What differs for one sample and engine, by kind: empty when identical."""
    kinds = []
    if before["verdict"] != after["verdict"]:
        kinds.append("verdict")
    rules = lambda r: sorted((f[0], f[1], f[2]) for f in r["findings"])
    if rules(before) != rules(after):
        kinds.append("rules")
    elif sorted(map(json.dumps, before["findings"])) != sorted(map(json.dumps, after["findings"])):
        kinds.append("description or evidence")
    if before["status"] != after["status"]:
        kinds.append("scanner status")
    if not (before["deterministic"] and after["deterministic"]):
        kinds.append("not deterministic")
    return kinds


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--before-python", required=True)
    parser.add_argument("--after-python", required=True)
    parser.add_argument("--public", type=Path, required=True, help="download directory of c2pa_corpus.json")
    parser.add_argument("--local", type=Path, action="append", default=[], help="JSON list of {id, path}")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    pythons = {"before": args.before_python, "after": args.after_python}
    with tempfile.TemporaryDirectory() as tmp:
        rows = c2pa_accuracy.samples(args.local, args.public, Path(tmp))
        paths = [r["path"] for r in rows]
        for tag, python in pythons.items():
            for r, result in zip(rows, scan(python, paths, args.trials)):
                r[tag] = result
    env = {"platform": platform.platform(), "trials": args.trials,
           "commit": pdf_accuracy.git(ROOT, "rev-parse", "HEAD"),
           "dirty": bool(pdf_accuracy.git(ROOT, "status", "--porcelain")),
           **{tag: {"python": subprocess.run([p, "-c", "import sys; print(sys.version.split()[0])"],
                                              capture_output=True, text=True).stdout.strip(),
                    "packages": {k: version(p, k) for k in ("pypdf", "yara-x", "oletools", "cryptography")}}
              for tag, p in pythons.items()}}
    changes = []
    for r in rows:
        for engine in ENGINES:
            kinds = compare(r["before"][engine], r["after"][engine])
            if kinds:
                changes.append({"id": r["id"], "split": r["split"], "engine": engine, "kinds": kinds,
                                "verdict": [r["before"][engine]["verdict"], r["after"][engine]["verdict"]],
                                "rules": [pdf_accuracy.rules(r["before"][engine]),
                                          pdf_accuracy.rules(r["after"][engine])]})
    wall = {tag: {e: sum(min(r[tag][e]["wall_ms"]) for r in rows) for e in ENGINES} for tag in pythons}
    summary = {"environment": env, "samples": len(rows), "comparisons": len(rows) * len(ENGINES),
               "changed": len(changes), "changes": changes, "total_min_wall_ms": wall}
    args.out.mkdir(parents=True, exist_ok=True)
    for r in rows:
        r.pop("path")
    (args.out / "results.json").write_text(json.dumps({"environment": env, "rows": rows}, indent=1))
    (args.out / "summary.json").write_text(json.dumps(summary, indent=1))
    b, a = env["before"]["packages"]["pypdf"], env["after"]["packages"]["pypdf"]
    lines = [f"# Dependency regression: pypdf {b} -> {a}", "",
             f"Commit `{env['commit'][:12]}` (dirty: {env['dirty']}), {env['platform']}, Python "
             f"{env['before']['python']} / {env['after']['python']}, {args.trials} trials per scan.", "",
             f"**{len(changes)} of {summary['comparisons']} sample-engine results differ** "
             f"({len(rows)} samples x {len(ENGINES)} engines).", ""]
    if changes:
        lines += ["| sample | split | engine | what differs | verdict | rules before -> after |", "|---|---|---|---|---|---|"]
        lines += [f"| {c['id']} | {c['split']} | {c['engine']} | {', '.join(c['kinds'])} | {' -> '.join(c['verdict'])} | "
                  f"{', '.join(c['rules'][0]) or '-'} -> {', '.join(c['rules'][1]) or '-'} |" for c in changes]
    lines += ["", "Sum of each sample's fastest trial (ms): " + "; ".join(
        f"{tag} {', '.join(f'{e} {round(v)}' for e, v in w.items())}" for tag, w in wall.items())]
    (args.out / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 1 if changes else 0


if __name__ == "__main__":
    sys.exit(main())
