"""VBA case matrix: inert VBA projects through the real isolated worker, current tree and baseline.

    python -m evaluation.vba_cases --out DIR [--baseline-tree PATH] [--trials N]

Every case is a real MS-OVBA project (tests/vba_fixtures.py: compressed source, no P-code) whose
"dangerous" lines carry placeholder arguments only, so nothing could run even if opened in Office.
Each case is scanned by this tree's worker and, with --baseline-tree (a checkout of the
pre-rebuild baseline, e.g. `git worktree add <dir> baseline/pre-custom-rebuild`), by that tree's
worker on the same bytes, so the effect of replacing olevba's heuristics is measured, not assumed.

`expected` is this rebuild's intended verdict; `why` says what the case tests.
"""

import argparse
import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

from app import worker
from app.models import WorkerReport
from evaluation.cases import verdicts
from tests.office_fixtures import make_ole, word_document_stream
from tests.vba_fixtures import docm, vba_streams

SHELL = 'Sub Tool()\n    Shell "placeholder"\nEnd Sub\n'
CASES = [
    ("v01-autoopen-calls-shell", {"Module1": 'Sub AutoOpen()\n    Tool\nEnd Sub\n' + SHELL}, "MALICIOUS",
     "automatic entry reaches Shell through a call"),
    ("v02-qualified-call-to-shell", {"Module1": 'Sub AutoOpen()\n    Module2.Tool\nEnd Sub\n', "Module2": SHELL},
     "MALICIOUS", "Module.Procedure call across modules (module names without olevba's .bas extension)"),
    ("v03-entry-and-unrelated-shell", {"Module1": 'Sub AutoOpen()\n    MsgBox "hello"\nEnd Sub\n' + SHELL},
     "MALICIOUS", "no call path, kept HIGH: P-code may differ from source (never lowered on source alone)"),
    ("v04-benign-formatting", {"Module1": 'Sub FormatTable()\n    ActiveDocument.Tables(1).Style = "Grid"\nEnd Sub\n'},
     "SUSPICIOUS", "harmless macro: macros present is never SAFE"),
    ("v05-vbhide-constant-only", {"Module1": 'Sub Document_Open()\n    style = vbHide\n    MsgBox style\nEnd Sub\n'},
     "SUSPICIOUS", "olevba listed vbHide as execution; a constant is no operation"),
    ("v06-application-run-macro", {"Module1": 'Sub AutoOpen()\n    Application.Run "Helper"\nEnd Sub\n'
                                              'Sub Helper()\n    MsgBox "x"\nEnd Sub\n'},
     "SUSPICIOUS", "olevba listed Run as execution; Application.Run starts a macro"),
    ("v07-shell32-folder-api", {"Module1": 'Private Declare PtrSafe Function GetFolder Lib "shell32" Alias '
                                           '"SHGetFolderPathA" (ByVal h As LongPtr) As Long\n'
                                           'Sub AutoOpen()\n    GetFolder 0\nEnd Sub\n'},
     "SUSPICIOUS", "olevba listed shell32 as execution; the declared API decides"),
    ("v08-user-shell-procedure", {"Module1": 'Sub AutoOpen()\n    Shell "x"\nEnd Sub\nSub Shell(s)\n    MsgBox s\nEnd Sub\n'},
     "SUSPICIOUS", "a user procedure named Shell shadows the built-in: only possible"),
    ("v09-strreverse-progid-run", {"Module1": 'Sub Document_Open()\n    Set o = CreateObject(StrReverse("llehS.tpircSW"))\n'
                                              '    o.Run "placeholder"\nEnd Sub\n'},
     "MALICIOUS", "obfuscated ProgID folded statically, method resolved on the object"),
    ("v10-callbyname-run", {"Module1": 'Sub AutoOpen()\n    CallByName CreateObject("WScript.Shell"), "Run", VbMethod, '
                                       '"placeholder"\nEnd Sub\n'},
     "MALICIOUS", "dynamic method call with a constant name"),
    ("v11-xmlhttp-download", {"Module1": 'Sub Workbook_Open()\n    Set h = CreateObject("MSXML2.XMLHTTP")\n'
                                         '    h.Open "GET", "https://example.test/", False\n    h.Send\nEnd Sub\n'},
     "MALICIOUS", "download on open"),
    ("v12-run-key-persistence", {"Module1": 'Sub AutoOpen()\n    CreateObject("WScript.Shell").RegWrite '
                                            '"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x", "p"\nEnd Sub\n'},
     "MALICIOUS", "persistence through the Run key"),
    ("v13-click-handler-shell", {"Module1": 'Sub CommandButton1_Click()\n    Shell "placeholder"\nEnd Sub\n'},
     "MALICIOUS", "user-triggered entry with execution (trigger kind recorded as user action)"),
    ("v14-obj-run-unknown-object", {"Module1": 'Sub AutoOpen()\n    x = obj.Run(1)\nEnd Sub\n'},
     "SUSPICIOUS", "Run on an object of unknown type: possible only"),
    ("v15-plain-helper-no-entry", {"Module1": SHELL}, "SUSPICIOUS",
     "Shell without any entry point: dangerous capability (MEDIUM), not automatic"),
]


def case_bytes(cid: str, modules: dict[str, str]) -> bytes:
    if cid == "v16-legacy-doc":
        return make_ole({"WordDocument": word_document_stream(), **vba_streams(modules, root="Macros/")})
    return docm(modules)


CASES.append(("v16-legacy-doc", {"Module1": 'Sub AutoOpen()\n    Tool\nEnd Sub\n' + SHELL}, "MALICIOUS",
              "legacy .doc with a Macros storage"))


def run_tree(data: bytes, tree: Path | None) -> tuple[WorkerReport, float]:
    start = time.perf_counter()
    if tree is None:
        report = asyncio.run(worker.run(data))
    else:  # the baseline tree's own worker on the same bytes (its unified engine)
        out = subprocess.run([sys.executable, "-B", "-m", "app.worker", "--engine=unified"], input=data,
                             capture_output=True, cwd=tree, check=True, timeout=60).stdout
        report = WorkerReport.model_validate_json(out)
    return report, round((time.perf_counter() - start) * 1000, 1)


def rules(report: WorkerReport) -> list[str]:
    return sorted({f"{f.scanner}:{f.rule_id}:{f.severity.value}" for f in report.findings if f.severity.value != "INFO"})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--baseline-tree", type=Path)
    parser.add_argument("--trials", type=int, default=3)
    args = parser.parse_args(argv)
    rows = []
    for cid, modules, expected, why in CASES:
        data = case_bytes(cid, modules)
        row = {"id": cid, "why": why, "expected": expected, "bytes": len(data)}
        for tag, tree in (("after", None), ("baseline", args.baseline_tree)):
            if tag == "baseline" and tree is None:
                continue
            runs = [run_tree(data, tree) for _ in range(args.trials)]
            first = runs[0][0]
            row[tag] = {"verdict": verdicts(first)["aggregate"], "rules": rules(first),
                        "deterministic": all(rules(r) == rules(first) and verdicts(r) == verdicts(first) for r, _ in runs),
                        "status": {s.name: s.status for s in first.scanners},
                        "wall_ms": sorted(ms for _, ms in runs)[len(runs) // 2]}
        rows.append(row)
        base = row.get("baseline", {}).get("verdict", "-")
        print(f"{cid:32} expected {expected:11} after {row['after']['verdict']:11} baseline {base}", flush=True)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    lines = ["# VBA case matrix", "", "| Case | Tests | Expected | After | Baseline b6774be | Rules changed (non-INFO) |",
             "|---|---|---|---|---|---|"]
    for r in rows:
        b = r.get("baseline")
        before = {x.replace("yara-x:", "signatures:", 1) for x in b["rules"]} if b else set()  # renamed scanner
        added = sorted(set(r["after"]["rules"]) - before) if b else []
        removed = sorted(before - set(r["after"]["rules"])) if b else []
        diff = "; ".join([f"+{x}" for x in added] + [f"-{x}" for x in removed]) or "none"
        ok = "" if r["after"]["verdict"] == r["expected"] else " **(unexpected)**"
        lines.append(f"| {r['id']} | {r['why']} | {r['expected']} | {r['after']['verdict']}{ok} | "
                     f"{b['verdict'] if b else '-'} | {diff} |")
    (args.out / "matrix.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0 if all(r["after"]["verdict"] == r["expected"] and r["after"]["deterministic"] for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
