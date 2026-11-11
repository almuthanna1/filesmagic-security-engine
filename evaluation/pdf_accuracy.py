"""PDF attachment accuracy study: one change, measured before and after on labelled samples.

Plan, labels, splits and predictions: docs/pdf-accuracy-preregistration.md (committed before the
engine change). Splits:
  dev         D1-D3 (private documents: hashes in pdf_accuracy.json, paths given at run time) and
              the synthetic PDFs below, which carry each structure the change has to handle
  heldout     L01-L55 (private copies of third-party course material, selected by file-name rule
              and never scanned before the change was fixed) and benign_corpus/independent
  regression  benign_corpus/files (29), evaluation.cases cases() (16) and field_cases() (6)
Every sample is scanned by both engines of two code trees (--before, e.g. the frozen release, and
this checkout) through each tree's own worker subprocess, so each tree runs its own code.

Labels are fixed by how a sample was made or obtained, never by a verdict:
  benign       real document of known provenance: SAFE is correct, SUSPICIOUS an unexpected warning
               (not by itself an error), MALICIOUS a classification error (false positive)
  no-attachment / attachment / ambiguous / dangerous   synthetic, required outcome in REQUIRED
Nothing here is malware: scripts are app.alert-style one-liners, "executables" are a few inert bytes.

    python -m evaluation.pdf_accuracy --before /c/tmp/fm-final-wt2 --local dev.json --local heldout.json \
        --trials 3 --out <dir>
--local: JSON lists of {"id", "path"} for the private samples. Writes results.json (full findings:
keep it local) and summary.md / summary.json (rule IDs and counts only: no paths, names or descriptions).
"""

import argparse
import hashlib
import json
import math
import platform
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

from evaluation.cases import cases, field_cases
from evaluation.evaluate import latency
from tests.pdf_fixtures import CATALOG, attachment, js_action, make_pdf

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path(__file__).with_name("pdf_accuracy.json")
CORPUS = ROOT / "evaluation" / "benign_corpus"
VERDICTS = ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNABLE_TO_SCAN"]
RANK = {v: i for i, v in enumerate(VERDICTS[:3])}
REQUIRED = {"no-attachment": "SAFE", "attachment": "SUSPICIOUS", "ambiguous": "SUSPICIOUS", "dangerous": "MALICIOUS"}
EMPTY = "/Names << /EmbeddedFiles << /Names [] >> >>"
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>/* inert */</script></svg>'


def _box(kind: bytes, payload: bytes) -> bytes:  # ISO/IEC 19566-5 (JUMBF) box: length, type, payload
    return struct.pack(">I", 8 + len(payload)) + kind + payload


def _stream(data: bytes, extra: str = "") -> str:
    return f"<< /Type /EmbeddedFile {extra} /Length {len(data)} >>\nstream\n{data.decode('latin-1')}\nendstream"


def _incremental_removal() -> bytes:
    """A text attachment, then an incremental update that rewrites the catalog with an empty tree
    and frees the attachment's objects: the old bytes stay in the file."""
    extra, objs = attachment("notes.txt")
    base = make_pdf(catalog_extra=extra, objects=objs)
    prev, at = int(base.rsplit(b"startxref", 1)[1].split()[0]), len(base)
    update = b"1 0 obj\n" + CATALOG.format(extra=EMPTY).encode() + b"\nendobj\n"
    xref = at + len(update)
    update += (b"xref\n0 2\n0000000000 65535 f \n%010d 00000 n \n5 2\n0000000000 00001 f \n0000000000 00001 f \n"
               b"trailer\n<< /Size 7 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (at, prev, xref))
    return base + update


def synthetic() -> list[dict]:
    att_extra, att = attachment("notes.txt")
    c2pa = _box(b"jumb", _box(b"jumd", bytes.fromhex("6332706100110010800000aa00389b71") + b"\x03c2pa\x00")
                + _box(b"bidb", SVG))
    clean_empty = make_pdf(catalog_extra=EMPTY)
    s = lambda id, cls, made, data: dict(id=id, cls=cls, construction=made, data=data)  # noqa: E731
    return [
        s("S01-empty-tree", "no-attachment", "catalog /Names /EmbeddedFiles << /Names [] >>", clean_empty),
        s("S02-empty-dict-af-null", "no-attachment", "/AF null and /EmbeddedFiles << >> (as metadata removal leaves it)",
          make_pdf(catalog_extra="/AF null /Names << /EmbeddedFiles << >> >>")),
        s("S03-empty-tree-indirect", "no-attachment", "/Names 5 0 R -> /EmbeddedFiles 6 0 R -> << /Names [] >>",
          make_pdf(catalog_extra="/Names 5 0 R", objects={5: "<< /EmbeddedFiles 6 0 R >>", 6: "<< /Names [] >>"})),
        s("S04-empty-tree-object-stream", "no-attachment", "the empty tree inside a compressed object stream (control: "
          "no raw marker)", make_pdf(catalog_extra=EMPTY, compressed={1})),
        s("S05-text-attachment", "attachment", "a genuine text attachment", make_pdf(catalog_extra=att_extra, objects=att)),
        s("S06-mz-bytes-text-name", "attachment", "an attachment named report.txt, /Subtype text/plain, whose bytes start MZ",
          make_pdf(catalog_extra="/Names << /EmbeddedFiles << /Names [(f) 5 0 R] >> >>",
                   objects={5: "<< /Type /Filespec /F (report.txt) /UF (report.txt) /EF << /F 6 0 R >> >>",
                            6: _stream(b"MZ\x90\x00inert", "/Subtype /text#2Fplain")})),
        s("S07-c2pa-manifest-with-svg-script", "attachment", "a C2PA-style JUMBF manifest (/AF, /AFRelationship "
          "/C2PA_Manifest) whose data box holds an SVG with a script element",
          make_pdf(catalog_extra="/AF [5 0 R] /Names << /EmbeddedFiles << /Names [(manifest.c2pa) 5 0 R] >> >>",
                   objects={5: "<< /Type /Filespec /F (manifest.c2pa) /UF (manifest.c2pa) /AFRelationship /C2PA_Manifest "
                               "/EF << /F 6 0 R >> >>", 6: _stream(c2pa, "/Subtype /application#2Fc2pa")})),
        s("S08-orphan-attachment-empty-tree", "attachment", "empty tree, plus a file specification with /EF that "
          "nothing references", make_pdf(catalog_extra=EMPTY, objects=att)),
        s("S09-file-attachment-annotation", "attachment", "empty tree, attachment only on a /FileAttachment annotation",
          make_pdf(catalog_extra=EMPTY, page_extra="/Annots [7 0 R]",
                   objects={**att, 7: "<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 10 10] /FS 5 0 R >>"})),
        s("S10-dangling-tree-entry", "ambiguous", "tree names (f) -> 9 0 R, an object that does not exist",
          make_pdf(catalog_extra="/Names << /EmbeddedFiles << /Names [(f) 9 0 R] >> >>")),
        s("S11-incremental-update-removes-attachment", "ambiguous", "attachment removed by an incremental update; the "
          "old revision's bytes remain", _incremental_removal()),
        s("S12-broken-xref", "ambiguous", "empty tree, startxref points nowhere (needs repair)",
          clean_empty.rsplit(b"startxref", 1)[0] + b"startxref\n9\n%%EOF\n"),
        s("S13-marker-in-page-text", "ambiguous", "empty tree, and the page text shows (/EmbeddedFiles )",
          make_pdf(catalog_extra=EMPTY, objects={4: "stream:BT /F1 12 Tf 20 100 Td (/EmbeddedFiles ) Tj ET"})),
        s("S14-marker-after-eof", "ambiguous", "empty tree, and a %/EmbeddedFiles comment after %%EOF",
          clean_empty + b"%/EmbeddedFiles \n"),
        s("S15-auto-js-exports-attachment", "dangerous", "/OpenAction JavaScript exportDataObject of the attachment",
          make_pdf(catalog_extra="/OpenAction 7 0 R " + att_extra,
                   objects={**att, 7: js_action('this.exportDataObject\\({cName: "f", nLaunch: 2}\\);')})),
        s("S16-auto-launch-embedded-exe", "dangerous", "/OpenAction /Launch of an embedded invoice.exe (inert bytes)",
          make_pdf(catalog_extra="/OpenAction 7 0 R /Names << /EmbeddedFiles << /Names [(f) 5 0 R] >> >>",
                   objects={5: "<< /Type /Filespec /F (invoice.exe) /UF (invoice.exe) /EF << /F 6 0 R >> >>",
                            6: _stream(b"MZ\x90\x00inert", "/Subtype /application#2Foctet-stream"),
                            7: "<< /S /Launch /F 5 0 R >>"})),
        s("S17-empty-tree-auto-launch", "dangerous", "empty tree, and /OpenAction /Launch of cmd.exe",
          make_pdf(catalog_extra="/OpenAction << /S /Launch /Win << /F (cmd.exe) /P (/c rem inert) >> >> " + EMPTY)),
    ]


# One scanning process per code tree, started in that tree, so `app` is that tree's code.
SCAN = r"""
import asyncio, json, sys, time
from app import worker
from evaluation.cases import verdicts
trials, rows = int(sys.argv[1]), []
for path in json.load(sys.stdin):
    data, row = open(path, "rb").read(), {}
    for engine in ("reference", "unified"):
        runs = []
        for _ in range(trials):
            start = time.perf_counter()
            report = asyncio.run(worker.run(data, engine=engine))
            runs.append(((time.perf_counter() - start) * 1000, report))
        first = runs[0][1]
        key = lambda r: [(f.scanner, f.rule_id, f.severity.value, f.description) for f in r.findings]
        row[engine] = {"verdict": verdicts(first)["aggregate"], "status": {s.name: s.status for s in first.scanners},
                       "findings": [[f.scanner, f.rule_id, f.severity.value, f.description, list(f.evidence)]
                                    for f in first.findings],
                       "deterministic": all(verdicts(r) == verdicts(first) and key(r) == key(first) for _, r in runs),
                       "wall_ms": [round(w, 2) for w, _ in runs],
                       "scanner_ms": [{s.name: [s.status, s.duration_ms] for s in r.scanners} for _, r in runs]}
    rows.append(row)
json.dump(rows, sys.stdout)
"""


def scan_tree(tree: Path, paths: list[str], trials: int) -> list[dict]:
    done = subprocess.run([sys.executable, "-B", "-c", SCAN, str(trials)], cwd=tree, input=json.dumps(paths),
                          capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def git(tree: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(tree), *args], capture_output=True, text=True).stdout.strip()


def samples(local: list[Path], tmp: Path) -> list[dict]:
    """Every sample with its split and label; private ones checked against the committed hashes."""
    paths = {e["id"]: e["path"] for f in local for e in json.loads(f.read_text())}
    out = []
    for split, entries in json.loads(MANIFEST.read_text()).items():
        for e in entries:
            if e["id"] not in paths:
                raise SystemExit(f"{e['id']}: no local path given (--local)")
            if hashlib.sha256(Path(paths[e["id"]]).read_bytes()).hexdigest() != e["sha256"]:
                raise SystemExit(f"{e['id']}: SHA-256 differs from {MANIFEST.name}")
            out.append(dict(id=e["id"], split=split, cls="benign", fmt=e["format"], path=paths[e["id"]]))
    for split, folder in (("heldout", CORPUS / "independent"), ("regression", CORPUS / "files")):
        for f in sorted(p for p in folder.iterdir() if p.name != "manifest.json"):
            out.append(dict(id=f"{folder.name}/{f.name}", split=split, cls="benign", fmt=f.suffix[1:], path=str(f)))
    built = [dict(c, split="dev", fmt="pdf") for c in synthetic()]
    built += [dict(id=c["id"], split="regression", cls="case", fmt="", data=c["data"]) for c in cases() + field_cases()]
    for c in built:
        (path := tmp / f"{c['id']}.bin").write_bytes(c.pop("data"))
        out.append(c | {"path": str(path)})
    return out


def wilson(k: int, n: int) -> list[float] | None:
    """95% Wilson score interval for k of n."""
    if not n:
        return None
    z, p = 1.96, k / n
    centre, half = p + z * z / (2 * n), z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round(max(0.0, (centre - half) / (1 + z * z / n)), 4), round(min(1.0, (centre + half) / (1 + z * z / n)), 4)]


def outcome(cls: str, verdict: str) -> str:
    if verdict == "UNABLE_TO_SCAN":
        return "incomplete"
    if cls == "benign":
        return {"SAFE": "correct", "SUSPICIOUS": "unexpected warning", "MALICIOUS": "false positive"}[verdict]
    need = REQUIRED[cls]
    if RANK[verdict] == RANK[need] or (cls in ("attachment", "ambiguous") and verdict == "MALICIOUS"):
        return "correct"
    return "missed (false negative)" if RANK[verdict] < RANK[need] else "unexpected warning"


def rules(result: dict) -> list[str]:
    return sorted({f"{s}:{r}:{v}" for s, r, v, *_ in result["findings"] if v != "INFO"})


def summarise(rows: list[dict]) -> dict:
    runs = [(t, e) for t in ("before", "after") for e in ("reference", "unified")]
    labelled = [r for r in rows if r["cls"] != "case"]
    by = {}
    for t, e in runs:
        tag = f"{t}/{e}"
        by[tag] = {"confusion": {}, "rates": {}, "rule_contributions": {}}
        for split in ("dev", "heldout", "regression"):
            group = [r for r in labelled if r["split"] == split]
            matrix = {}
            for r in group:
                matrix.setdefault(r["cls"], Counter())[r[t][e]["verdict"]] += 1
            by[tag]["confusion"][split] = {c: {v: m[v] for v in VERDICTS} for c, m in matrix.items()}
            benign = [r for r in group if r["cls"] == "benign"]
            n = len(benign)
            fp = sum(r[t][e]["verdict"] == "MALICIOUS" for r in benign)
            warn = sum(r[t][e]["verdict"] in ("SUSPICIOUS", "MALICIOUS") for r in benign)
            by[tag]["rates"][split] = {"benign_n": n, "false_positive": [fp, wilson(fp, n)],
                                       "any_warning": [warn, wilson(warn, n)]}
            contrib = {}
            for r in benign:
                found = rules(r[t][e])
                for rule in found:
                    c = contrib.setdefault(rule, {"documents": 0, "sole_non_info_finding": 0})
                    c["documents"] += 1
                    c["sole_non_info_finding"] += len(found) == 1
            by[tag]["rule_contributions"][split] = dict(sorted(contrib.items()))
    changes = [{"id": r["id"], "split": r["split"], "class": r["cls"], "engine": e,
                "before": r["before"][e]["verdict"], "after": r["after"][e]["verdict"],
                "removed": sorted(set(rules(r["before"][e])) - set(rules(r["after"][e]))),
                "added": sorted(set(rules(r["after"][e])) - set(rules(r["before"][e])))}
               for r in rows for e in ("reference", "unified")
               if r["before"][e]["verdict"] != r["after"][e]["verdict"] or rules(r["before"][e]) != rules(r["after"][e])]
    high = lambda res: {x for x in rules(res) if x.endswith((":HIGH", ":CRITICAL"))}  # noqa: E731
    outcomes = {f"{t}/{e}": [{"id": r["id"], "split": r["split"], "class": r["cls"], "verdict": r[t][e]["verdict"],
                              "outcome": outcome(r["cls"], r[t][e]["verdict"]), "rules": rules(r[t][e])}
                             for r in labelled] for t, e in runs}
    timing = {}
    for t, e in runs:
        walls = [w for r in rows for w in r[t][e]["wall_ms"]]
        per = {}
        for r in rows:
            for trial in r[t][e]["scanner_ms"]:
                for name, (status, ms) in trial.items():
                    if ms is not None:
                        per.setdefault(f"{name} ({status})", []).append(ms)
        pdf_walls = [w for r in rows if r["fmt"] == "pdf" for w in r[t][e]["wall_ms"]]
        timing[f"{t}/{e}"] = {"wall_all": latency(walls), "wall_pdf": latency(pdf_walls),
                              "scanners": {k: latency(v) for k, v in sorted(per.items())}}
    return {"samples": Counter(f"{r['split']}/{r['cls']}" for r in rows), "by_run": by, "changes": changes,
            "lost_high_or_critical": [{"id": r["id"], "engine": e, "lost": sorted(high(r["before"][e]) - high(r["after"][e]))}
                                      for r in rows for e in ("reference", "unified")
                                      if high(r["before"][e]) - high(r["after"][e])],
            "nondeterministic": [r["id"] for r in rows for t, e in runs if not r[t][e]["deterministic"]],
            "outcomes": outcomes, "timing": timing}


def markdown(s: dict, env: dict) -> str:
    out = [f"# PDF accuracy study: results\n\nbefore `{env['before']['commit'][:7]}`, after `{env['after']['commit'][:7]}`"
           f"{' (uncommitted changes)' if env['after']['dirty'] else ''}; {env['trials']} trial(s) per scan; "
           f"{env['platform']}, Python {env['python']}.\n",
           "Samples: " + ", ".join(f"{k} {v}" for k, v in sorted(s["samples"].items())) + ".\n"]
    for split in ("dev", "heldout", "regression"):
        out.append(f"\n## Confusion matrices: {split}\n\n| run | class | " + " | ".join(VERDICTS) + " |\n|---|---|" + "---|" * 4)
        for tag, run in s["by_run"].items():
            for cls, row in run["confusion"][split].items():
                out.append(f"| {tag} | {cls} | " + " | ".join(str(row[v]) for v in VERDICTS) + " |")
        out.append("\n| run | benign n | false positives (MALICIOUS) | any warning (SUSPICIOUS or MALICIOUS) |\n|---|---|---|---|")
        for tag, run in s["by_run"].items():
            r = run["rates"][split]
            if r["benign_n"]:
                out.append(f"| {tag} | {r['benign_n']} | {r['false_positive'][0]} (95% CI {r['false_positive'][1]}) | "
                           f"{r['any_warning'][0]} (95% CI {r['any_warning'][1]}) |")
        out.append("\nPer-rule contributions on benign documents (documents with the rule; documents where it is the only "
                   "non-INFO finding):\n\n| run | rule | documents | sole |\n|---|---|---|---|")
        for tag, run in s["by_run"].items():
            for rule, c in run["rule_contributions"][split].items():
                out.append(f"| {tag} | `{rule}` | {c['documents']} | {c['sole_non_info_finding']} |")
    out.append("\n## Changes between before and after\n\n| sample | split | class | engine | before | after | removed | added |"
               "\n|---|---|---|---|---|---|---|---|")
    out += [f"| {c['id']} | {c['split']} | {c['class']} | {c['engine']} | {c['before']} | {c['after']} | "
            f"{', '.join(c['removed']) or '-'} | {', '.join(c['added']) or '-'} |" for c in s["changes"]] or ["| none |"]
    out.append(f"\nHIGH/CRITICAL findings lost: {s['lost_high_or_critical'] or 'none'}. "
               f"Non-deterministic scans: {s['nondeterministic'] or 'none'}.\n")
    out.append("\n## Outcomes after (unified)\n\n| sample | split | class | verdict | outcome | non-INFO rules |\n|---|---|---|---|---|---|")
    out += [f"| {o['id']} | {o['split']} | {o['class']} | {o['verdict']} | {o['outcome']} | {', '.join(o['rules']) or '-'} |"
            for o in s["outcomes"]["after/unified"] if o["outcome"] != "correct" or o["split"] == "dev"]
    out.append("\n(Rows not shown: held-out and regression documents with a correct outcome.)\n\n## Latency (ms)\n\n"
               "| run | scope | n | median | p95 | max |\n|---|---|---|---|---|---|")
    for tag, t in s["timing"].items():
        for scope, v in [("all scans, wall", t["wall_all"]), ("PDF scans, wall", t["wall_pdf"])] + list(t["scanners"].items()):
            if v:
                out.append(f"| {tag} | {scope} | {v['n']} | {v['median_ms']} | {v['p95_ms']} | {v['max_ms']} |")
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--before", type=Path, required=True, help="checkout of the baseline (frozen release)")
    parser.add_argument("--local", type=Path, action="append", default=[], help="JSON list of {id, path}")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as tmp:
        rows = samples(args.local, Path(tmp))
        paths = [r["path"] for r in rows]
        for tag, tree in (("before", args.before), ("after", ROOT)):
            for r, result in zip(rows, scan_tree(tree, paths, args.trials)):
                r[tag] = result
    env = {"platform": platform.platform(), "python": sys.version.split()[0], "trials": args.trials,
           **{tag: {"commit": git(tree, "rev-parse", "HEAD"), "dirty": bool(git(tree, "status", "--porcelain"))}
              for tag, tree in (("before", args.before), ("after", ROOT))}}
    summary = summarise(rows)
    args.out.mkdir(parents=True, exist_ok=True)
    for r in rows:
        r.pop("path")
    (args.out / "results.json").write_text(json.dumps({"environment": env, "rows": rows}, indent=1))
    (args.out / "summary.json").write_text(json.dumps({"environment": env, **summary}, indent=1))
    (args.out / "summary.md").write_text(markdown(summary, env))
    print(markdown(summary, env))
    return 0


if __name__ == "__main__":
    sys.exit(main())
