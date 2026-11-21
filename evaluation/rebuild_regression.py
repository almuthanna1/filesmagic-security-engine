"""Phase 6 numbers that compare_baseline does not give: matcher cost and engine latency/determinism.

    python -m evaluation.rebuild_regression BASELINE_DIR AFTER_DIR [--out FILE]

1. Signature matcher vs YARA-X (development-only oracle) on the parity corpus of
   tests/test_signatures.py: agreement, total scan time (best of 3) and Python heap peak
   (tracemalloc; YARA-X's native allocations are invisible to it, so only ours is reported).
2. Synthetic cases (cases-unified/results.json in each directory): determinism flags and the median
   in-worker time per case (sum of the scanners' medians, excluding process start-up) and harness wall.
"""

import argparse
import json
import statistics
import time
import tracemalloc
from pathlib import Path

from app.engine import signatures as sig
from app.engine.signatures import SignatureScanner
from tests.test_signatures import ROOT, parity_corpus


def best_of(fn, corpus, n=3) -> float:
    times = []
    for _ in range(n):
        start = time.perf_counter()
        for d in corpus:
            fn(d)
        times.append(time.perf_counter() - start)
    return round(min(times) * 1000, 1)


def matcher(corpus) -> dict:
    ours = SignatureScanner()
    tracemalloc.start()
    for d in corpus:
        ours.scan("", d)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    out = {"inputs": len(corpus), "bytes": sum(map(len, corpus)), "ours_ms": best_of(lambda d: ours.scan("", d), corpus),
           "ours_heap_peak_kib": round(peak / 1024, 1)}
    try:
        import yara_x
    except ImportError:
        return out | {"yara_x": "not installed (requirements-dev.txt)"}
    compiler = yara_x.Compiler(includes_enabled=False)
    for path in sorted((ROOT / "tests/signature_parity").glob("*.yar")):
        compiler.add_source(path.read_text(encoding="utf-8"), origin=path.name)
    rules = compiler.build()

    def yscan(d):
        s = yara_x.Scanner(rules)
        s.max_matches_per_pattern(sig.MAX_MATCHES_PER_PATTERN)
        return {r.identifier for r in s.scan(d).matching_rules} - {"PDF_JavaScript_With_Automatic_Action"}

    reused = yara_x.Scanner(rules)  # matching cost alone; the retired scanner built one per scan (as yscan)
    reused.max_matches_per_pattern(sig.MAX_MATCHES_PER_PATTERN)
    agree = sum(yscan(d) == {f.rule_id for f in ours.scan("", d) or []} for d in corpus)
    return out | {"yara_x_ms": best_of(yscan, corpus), "yara_x_reused_scanner_ms": best_of(reused.scan, corpus),
                  "agreements": agree}


def cases(directory: Path) -> dict:
    rows = json.loads((directory / "cases-unified/results.json").read_text(encoding="utf-8"))["results"]
    inner = [sum(t["median_ms"] for k, t in r["timing_ms"].items() if k != "harness_wall") for r in rows]
    return {"cases": len(rows), "nondeterministic": [r["id"] for r in rows if not r["deterministic"]],
            "median_in_worker_ms": round(statistics.median(inner), 2), "max_in_worker_ms": round(max(inner), 2),
            "median_harness_wall_ms": round(statistics.median(r["timing_ms"]["harness_wall"]["median_ms"] for r in rows), 1)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("baseline", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    report = {"signature_matcher": matcher(parity_corpus()),
              "cases": {"baseline": cases(args.baseline), "after": cases(args.after)}}
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    m = report["signature_matcher"]
    return 0 if m.get("agreements", m["inputs"]) == m["inputs"] and not report["cases"]["after"]["nondeterministic"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
