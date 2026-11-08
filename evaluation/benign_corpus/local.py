"""Internal baseline: every corpus file through both engines in the real worker subprocess, with the
verdict rules /scan applies (evaluation.cases.verdicts). No token, no network.

    python -m evaluation.benign_corpus.local --out <results.json> [--dir evaluation/benign_corpus/independent]
"""

import argparse
import asyncio
import json
import time
from pathlib import Path

from app import main, worker
from evaluation.cases import verdicts

FILES = Path(__file__).parent / "files"


def scan(data: bytes, engine: str) -> dict:
    start = time.perf_counter()
    report = asyncio.run(worker.run(data, engine=engine))
    return {"verdict": verdicts(report)["aggregate"], "wall_ms": round((time.perf_counter() - start) * 1000, 1),
            "status": {s.name: s.status for s in report.scanners},
            "errors": {s.name: s.error for s in report.scanners if s.error},
            "findings": sorted(f"{f.scanner}:{f.rule_id}:{f.severity.value}" for f in report.findings),
            "scanner_ms": round(sum(s.duration_ms or 0 for s in report.scanners), 2)}


def main_(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--dir", type=Path, default=FILES, help="folder of documents (default: files/)")
    args = parser.parse_args(argv)
    rows = []
    for f in sorted(p for p in args.dir.iterdir() if p.name != "manifest.json"):
        data = f.read_bytes()
        row = {"file": f.name, "detected_format": main.detect_format(data)}
        row |= {e: scan(data, e) for e in ("reference", "unified")}
        rows.append(row)
        print(f"{f.name:45} {row['detected_format']:5} {row['reference']['verdict']:14} {row['unified']['verdict']:14} "
              f"{'; '.join(x for x in row['unified']['findings'] if not x.endswith(':INFO'))[:120]}")
    args.out.write_text(json.dumps(rows, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_())
