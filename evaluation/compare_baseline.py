"""Compare a rerun of the evaluation harnesses with the frozen pre-rebuild baseline.

    python -m evaluation.compare_baseline BASELINE_DIR AFTER_DIR

Both directories hold cases-unified/results.json (evaluation.cases) and benign-files.json /
benign-independent.json (evaluation.benign_corpus.local). Prints, per input, the unified verdict
before and after and the findings that appeared or disappeared, so every changed outcome is listed.
Scanner names renamed by the rebuild (yara-x, yara-x-engine -> signatures) are compared as one.
"""

import json
import sys
from pathlib import Path

RENAMED = {"yara-x": "signatures", "yara-x-engine": "signatures"}


def _rule(scanner: str, rule_id: str) -> str:
    return f"{RENAMED.get(scanner, scanner)}:{rule_id}"


def _findings(items) -> set[str]:
    out = set()
    for f in items:
        if isinstance(f, str):  # "scanner:RULE:SEVERITY" or "scanner:RULE"
            scanner, rule = f.split(":")[:2]
        else:
            scanner, rule = f["scanner"], f["rule_id"]
        if rule != "ENGINE_CORRELATION":  # notes, not detections
            out.add(_rule(scanner, rule))
    return out


def cases(path: Path) -> dict[str, tuple[str, set[str], bool]]:
    data = json.loads(path.read_text(encoding="utf-8"))["results"]
    return {r["id"]: (r["verdicts"]["aggregate"], _findings(r["findings"]), r.get("deterministic", True)) for r in data}


def benign(path: Path) -> dict[str, tuple[str, set[str], bool]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {r["file"]: (r["unified"]["verdict"], _findings(r["unified"]["findings"]), True) for r in data}


def compare(name: str, before: dict, after: dict) -> int:
    changed = 0
    print(f"## {name}: {len(after)} inputs")
    for key in sorted(before.keys() | after.keys()):
        if key not in before or key not in after:
            print(f"- {key}: only {'after' if key in after else 'before'}")
            changed += 1
            continue
        (vb, fb, _), (va, fa, det) = before[key], after[key]
        if vb != va or fb != fa or not det:
            changed += 1
            print(f"- {key}: {vb} -> {va}" + ("" if det else " (NOT DETERMINISTIC)"))
            for f in sorted(fa - fb):
                print(f"    + {f}")
            for f in sorted(fb - fa):
                print(f"    - {f}")
    print(f"{changed} changed\n")
    return changed


def main(baseline: str, after: str) -> None:
    b, a = Path(baseline), Path(after)
    compare("synthetic cases (unified)", cases(b / "cases-unified/results.json"), cases(a / "cases-unified/results.json"))
    for name in ("benign-files.json", "benign-independent.json"):
        compare(name, benign(b / name), benign(a / name))


if __name__ == "__main__":
    main(*sys.argv[1:3])
