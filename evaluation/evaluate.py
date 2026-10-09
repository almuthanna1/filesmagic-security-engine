"""Offline evaluation harness for the FilesMagic Security Engine.

Runs every sample in a manifest through the engine IN-PROCESS (FastAPI TestClient,
i.e. the exact production /scan code path including the upload limit) and writes
per-sample results plus aggregate metrics. There is deliberately no network mode:
samples are never sent to the public Render service.

Usage (inside the isolated evaluation VM, from the repository root):

    python -m evaluation.evaluate --manifest ~/fm-eval/manifest.csv \
        --samples-root ~/fm-eval/samples --out evaluation/results/run-001

Outputs (no sample bytes are ever copied):
    per_sample.csv   one row per manifest entry
    summary.json     all metrics, machine-readable
    summary.md       the same, readable
See evaluation/README.md for the methodology behind every metric.
"""

import argparse
import csv
import hashlib
import json
import math
import platform
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

GROUND_TRUTHS = {"BENIGN", "MALICIOUS", "SECURITY_TEST", "EXCLUDED"}
SPLITS = {"dev", "holdout"}
TRI_STATE = {"yes", "no", "unknown"}
REQUIRED_COLUMNS = [
    "sample_id", "sha256", "path", "file_type", "ground_truth", "ground_truth_basis",
    "source", "source_ref", "acquired_date", "split", "active_content", "encrypted", "tags", "notes",
]
# Outcomes beyond the four verdicts: REJECTED = HTTP 413 (over the upload limit),
# ERROR = any other non-200 response or exception (a harness/engine bug, not a verdict).
VERDICTS = ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNABLE_TO_SCAN"]
OUTCOMES = VERDICTS + ["REJECTED", "ERROR"]

# Verdict-to-binary mappings. Ground truth: MALICIOUS = positive, BENIGN = negative.
VIEWS = {
    # Would FilesMagic stop the file automatically? Coverage failures reported separately.
    "block": {"positive": {"SUSPICIOUS", "MALICIOUS"}, "negative": {"SAFE"}},
    # What the user experiences: production also refuses files it could not scan.
    "block_fail_closed": {"positive": {"SUSPICIOUS", "MALICIOUS", "UNABLE_TO_SCAN", "REJECTED"}, "negative": {"SAFE"}},
    # High-confidence conviction: only MALICIOUS counts as a detection.
    "conviction": {"positive": {"MALICIOUS"}, "negative": {"SAFE", "SUSPICIOUS"}},
}


class ManifestError(ValueError):
    pass


# ----------------------------------------------------------------------------- manifest


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(manifest: Path, samples_root: Path) -> list[dict]:
    """Validate the manifest and every sample file; mark SHA-256 duplicates."""
    samples_root = samples_root.resolve()
    if samples_root == REPO_ROOT or REPO_ROOT in samples_root.parents:
        raise ManifestError(f"samples root {samples_root} is inside the repository; keep samples outside it")

    with manifest.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ManifestError(f"manifest is missing columns: {', '.join(missing)}")
        rows = list(reader)

    errors, seen_ids, first_by_hash = [], set(), {}
    for n, row in enumerate(rows, start=2):  # line 1 is the header
        row = {k: (v or "").strip() for k, v in row.items() if k in REQUIRED_COLUMNS}
        rows[n - 2] = row
        where = f"line {n} ({row['sample_id'] or 'no id'})"
        if not row["sample_id"] or row["sample_id"] in seen_ids:
            errors.append(f"{where}: sample_id missing or not unique")
        seen_ids.add(row["sample_id"])
        if row["ground_truth"] not in GROUND_TRUTHS:
            errors.append(f"{where}: ground_truth must be one of {sorted(GROUND_TRUTHS)}")
        if row["split"] not in SPLITS:
            errors.append(f"{where}: split must be one of {sorted(SPLITS)}")
        for col in ("active_content", "encrypted"):
            if row[col] not in TRI_STATE:
                errors.append(f"{where}: {col} must be yes/no/unknown")
        if row["ground_truth"] != "EXCLUDED" and not row["ground_truth_basis"]:
            errors.append(f"{where}: ground_truth_basis is required (why is this label trusted?)")

        path = (samples_root / row["path"]).resolve()
        if samples_root not in path.parents:
            errors.append(f"{where}: path escapes the samples root")
            continue
        if not path.is_file():
            errors.append(f"{where}: file not found")
            continue
        actual = sha256_of(path)
        if row["sha256"].lower() != actual:
            errors.append(f"{where}: sha256 mismatch (manifest {row['sha256'][:12]}…, file {actual[:12]}…)")
        row["_path"] = path
        row["_size"] = path.stat().st_size
        row["duplicate_of"] = first_by_hash.setdefault(actual, row["sample_id"])
        if row["duplicate_of"] == row["sample_id"]:
            row["duplicate_of"] = ""

    if errors:
        raise ManifestError("invalid manifest:\n  " + "\n  ".join(errors))
    return rows


# ----------------------------------------------------------------------------- scanning


def scan_samples(rows: list[dict], client=None) -> list[dict]:
    """Scan every unique, non-EXCLUDED sample through the in-process API."""
    if client is None:
        from fastapi.testclient import TestClient

        from app.main import app

        client = TestClient(app)

    results = []
    for row in rows:
        result = {k: row[k] for k in ("sample_id", "sha256", "file_type", "ground_truth", "split",
                                      "active_content", "encrypted", "duplicate_of")}
        result.update(outcome="", http_status="", duration_ms="", rule_ids="", scanners="",
                      max_severity="", message="", size_bytes=row["_size"])
        if row["duplicate_of"] or row["ground_truth"] == "EXCLUDED":
            result["outcome"] = "SKIPPED"
            results.append(result)
            continue

        data = row["_path"].read_bytes()
        start = time.perf_counter()
        try:
            # The sample ID, not the original filename, is sent; scanners ignore names anyway.
            response = client.post("/scan", files={"file": (row["sample_id"], data)})
        except Exception as e:
            result.update(outcome="ERROR", message=f"{type(e).__name__}: {e}"[:300])
        else:
            result["http_status"] = response.status_code
            if response.status_code == 200:
                body = response.json()
                findings = body["findings"]
                result.update(
                    outcome=body["verdict"],
                    rule_ids=";".join(sorted({f["rule_id"] or f["category"] for f in findings})),
                    scanners=";".join(sorted({f["scanner"] for f in findings})),
                    max_severity=max((f["severity"] for f in findings), key=SEVERITY_RANK.get, default=""),
                    message=body["message"],
                )
            elif response.status_code == 413:
                result.update(outcome="REJECTED", message="over the upload size limit")
            else:
                result.update(outcome="ERROR", message=f"HTTP {response.status_code}")
        result["duration_ms"] = round((time.perf_counter() - start) * 1000, 2)
        results.append(result)
    return results


SEVERITY_RANK = {s: i for i, s in enumerate(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])}


# ----------------------------------------------------------------------------- metrics


def ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def wilson(successes: int, n: int, z: float = 1.96) -> list[float] | None:
    """95% Wilson score interval for a proportion (NIST/SEMATECH e-Handbook 7.2.4.1)."""
    if n == 0:
        return None
    p = successes / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def view_metrics(scored: list[dict], view: dict) -> dict:
    tp = fn = fp = tn = 0
    excluded = Counter()
    for r in scored:
        malicious = r["ground_truth"] == "MALICIOUS"
        if r["outcome"] in view["positive"]:
            tp, fp = (tp + 1, fp) if malicious else (tp, fp + 1)
        elif r["outcome"] in view["negative"]:
            fn, tn = (fn + 1, tn) if malicious else (fn, tn + 1)
        else:
            excluded[r["ground_truth"]] += 1
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    specificity = ratio(tn, tn + fp)
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else (0.0 if tp + fp and tp + fn else None)
    out = {
        "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "excluded_malicious": excluded["MALICIOUS"], "excluded_benign": excluded["BENIGN"],
        "precision": precision, "recall": recall, "specificity": specificity,
        "false_positive_rate": ratio(fp, fp + tn), "false_negative_rate": ratio(fn, fn + tp),
        "f1": f1, "accuracy": ratio(tp + tn, tp + tn + fp + fn),
        "balanced_accuracy": (recall + specificity) / 2 if recall is not None and specificity is not None else None,
        "ci95_recall": wilson(tp, tp + fn), "ci95_specificity": wilson(tn, tn + fp),
        "ci95_false_positive_rate": wilson(fp, fp + tn), "ci95_precision": wilson(tp, tp + fp),
    }
    return {k: round(v, 4) if isinstance(v, float) else v for k, v in out.items()}


def latency(values: list[float]) -> dict | None:
    if not values:
        return None
    ordered = sorted(values)
    p95 = ordered[min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1)]
    return {"n": len(values), "mean_ms": round(statistics.mean(values), 2), "median_ms": round(statistics.median(values), 2),
            "p95_ms": p95, "max_ms": ordered[-1], "min_ms": ordered[0]}


def summarise(results: list[dict]) -> dict:
    scanned = [r for r in results if r["outcome"] not in ("SKIPPED", "")]
    scored = [r for r in scanned if r["ground_truth"] in ("BENIGN", "MALICIOUS")]

    distribution = {gt: {o: 0 for o in OUTCOMES} for gt in ("BENIGN", "MALICIOUS", "SECURITY_TEST")}
    for r in scanned:
        distribution[r["ground_truth"]][r["outcome"]] += 1

    by_type = defaultdict(list)
    for r in scored:
        by_type[r["file_type"]].append(r)

    coverage = {}
    for gt in ("BENIGN", "MALICIOUS", "SECURITY_TEST"):
        rows = [r for r in scanned if r["ground_truth"] == gt]
        unscanned = sum(r["outcome"] in ("UNABLE_TO_SCAN", "REJECTED", "ERROR") for r in rows)
        coverage[gt] = {"n": len(rows), "not_scanned": unscanned, "not_scanned_rate": ratio(unscanned, len(rows)),
                        "ci95": wilson(unscanned, len(rows))}

    rule_hits = {gt: Counter() for gt in ("BENIGN", "MALICIOUS", "SECURITY_TEST")}
    for r in scanned:
        for rule in filter(None, r["rule_ids"].split(";")):
            rule_hits[r["ground_truth"]][rule] += 1

    timed = [r for r in scanned if r["outcome"] != "ERROR" and r["duration_ms"] != ""]
    lat_by_type = defaultdict(list)
    for r in timed:
        lat_by_type[r["file_type"]].append(r["duration_ms"])

    return {
        "counts": {
            "manifest_rows": len(results),
            "duplicates_skipped": sum(bool(r["duplicate_of"]) for r in results),
            "excluded_skipped": sum(r["ground_truth"] == "EXCLUDED" for r in results),
            "scanned": len(scanned),
            "scored": len(scored),
            "by_ground_truth": dict(Counter(r["ground_truth"] for r in scanned)),
        },
        "distribution": distribution,
        "views": {name: view_metrics(scored, v) for name, v in VIEWS.items()},
        "views_by_file_type": {t: {name: view_metrics(rs, v) for name, v in VIEWS.items()} for t, rs in sorted(by_type.items())},
        "coverage": coverage,
        "rule_hits": {gt: dict(c.most_common()) for gt, c in rule_hits.items()},
        "latency": {"all": latency([r["duration_ms"] for r in timed]),
                    "by_file_type": {t: latency(v) for t, v in sorted(lat_by_type.items())}},
        "errors": [{"sample_id": r["sample_id"], "message": r["message"]} for r in scanned if r["outcome"] == "ERROR"],
    }


# ----------------------------------------------------------------------------- environment / output


def environment(manifest: Path) -> dict:
    def version(pkg):
        try:
            return metadata.version(pkg)
        except metadata.PackageNotFoundError:
            return None

    try:
        commit = subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=10).stdout.strip() or None
        dirty = bool(subprocess.run(["git", "-C", str(REPO_ROOT), "status", "--porcelain"],
                                    capture_output=True, text=True, timeout=10).stdout.strip())
    except (OSError, subprocess.SubprocessError):
        commit, dirty = None, None
    peak_rss_mib = None
    try:
        import resource  # Unix only

        peak_rss_mib = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)  # Linux reports KiB
    except ImportError:
        pass
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "engine_commit": commit, "working_tree_dirty": dirty,
        "manifest_sha256": sha256_of(manifest),
        "python": platform.python_version(), "platform": platform.platform(),
        "packages": {p: version(p) for p in ("yara-x", "oletools", "pypdf", "msoffcrypto-tool", "defusedxml", "fastapi")},
        "peak_rss_mib": peak_rss_mib,
    }


PER_SAMPLE_COLUMNS = ["sample_id", "sha256", "file_type", "ground_truth", "split", "active_content", "encrypted",
                      "duplicate_of", "size_bytes", "outcome", "http_status", "duration_ms", "max_severity",
                      "rule_ids", "scanners", "message"]


def fmt(v):
    return "–" if v is None else (f"{v:.3f}" if isinstance(v, float) else str(v))


def markdown(summary: dict, env: dict, split: str | None) -> str:
    lines = [f"# FilesMagic evaluation summary", "",
             f"- Run: {env['timestamp_utc']}, engine commit `{env['engine_commit']}`"
             f"{' (working tree DIRTY)' if env['working_tree_dirty'] else ''}",
             f"- Split: {split or 'all'}; manifest SHA-256 `{env['manifest_sha256']}`",
             f"- Python {env['python']} on {env['platform']}; peak RSS {fmt(env['peak_rss_mib'])} MiB",
             f"- Counts: {json.dumps(summary['counts'])}", "",
             "## Ground truth × outcome", "", "| Ground truth | " + " | ".join(OUTCOMES) + " |",
             "|---|" + "---|" * len(OUTCOMES)]
    for gt, row in summary["distribution"].items():
        lines.append(f"| {gt} | " + " | ".join(str(row[o]) for o in OUTCOMES) + " |")
    lines += ["", "## Binary views", "", "| View | TP | FN | FP | TN | Recall (95% CI) | FPR (95% CI) | Precision | F1 | Balanced acc. |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for name, m in summary["views"].items():
        lines.append(f"| {name} | {m['TP']} | {m['FN']} | {m['FP']} | {m['TN']} | {fmt(m['recall'])} {m['ci95_recall']} | "
                     f"{fmt(m['false_positive_rate'])} {m['ci95_false_positive_rate']} | {fmt(m['precision'])} | "
                     f"{fmt(m['f1'])} | {fmt(m['balanced_accuracy'])} |")
    lines += ["", "## Block view by file type", "", "| File type | TP | FN | FP | TN | Recall | FPR |", "|---|---|---|---|---|---|---|"]
    for t, views in summary["views_by_file_type"].items():
        m = views["block"]
        lines.append(f"| {t} | {m['TP']} | {m['FN']} | {m['FP']} | {m['TN']} | {fmt(m['recall'])} | {fmt(m['false_positive_rate'])} |")
    lines += ["", "## Coverage (UNABLE_TO_SCAN + REJECTED + ERROR)", ""]
    for gt, c in summary["coverage"].items():
        lines.append(f"- {gt}: {c['not_scanned']}/{c['n']} not scanned ({fmt(c['not_scanned_rate'])}, 95% CI {c['ci95']})")
    lines += ["", "## Latency (in-process, ms)", "", f"- all: {summary['latency']['all']}"]
    lines += [f"- {t}: {v}" for t, v in summary["latency"]["by_file_type"].items()]
    lines += ["", "## Rule hits", ""]
    lines += [f"- {gt}: {hits}" for gt, hits in summary["rule_hits"].items()]
    if summary["errors"]:
        lines += ["", "## Errors", ""] + [f"- {e['sample_id']}: {e['message']}" for e in summary["errors"]]
    return "\n".join(lines) + "\n"


def run(manifest: Path, samples_root: Path, out: Path, split: str | None = None, client=None) -> dict:
    rows = load_manifest(manifest, samples_root)
    if split:
        rows = [r for r in rows if r["split"] == split]
    results = scan_samples(rows, client)
    summary = summarise(results)
    env = environment(manifest)

    out.mkdir(parents=True, exist_ok=True)
    with (out / "per_sample.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PER_SAMPLE_COLUMNS)
        writer.writeheader()
        writer.writerows({k: r.get(k, "") for k in PER_SAMPLE_COLUMNS} for r in results)
    (out / "summary.json").write_text(json.dumps({"environment": env, "split": split, **summary}, indent=2), encoding="utf-8")
    (out / "summary.md").write_text(markdown(summary, env, split), encoding="utf-8")
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--samples-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "evaluation" / "results" /
                        datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ"))
    parser.add_argument("--split", choices=sorted(SPLITS), help="evaluate only this split")
    args = parser.parse_args(argv)
    try:
        summary = run(args.manifest, args.samples_root, args.out, args.split)
    except ManifestError as e:
        print(e, file=sys.stderr)
        return 2
    print(f"Wrote {args.out}. Block view: {json.dumps(summary['views']['block'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
