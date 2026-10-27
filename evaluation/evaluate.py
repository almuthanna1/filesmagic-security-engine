"""Offline evaluation harness for the FilesMagic Security Engine.

Runs every sample in a manifest through the engine's /scan code path via FastAPI's
in-process TestClient (same scanners, upload limit and decision engine as deployed; each
sample is still parsed in a separate worker process) and writes per-sample results plus
aggregate metrics. There is deliberately no network mode: samples are never sent to the
public Render service.

Strict isolation is mandatory for a research run. Before the manifest or any sample is
read, the harness checks that SECURITY_ENGINE_REQUIRE_ISOLATION=1 is loaded and scans a
harmless generated PDF; unless that preflight scan is SAFE, complete, and reports every
required isolation control with isolation_missing=[], the run aborts. If required isolation
is ever missing during the run, scanning stops and the run is recorded as failed.

Usage (inside the isolated evaluation VM, from the repository root):

    python -m evaluation.evaluate --manifest ~/fm-eval/manifest.csv \
        --samples-root ~/fm-eval/samples --out evaluation/results/run-001

Outputs (no sample bytes are ever copied):
    run_status.json  completed / aborted_preflight / failed_isolation_lost, preflight evidence
    per_sample.csv   one row per manifest entry
    per_sample.json  the same with the full isolation report per sample
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
# SKIPPED (duplicate or EXCLUDED) and NOT_RUN (after a failed run stopped) are never scanned.
VERDICTS = ["SAFE", "SUSPICIOUS", "MALICIOUS", "UNABLE_TO_SCAN"]
OUTCOMES = VERDICTS + ["REJECTED", "ERROR"]
# Why a result is incomplete. Safe, structured values only: never scanner error text, which
# can quote document content.
FAILURE_REASONS = ["isolation_unavailable", "worker_failure", "parser_failure", "scanner_error",
                   "not_applicable", "rejected_size", "http_error", "harness_exception"]

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


class EvaluationAborted(RuntimeError):
    """The run cannot produce research results (strict isolation not established or lost)."""


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


def make_client():
    """The in-process API, trusting a signing key that exists only for this run."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from fastapi.testclient import TestClient

    from app import auth
    from app.main import app

    key = Ed25519PrivateKey.generate()
    auth.PUBLIC_KEY = key.public_key()
    return TestClient(app), key


def post_scan(client, key, data: bytes, name: str):
    from app import auth

    # The sample ID, not the original filename, is sent; scanners ignore names anyway.
    token = auth.mint_token(key, hashlib.sha256(data).hexdigest(), len(data))
    return client.post("/scan", content=data, headers={"Authorization": f"Bearer {token}", "X-Filename": name})


def isolation_verified(body: dict) -> bool:
    """Strict mode was configured and every required isolation control is literally true."""
    from app.worker import REQUIRED_CONTROLS

    isolation = body.get("isolation") or {}
    return (body.get("isolation_required") is True and body.get("isolation_missing") == []
            and all(isolation.get(k) is True for k in REQUIRED_CONTROLS))


def failure_reason(status: int, body: dict | None) -> str:
    """Why a result is incomplete ("" if it is complete), from structured fields only."""
    if status == 413:
        return "rejected_size"
    if status != 200 or body is None:
        return "http_error"
    failed = [s for s in body["scanners"] if s["status"] == "failed"]
    if any(s.get("error_kind") == "worker" for s in failed):
        return "worker_failure"  # timeout or crash: the worker sent no isolation report
    if body.get("isolation_required") and body.get("isolation_missing"):
        return "isolation_unavailable"  # strict worker refused before reading the document
    if not failed:
        return "" if body["complete"] else "not_applicable"
    if {s.get("error_kind") for s in failed} <= {"malformed_input", "invalid_structure"}:
        return "parser_failure"
    return "scanner_error"


def preflight_document() -> bytes:
    """A known harmless, valid one-page PDF, generated here; never taken from the dataset."""
    import io

    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def strict_preflight(client, key) -> dict:
    """Prove strict isolation works before any sample is touched. Raises EvaluationAborted."""
    from app import worker

    evidence = {"strict_isolation_configured": worker.REQUIRE_ISOLATION}
    if not worker.REQUIRE_ISOLATION:
        raise EvaluationAborted("strict isolation is not configured: set SECURITY_ENGINE_REQUIRE_ISOLATION=1", evidence)
    try:
        response = post_scan(client, key, preflight_document(), "PREFLIGHT")
    except Exception as e:
        raise EvaluationAborted(f"preflight scan raised {type(e).__name__}", evidence) from None
    body = response.json() if response.status_code == 200 else None
    evidence.update(http_status=response.status_code)
    if body:
        evidence.update(request_id=body.get("request_id"), verdict=body["verdict"], complete=body["complete"],
                        isolation_required=body.get("isolation_required"), isolation=body.get("isolation"),
                        isolation_missing=body.get("isolation_missing"),
                        scanner_status=scanner_status(body), failure_reason=failure_reason(200, body))
    if not (body and body["verdict"] == "SAFE" and body["complete"] is True and isolation_verified(body)):
        missing = ", ".join((body or {}).get("isolation_missing") or []) or "none reported"
        raise EvaluationAborted(f"strict-isolation preflight failed (missing: {missing})", evidence)
    return evidence


def scanner_status(body: dict) -> str:
    """name=status[:error_kind[:error_type]]; error kinds and types are engine-validated identifiers."""
    parts = []
    for s in body["scanners"]:
        detail = ":".join(filter(None, [s["status"], s.get("error_kind"), s.get("error_type")]))
        parts.append(f"{s['name']}={detail}")
    return ";".join(parts)


def scan_samples(rows: list[dict], client=None, key=None, require_isolation: bool = False) -> tuple[list[dict], str]:
    """Scan every unique, non-EXCLUDED sample. Returns the results and the run status:
    "completed", or "failed_isolation_lost" if strict isolation went missing (scanning stops;
    remaining samples are NOT_RUN). Isolation is applied before a worker reads its document,
    so a missing control is never caused by the sample itself."""
    if client is None:
        client, key = make_client()
    status = "completed"
    results = []
    for row in rows:
        result = {k: row[k] for k in ("sample_id", "sha256", "file_type", "ground_truth", "split",
                                      "active_content", "encrypted", "duplicate_of")}
        result.update(outcome="", http_status="", duration_ms="", rule_ids="", scanners="", max_severity="",
                      message="", size_bytes=row["_size"], request_id="", complete="", failure_reason="",
                      scanner_status="", isolation_required="", isolation={}, isolation_missing="",
                      ruleset_sha256="")
        if row["duplicate_of"] or row["ground_truth"] == "EXCLUDED":
            result["outcome"] = "SKIPPED"
            results.append(result)
            continue
        if status != "completed":
            result["outcome"] = "NOT_RUN"
            results.append(result)
            continue

        data = row["_path"].read_bytes()
        start = time.perf_counter()
        try:
            response = post_scan(client, key, data, row["sample_id"])
        except Exception as e:  # the type only: exception text can quote sample content
            result.update(outcome="ERROR", failure_reason="harness_exception", message=type(e).__name__)
        else:
            result["http_status"] = response.status_code
            body = response.json() if response.status_code == 200 else None
            result["failure_reason"] = failure_reason(response.status_code, body)
            if body is not None:
                findings = body["findings"]
                result.update(
                    outcome=body["verdict"],
                    rule_ids=";".join(sorted({f["rule_id"] or f["category"] for f in findings})),
                    scanners=";".join(sorted({f["scanner"] for f in findings})),
                    max_severity=max((f["severity"] for f in findings), key=SEVERITY_RANK.get, default=""),
                    message=body["message"],  # composed by the engine from counts, never document text
                    request_id=body.get("request_id", ""), complete=body["complete"],
                    scanner_status=scanner_status(body), isolation_required=body.get("isolation_required", ""),
                    isolation=body.get("isolation") or {}, isolation_missing=";".join(body.get("isolation_missing") or []),
                    ruleset_sha256=body.get("versions", {}).get("ruleset_sha256", ""),
                )
                if require_isolation and result["failure_reason"] != "worker_failure" and not isolation_verified(body):
                    status = "failed_isolation_lost"
            elif response.status_code == 413:
                result.update(outcome="REJECTED", message="over the upload size limit")
            else:
                result.update(outcome="ERROR", message=f"HTTP {response.status_code}")
        result["duration_ms"] = round((time.perf_counter() - start) * 1000, 2)
        results.append(result)
    return results, status


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
    scanned = [r for r in results if r["outcome"] not in ("SKIPPED", "NOT_RUN", "")]
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
            "not_run": sum(r["outcome"] == "NOT_RUN" for r in results),
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
        "failure_reasons": {gt: dict(Counter(r["failure_reason"] for r in scanned if r["ground_truth"] == gt
                                             and r["failure_reason"])) for gt in ("BENIGN", "MALICIOUS", "SECURITY_TEST")},
        "isolation": {
            "samples_with_verified_isolation": sum(r["http_status"] == 200 and isolation_verified(
                {"isolation_required": r["isolation_required"], "isolation": r["isolation"],
                 "isolation_missing": [m for m in r["isolation_missing"].split(";") if m]}) for r in scanned),
            "samples_without_isolation_report": sum(r["failure_reason"] in ("worker_failure", "rejected_size", "http_error",
                                                                            "harness_exception") for r in scanned),
        },
    }


# ----------------------------------------------------------------------------- environment / output


def environment(manifest: Path | None) -> dict:
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
    harness_peak_rss_mib = None
    try:
        import resource  # Unix only

        # The harness process only (RUSAGE_SELF). Scan workers are separate processes and are
        # NOT included; worker memory is not measured by this harness.
        harness_peak_rss_mib = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)  # Linux: KiB
    except ImportError:
        pass
    from app import main, worker

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "engine_commit": commit, "working_tree_dirty": dirty,
        "manifest_sha256": sha256_of(manifest) if manifest and manifest.is_file() else None,
        "engine_version": main.VERSIONS.get("engine"), "ruleset_sha256": main.VERSIONS.get("ruleset_sha256"),
        "strict_isolation_configured": worker.REQUIRE_ISOLATION,
        "python": platform.python_version(), "platform": platform.platform(),
        "packages": {p: version(p) for p in ("yara-x", "oletools", "pypdf", "msoffcrypto-tool", "defusedxml", "fastapi")},
        "harness_peak_rss_mib": harness_peak_rss_mib,
        "worker_memory_measured": False,
    }


PER_SAMPLE_COLUMNS = ["sample_id", "sha256", "file_type", "ground_truth", "split", "active_content", "encrypted",
                      "duplicate_of", "size_bytes", "outcome", "http_status", "duration_ms", "max_severity",
                      "rule_ids", "scanners", "message",
                      # Added for strict-isolation evidence; existing columns keep their meaning and order.
                      "complete", "failure_reason", "scanner_status", "isolation_required", "isolation",
                      "isolation_missing", "request_id", "engine_commit", "ruleset_sha256"]


def fmt(v):
    return "–" if v is None else (f"{v:.3f}" if isinstance(v, float) else str(v))


def markdown(summary: dict, env: dict, split: str | None, status: dict) -> str:
    banner = [] if status["status"] == "completed" and status["strict_isolation_required"] else [
        f"> **NOT A VALID RESEARCH RUN** (status `{status['status']}`, strict isolation required: "
        f"{status['strict_isolation_required']}). Do not report these metrics.", ""]
    lines = [f"# FilesMagic evaluation summary", "", *banner,
             f"- Run: {env['timestamp_utc']}, engine commit `{env['engine_commit']}`"
             f"{' (working tree DIRTY)' if env['working_tree_dirty'] else ''}; engine {env['engine_version']}, "
             f"rule set `{env['ruleset_sha256']}`",
             f"- Status: `{status['status']}`; strict isolation required: {status['strict_isolation_required']}; "
             f"preflight request `{status['preflight'].get('request_id', '–')}`",
             f"- Isolation: {json.dumps(summary['isolation'])}",
             f"- Split: {split or 'all'}; manifest SHA-256 `{env['manifest_sha256']}`",
             f"- Python {env['python']} on {env['platform']}; harness-process peak RSS {fmt(env['harness_peak_rss_mib'])} MiB "
             f"(scan workers not included; worker memory not measured)",
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
    lines += ["", "## Incomplete results by reason", ""]
    lines += [f"- {gt}: {reasons or '{}'}" for gt, reasons in summary["failure_reasons"].items()]
    lines += ["", "## Latency (harness wall-clock per sample, incl. worker start-up, ms)", "",
              f"- all: {summary['latency']['all']}"]
    lines += [f"- {t}: {v}" for t, v in summary["latency"]["by_file_type"].items()]
    lines += ["", "## Rule hits", ""]
    lines += [f"- {gt}: {hits}" for gt, hits in summary["rule_hits"].items()]
    if summary["errors"]:
        lines += ["", "## Errors", ""] + [f"- {e['sample_id']}: {e['message']}" for e in summary["errors"]]
    return "\n".join(lines) + "\n"


def write_status(out: Path, status: dict) -> None:
    (out / "run_status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")


def run(manifest: Path, samples_root: Path, out: Path, split: str | None = None, client=None, key=None,
        require_isolation: bool = True) -> dict:
    """Evaluate a manifest. require_isolation=False exists only for functional tests of the
    harness on hosts without namespaces; such output is marked as not a valid research run.
    Raises EvaluationAborted if strict isolation cannot be established or is lost."""
    out.mkdir(parents=True, exist_ok=True)
    status = {"status": "completed", "strict_isolation_required": require_isolation, "preflight": {}}
    if client is None:
        client, key = make_client()
    if require_isolation:  # before the manifest or any sample file is read
        try:
            status["preflight"] = strict_preflight(client, key)
        except EvaluationAborted as e:
            status.update(status="aborted_preflight", reason=e.args[0], preflight=e.args[1])
            write_status(out, status)
            raise

    rows = load_manifest(manifest, samples_root)
    if split:
        rows = [r for r in rows if r["split"] == split]
    results, status["status"] = scan_samples(rows, client, key, require_isolation)
    summary = summarise(results)
    env = environment(manifest)
    for r in results:
        r["engine_commit"] = env["engine_commit"] or ""

    with (out / "per_sample.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PER_SAMPLE_COLUMNS)
        writer.writeheader()
        writer.writerows({k: (";".join(f"{c}={v}" for c, v in r[k].items()) if k == "isolation" else r.get(k, ""))
                          for k in PER_SAMPLE_COLUMNS} for r in results)
    (out / "per_sample.json").write_text(json.dumps([{k: r.get(k, "") for k in PER_SAMPLE_COLUMNS} for r in results],
                                                    indent=2), encoding="utf-8")
    (out / "summary.json").write_text(json.dumps({"run_status": status, "environment": env, "split": split, **summary},
                                                 indent=2), encoding="utf-8")
    (out / "summary.md").write_text(markdown(summary, env, split, status), encoding="utf-8")
    write_status(out, status)
    if status["status"] != "completed":
        raise EvaluationAborted("required isolation was lost during the run; scanning stopped "
                                f"({summary['counts']['not_run']} samples not run)", status)
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
        summary = run(args.manifest, args.samples_root, args.out, args.split)  # strict isolation always required
    except ManifestError as e:
        print(e, file=sys.stderr)
        return 2
    except EvaluationAborted as e:
        print(f"Evaluation aborted: {e.args[0]}. See {args.out / 'run_status.json'}.", file=sys.stderr)
        return 3
    print(f"Wrote {args.out}. Block view: {json.dumps(summary['views']['block'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
