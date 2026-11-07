"""Acceptance run over real HTTP: Security Lab token route -> engine /scan, for both engines.

Does what the Lab's browser code does (lib/api.ts): hash the file, ask the Lab's /api/scan-token
for a file-bound token, upload the raw bytes to the engine's /scan?engine=..., sending the Lab's
Origin so CORS is checked as a browser would. Every inert fixture of evaluation.cases goes through
both engines and is compared with the frozen evaluation (verdict, non-INFO rules, scanner
statuses); a few extra cases cover other formats and failures. Records the engine commit and the
engine of every response. Standard library only.

Inert, synthetic fixtures only: never point this at genuine malware or private documents.

    python -m evaluation.lab_acceptance --lab http://localhost:3000 --api http://localhost:8000 \
        --frozen docs/evidence/custom-engine-1668326 --out <report.json>
"""

import argparse
import hashlib
import http.client
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from evaluation.cases import cases
from tests import custom_fixtures as fx

ENGINES = ["reference", "unified"]
EXPECTED_SCANNERS = {"reference": ["yara-x", "office", "pdf", "custom"],
                     "unified": ["yara-x", "office", "pdf", "custom", "yara-x-engine", "pdf-chains", "vba-chains",
                                 "ooxml-links"]}
# Extra cases: (id, data, expected verdict) - formats and a fail-closed parse failure.
EXTRA = [
    ("office-clean-xlsx", fx.office_package("xlsx"), "SAFE"),
    ("office-clean-pptx", fx.office_package("pptx"), "SAFE"),
    ("corrupt-truncated-pdf", b"%PDF-1.7\n1 0 obj\n<< /Length 10 >>\nstream\nno end marker follows", "UNABLE_TO_SCAN"),
]
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def request(url: str, data: bytes | None = None, headers: dict | None = None, method: str = "GET"):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def headers_only_status(url: str, length: int, headers: dict) -> int:
    parts = urllib.parse.urlsplit(url)
    connection = (http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection)(
        parts.netloc, timeout=60)
    try:
        connection.putrequest("POST", f"{parts.path}?{parts.query}")
        for k, v in {**headers, "Content-Length": str(length), "Content-Type": "application/octet-stream"}.items():
            connection.putheader(k, v)
        connection.endheaders()
        return connection.getresponse().status
    finally:
        connection.close()


def token(lab: str, data: bytes) -> tuple[int, dict]:
    body = json.dumps({"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}).encode()
    status, _, raw = request(f"{lab}/api/scan-token", body, {"Content-Type": "application/json"}, "POST")
    return status, json.loads(raw or b"{}")


def scan(lab: str, api: str, data: bytes, engine: str, name: str) -> dict:
    status, issued = token(lab, data)
    if status != 200:
        return {"http": status, "stage": "token", "detail": issued.get("detail")}
    start = time.perf_counter()
    status, headers, raw = request(f"{api}/scan?engine={engine}", data, {
        "Authorization": f"Bearer {issued['token']}", "Content-Type": "application/octet-stream",
        "X-Filename": name, "Origin": lab}, "POST")
    wall = round((time.perf_counter() - start) * 1000, 1)
    out = {"http": status, "stage": "scan", "wall_ms": wall,
           "cors_allowed": headers.get("access-control-allow-origin") == lab}
    try:
        body = json.loads(raw)
    except ValueError:
        return out | {"detail": raw[:200].decode("latin-1")}
    if status != 200:
        return out | {"detail": body.get("detail")}
    return out | {
        "engine": body["engine"], "commit": body["versions"].get("commit"), "verdict": body["verdict"],
        "rules": sorted({f"{f['scanner']}:{f['rule_id']}:{f['severity']}" for f in body["findings"]
                         if f["severity"] != "INFO"}),
        "status": {s["name"]: s["status"] for s in body["scanners"]}, "complete": body["complete"],
        "duration_ms": body["duration_ms"], "sha256": body["sha256"], "sent_sha256": hashlib.sha256(data).hexdigest(),
        "evidence_items": sum(len(f.get("evidence") or []) for f in body["findings"]),
        "isolation_missing": body.get("isolation_missing", []),
    }


def check(result: dict, engine: str, frozen: dict | None, expected_verdict: str | None) -> list[str]:
    problems = []
    if result.get("http") != 200:
        return [f"HTTP {result.get('http')} at {result.get('stage')}: {result.get('detail')}"]
    if not result["cors_allowed"]:
        problems.append("the engine did not allow the Lab's origin (CORS)")
    if result["sha256"] != result["sent_sha256"]:
        problems.append("the response describes different bytes than were uploaded")
    if result["engine"] != engine:
        problems.append(f"requested {engine}, response came from {result['engine']}")
    if sorted(result["status"]) != sorted(EXPECTED_SCANNERS[engine]):
        problems.append(f"unexpected scanners {sorted(result['status'])}")
    if frozen:
        # Not the frozen SHA-256: DEFLATE output depends on the zlib build, so a ZIP fixture built on
        # another platform has different bytes. The hash of the bytes actually sent is checked above.
        for key, want in (("verdict", frozen["verdicts"]["aggregate"]), ("rules", frozen["rules"]),
                          ("status", frozen["status"])):
            if result[key] != want:
                problems.append(f"{key}: got {result[key]}, frozen {want}")
    if expected_verdict and result["verdict"] != expected_verdict:
        problems.append(f"verdict {result['verdict']}, expected {expected_verdict}")
    return problems


def items() -> list[tuple[str, bytes, str | None]]:
    return [(c["id"], c["data"], None) for c in cases()] + EXTRA


def run(lab: str, api: str, frozen_dir: Path | None, batch: int | None = None, batch_size: int = 6,
        scans: bool = True, failure_checks: bool = True, require_isolation: bool = False) -> dict:
    """batch/batch_size: scan only that slice of the fixtures (each costs one token per engine), so a
    run can respect the Lab's token limit. require_isolation: a result with missing isolation
    controls is a failure, and scanning stops at the first one."""
    lab, api = lab.rstrip("/"), api.rstrip("/")
    _, _, raw = request(f"{api}/health")  # also wakes a sleeping instance before any token is taken
    health = json.loads(raw)
    frozen = {e: {r["id"]: r for r in json.loads((frozen_dir / e / "results.json").read_text())["results"]}
              for e in ENGINES} if frozen_dir else {e: {} for e in ENGINES}
    rows, stopped = [], None
    selected = items() if batch is None else items()[batch * batch_size:(batch + 1) * batch_size]
    for case, data, expected in (selected if scans else []):
        for engine in ENGINES:
            result = scan(lab, api, data, engine, f"{case}.bin")
            problems = check(result, engine, frozen[engine].get(case), expected)
            if require_isolation and result.get("http") == 200 and result.get("isolation_missing"):
                problems.append(f"required isolation missing: {result['isolation_missing']}")
                stopped = f"isolation missing at {case} ({engine}); scanning stopped"
            rows.append({"case": case, "engine": engine, "result": result, "problems": problems})
            if stopped:
                break
        if stopped:
            break
    if failure_checks and not stopped:
        rows += failure_rows(lab, api, health)
    failed = [r for r in rows if r["problems"]]
    return {"lab": lab, "api": api, "health": health, "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "batch": batch, "batch_size": batch_size, "stopped": stopped,
            "checks": len(rows), "failed": len(failed), "rows": rows}


def failure_rows(lab: str, api: str, health: dict) -> list[dict]:
    """Failure handling over HTTP; uses one token (for the oversized upload)."""
    rows = []
    oversized = b"\0" * (MAX_UPLOAD_BYTES + 1)
    status, issued = token(lab, oversized)
    rows.append({"case": "oversized-token", "engine": "-", "result": {"http": status, "detail": issued.get("detail")},
                 "problems": [] if status == 413 else [f"token route answered {status} for an oversized file"]})
    # The engine refuses on Content-Length and closes the connection, so send only the headers and
    # read the answer before any body byte (a client still sending 10 MB would see a reset instead).
    status, issued = token(lab, b"x")
    s = headers_only_status(f"{api}/scan?engine=reference", MAX_UPLOAD_BYTES + 1, {
        "Authorization": f"Bearer {issued.get('token', '')}", "Origin": lab})
    rows.append({"case": "oversized-upload", "engine": "reference", "result": {"http": s},
                 "problems": [] if s == 413 else [f"engine answered {s} for an oversized upload"]})
    s, _, raw = request(f"{api}/scan?engine=fastest", b"x", {"Origin": lab}, "POST")
    rows.append({"case": "unknown-engine", "engine": "fastest", "result": {"http": s},
                 "problems": [] if s == 400 else [f"engine answered {s} for an unknown engine"]})
    s, _, raw = request(f"{api}/scan?engine=unified", b"x", {"Origin": lab, "Authorization": "Bearer not-a-token"}, "POST")
    want = 401 if "unified" in health.get("engines", []) else 403
    rows.append({"case": "bad-token", "engine": "unified", "result": {"http": s},
                 "problems": [] if s == want else [f"engine answered {s} for an invalid token, expected {want}"]})
    return rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lab", required=True)
    parser.add_argument("--api", required=True)
    parser.add_argument("--frozen", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--batch", type=int, help="scan only this slice of the fixtures (0-based); no failure checks")
    parser.add_argument("--batch-size", type=int, default=6, help="fixtures per batch (two tokens each)")
    parser.add_argument("--failure-checks-only", action="store_true", help="run only the failure checks (one token)")
    parser.add_argument("--require-isolation", action="store_true",
                        help="fail, and stop scanning, if any result has missing isolation controls")
    args = parser.parse_args(argv)
    report = run(args.lab, args.api, args.frozen, batch=args.batch, batch_size=args.batch_size,
                 scans=not args.failure_checks_only, failure_checks=args.batch is None,
                 require_isolation=args.require_isolation)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))
    for r in report["rows"]:
        res = r["result"]
        mark = "FAIL" if r["problems"] else "ok  "
        print(f"{mark} {r['case']:42} {r['engine']:9} http={res.get('http')} verdict={res.get('verdict', '-'):14} "
              f"{'; '.join(r['problems'])}")
    print(f"{report['checks'] - report['failed']} of {report['checks']} checks passed; engine commit "
          f"{report['health'].get('commit')}; engines {report['health'].get('engines')}")
    if report["stopped"]:
        print(f"STOPPED: {report['stopped']}")
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
