"""Conversion Engine acceptance over real HTTP: what filesmagic-engine will do, against a deployed engine.

Mints Conversion Engine scan tokens, uploads the raw bytes to /scan?engine=unified, and verifies every
receipt independently (app.receipts.verify, pinned to the deployed build). Checks /health readiness,
the four verdicts and their authorizations, the authentication and integrity refusals, tampered and
mismatched receipts, and (with --lab) that a Security Lab token never yields a receipt.

Trusted benign documents and inert synthetic fixtures only: never point this at genuine malware,
EICAR or private documents. Prints and records receipt CLAIMS, never keys, tokens or receipts.

    python -m evaluation.conversion_acceptance --api https://<engine> --commit <full sha> \
        --token-key <dir>/private.txt --receipt-public-key <dir>/public.txt [--lab https://<lab>] --out <report.json>
"""

import argparse
import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key

from app import receipts
from evaluation import lab_acceptance
from evaluation.cases import cases
from tests import custom_fixtures as fx
from tests.pdf_fixtures import encrypted_pdf, make_pdf

ROOT = Path(__file__).resolve().parents[1]
BENIGN = ROOT / "evaluation" / "benign_corpus" / "files"
ROSTER = sorted(lab_acceptance.EXPECTED_SCANNERS["unified"])
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
BAD_LZW = bytes.fromhex("789c730ae15250d0773354303251084903b2cd8d80c840212405c8d608c82f492cc9d75408c9e2720de10200cb0109c8")
CASE = {c["id"]: c["data"] for c in cases()}
# (id, bytes, verdict, authorization, a reason code that must be present)
SCANS = [
    ("benign-pdf-word-export", (BENIGN / "pdf-01-word-export.pdf").read_bytes(), "SAFE", "allow", None),
    ("benign-docx", (BENIGN / "docx-01-word-plain.docx").read_bytes(), "SAFE", "allow", None),
    ("benign-xlsx", (BENIGN / "xlsx-01-excel-formulas.xlsx").read_bytes(), "SAFE", "allow", None),
    ("suspicious-auto-js-unrelated-attachment", CASE["5a-pdf-auto-js-unrelated-attachment"], "SUSPICIOUS",
     "consent_required", None),
    ("unable-damaged-page-content", make_pdf(objects={4: fx.stream_object("/Filter /LZWDecode", BAD_LZW)}),
     "UNABLE_TO_SCAN", "consent_required", "PDF_CONTENT_LZW_DECODE_FAILED"),
    ("encrypted-content", encrypted_pdf("secret"), None, "consent_required", "PDF_ENCRYPTED_CONTENT_UNAVAILABLE"),
    ("malicious-auto-js-exports-attachment", CASE["5b-pdf-auto-js-exports-attachment"], "MALICIOUS", "deny", None),
]

b64 = receipts._b64


def mint(key: Ed25519PrivateKey, data: bytes, iat: int | None = None, lifetime: int = 120) -> tuple[str, str]:
    iat = int(time.time()) if iat is None else iat
    claims = {"aud": "filesmagic-security-engine/scan", "iat": iat, "exp": iat + lifetime,
              "jti": secrets.token_hex(16), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    payload = json.dumps(claims, separators=(",", ":")).encode()
    return f"{b64(payload)}.{b64(key.sign(payload))}", claims["jti"]


def post(api: str, data: bytes, token: str | None, engine: str = "unified") -> tuple[int, dict]:
    headers = {"Content-Type": "application/octet-stream"} | ({"Authorization": f"Bearer {token}"} if token else {})
    req = urllib.request.Request(f"{api}/scan?engine={engine}", data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except ValueError:
            return e.code, {}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--api", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--token-key", type=Path, required=True, help="Conversion Engine token private.txt")
    p.add_argument("--receipt-public-key", type=Path, required=True, help="receipt public.txt")
    p.add_argument("--lab", help="Security Lab base URL: also check that a Lab token gets no receipt")
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args(argv)
    api = a.api.rstrip("/")
    key = load_der_private_key(base64.b64decode(a.token_key.read_text().strip()), password=None)
    public = load_der_public_key(base64.b64decode(a.receipt_public_key.read_text().strip()))
    trusted = {receipts.key_id(public): public}
    results = []

    def record(check: str, ok: bool, **detail):
        results.append({"check": check, "pass": bool(ok), **detail})
        print(("PASS " if ok else "FAIL ") + check + (f"  {detail}" if not ok else ""))

    with urllib.request.urlopen(f"{api}/health", timeout=180) as r:
        health = json.loads(r.read())
    record("health: service identity", health.get("service") == "filesmagic-security-engine", got=health.get("service"))
    record("health: pinned commit", health.get("commit") == a.commit, got=health.get("commit"))
    record("health: all scanners ready", health.get("scanners_ready") == health.get("scanners_registered"))
    record("health: unified engine only", health.get("engines") == ["unified"], got=health.get("engines"))
    record("health: receipt key is the expected one", health.get("receipt_key_id") in trusted,
           got=health.get("receipt_key_id"))
    record("health: conversion auth, strict isolation", health.get("conversion_auth_configured") is True
           and health.get("isolation_required") is True)
    record("health: ready_for_conversion", health.get("ready_for_conversion") is True)
    record("health: 25 MiB limit", health.get("max_upload_bytes") == MAX_UPLOAD_BYTES, got=health.get("max_upload_bytes"))

    pins = {"commit": a.commit, "scanners": ROSTER}
    good = None
    for name, data, verdict, authorization, reason in SCANS:
        token, jti = mint(key, data)
        status, body = post(api, data, token)
        problems = []
        if status != 200:
            record(f"scan {name}", False, http=status, code=body.get("code"))
            continue
        try:
            claims = receipts.verify(body.get("receipt"), trusted, sha256=hashlib.sha256(data).hexdigest(),
                                     size=len(data), token_jti=jti, pins=pins)
        except receipts.ReceiptError as e:
            record(f"scan {name}", False, receipt_error=e.code, verdict=body.get("verdict"),
                   reasons=[x["code"] for x in body.get("reasons", [])])
            continue
        good = good or (data, body["receipt"], jti)
        if body["sha256"] != hashlib.sha256(data).hexdigest() or body["size_bytes"] != len(data):
            problems.append("response hash/size differ from the uploaded bytes")
        if verdict and claims["verdict"] != verdict:
            problems.append(f"verdict {claims['verdict']}, expected {verdict}")
        if claims["authorization"] != authorization:
            problems.append(f"authorization {claims['authorization']}, expected {authorization}")
        if claims["verdict"] != body["verdict"] or claims["authorization"] != body["authorization"]:
            problems.append("receipt and body disagree")
        if reason and reason not in claims["reason_codes"]:
            problems.append(f"reason {reason} missing: {claims['reason_codes']}")
        if authorization == "consent_required" and not all(x["override_eligible"] for x in body["reasons"]):
            problems.append("consent offered with a non-eligible reason")
        if not (body["isolation_verified"] and body["isolation_missing"] == [] and claims["isolation_verified"]):
            problems.append("isolation not verified")
        if claims["scanner_versions"] != {k: body["versions"][k] for k in claims["scanner_versions"]}:
            problems.append("scanner versions differ between receipt and body")
        if claims["verdict"] in ("SUSPICIOUS", "MALICIOUS") and not (body["findings"] and body["explanation"]):
            problems.append("findings or explanation missing")
        record(f"scan {name}", not problems, problems=problems, verdict=claims["verdict"],
               authorization=claims["authorization"], reason_codes=claims["reason_codes"],
               duration_ms=body.get("duration_ms"), rid=claims["rid"], kid=claims["kid"])

    data = SCANS[0][1]
    expect = lambda label, got, want_status, want_code: record(  # noqa: E731
        label, got[0] == want_status and got[1].get("code") == want_code, http=got[0], code=got[1].get("code"))
    expect("auth: missing credentials", post(api, data, None), 401, "AUTH_MISSING")
    expect("auth: invalid token", post(api, data, "not.a-token"), 401, "AUTH_INVALID")
    expect("auth: wrong signing key", post(api, data, mint(Ed25519PrivateKey.generate(), data)[0]), 401, "AUTH_INVALID")
    expect("auth: expired token", post(api, data, mint(key, data, iat=int(time.time()) - 600)[0]), 401,
           "AUTH_EXPIRED_OR_INVALID_CLAIMS")
    replay = mint(key, data)[0]
    post(api, data, replay)
    expect("auth: replayed token", post(api, data, replay), 401, "AUTH_REPLAYED")
    expect("integrity: token for other bytes", post(api, data + b"\n", mint(key, data)[0]), 403, "TOKEN_FILE_MISMATCH")
    big = b"0" * (MAX_UPLOAD_BYTES + 1)
    record("size: over 25 MiB refused before upload",
           lab_acceptance.headers_only_status(f"{api}/scan?engine=unified", len(big),
                                              {"Authorization": f"Bearer {mint(key, big)[0]}"}) == 413)

    if good:
        data, receipt, jti = good
        payload, sig = receipt.split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
        forged = f"{b64(json.dumps(claims | {'verdict': 'SAFE', 'authorization': 'allow'}).encode())}.{sig}"
        for label, r, d in (("receipt: tampered claims", forged, data), ("receipt: other document", receipt, data + b"x")):
            try:
                receipts.verify(r, trusted, sha256=hashlib.sha256(d).hexdigest(), size=len(d), token_jti=jti, pins=pins)
                record(label, False, detail="accepted")
            except receipts.ReceiptError as e:
                record(label, True, code=e.code)

    if a.lab:
        data = SCANS[0][1]
        status, lab_token = lab_acceptance.token(a.lab, data)
        if status == 200:
            got = post(api, data, lab_token["token"])
            record("lab: Lab token scans, never gets a receipt", got[0] == 200 and got[1].get("receipt") is None,
                   http=got[0], verdict=got[1].get("verdict"))
        else:
            record("lab: Lab token issued", False, http=status)

    report = {"api": api, "commit": a.commit, "health": health, "results": results,
              "passed": sum(r["pass"] for r in results), "failed": sum(not r["pass"] for r in results),
              "not_testable_hosted": ["operational failures (worker crash, timeout, isolation loss): covered by "
                                      "tests/test_integration_v1.py and the Linux isolation suite in CI"]}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(report, indent=1))
    print(f"{report['passed']} passed, {report['failed']} failed")
    return 0 if not report["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
