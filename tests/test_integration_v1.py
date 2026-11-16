"""Integration contract v1 (docs/security-integration-v1.md): Conversion Engine tokens, signed scan
receipts, reason codes and the override policy. Inert synthetic and benign fixtures only."""

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app import auth, main, receipts, worker
from app import engine as unified_engine
from app.decision import classify
from app.models import CoverageIssue, ScannerStatus, Verdict
from evaluation.cases import cases
from tests.conftest import in_process
from tests.pdf_fixtures import encrypted_pdf
from tests.scan_client import auth_headers

client = TestClient(main.app)
CASE = {c["id"]: c["data"] for c in cases()}
BENIGN = Path(__file__).resolve().parent.parent / "evaluation" / "benign_corpus" / "files"
CONVERSION_KEY = Ed25519PrivateKey.generate()
RECEIPT_KEY = Ed25519PrivateKey.generate()
TRUSTED = {receipts.key_id(RECEIPT_KEY.public_key()): RECEIPT_KEY.public_key()}
VERIFIED = dict.fromkeys(worker.ISOLATION_CONTROLS, True) | {"net_fallback_tunnel_inert": False}


async def isolated(data: bytes, engine: str = "reference"):
    """The in-process scan, reporting what a strict Linux worker reports when every control holds."""
    report = await in_process(data, engine)
    return report.model_copy(update={"isolation": VERIFIED})


@pytest.fixture(autouse=True)
def production(monkeypatch):
    monkeypatch.setattr(auth, "CONVERSION_PUBLIC_KEY", CONVERSION_KEY.public_key())
    monkeypatch.setattr(receipts, "PRIVATE_KEY", RECEIPT_KEY)
    monkeypatch.setattr(worker, "REQUIRE_ISOLATION", True)
    monkeypatch.setattr(main, "RESEARCH_ENGINES", True)
    monkeypatch.setattr(main, "run_scan", isolated)


def token(data: bytes, key=CONVERSION_KEY, **kw) -> str:
    return auth.mint_token(key, hashlib.sha256(data).hexdigest(), len(data), **kw)


def convert_scan(data: bytes, engine: str = "unified", key=CONVERSION_KEY, **kw):
    t = token(data, key, **kw)
    jti = json.loads(base64.urlsafe_b64decode(t.split(".")[0] + "=="))["jti"]
    r = client.post(f"/scan?engine={engine}", content=data, headers={"Authorization": f"Bearer {t}"})
    return r, jti


def verified(data: bytes, body: dict, jti: str) -> dict:
    return receipts.verify(body["receipt"], TRUSTED, sha256=hashlib.sha256(data).hexdigest(), size=len(data),
                           token_jti=jti)


# ----------------------------------------------------------------------------- verdicts and receipts


@pytest.mark.parametrize("name", ["pdf-01-word-export.pdf", "docx-01-word-plain.docx",
                                  "xlsx-01-excel-formulas.xlsx", "pptx-01-ppt-plain.pptx"])
def test_realistic_benign_documents_are_safe_and_receipted_as_allow(name):
    data = (BENIGN / name).read_bytes()
    r, jti = convert_scan(data)
    body = r.json()
    assert r.status_code == 200 and body["verdict"] == "SAFE" and body["authorization"] == "allow"
    assert body["reasons"] == [] and not body["override_eligible"] and body["isolation_verified"]
    claims = verified(data, body, jti)
    assert claims["authorization"] == "allow" and claims["verdict"] == "SAFE"
    assert claims["engine"] == "unified" and claims["scanners"] == sorted(main.engine_scanners("unified"))
    assert claims["commit"] == main.VERSIONS["commit"]
    assert claims["scanner_versions"]["pypdf"] == main.VERSIONS["pypdf"]
    assert claims["exp"] - claims["iat"] == 300 and claims["kid"] in TRUSTED
    assert claims["complete"] and claims["coverage_complete"] and claims["isolation_verified"]
    assert body["sha256"] == claims["sha256"] == hashlib.sha256(data).hexdigest() and claims["size"] == len(data)


def test_suspicious_requires_consent_and_is_receipted():
    data = CASE["5a-pdf-auto-js-unrelated-attachment"]
    r, jti = convert_scan(data)
    body = r.json()
    assert body["verdict"] == "SUSPICIOUS" and body["authorization"] == "consent_required" and body["override_eligible"]
    assert body["findings"] and body["explanation"]
    claims = verified(data, body, jti)
    assert (claims["verdict"], claims["authorization"], claims["override_eligible"]) == ("SUSPICIOUS", "consent_required", True)


def test_malicious_is_receipted_but_never_authorizing():
    data = CASE["5b-pdf-auto-js-exports-attachment"]
    r, jti = convert_scan(data)
    body = r.json()
    assert body["verdict"] == "MALICIOUS" and body["authorization"] == "deny" and not body["override_eligible"]
    claims = verified(data, body, jti)
    assert (claims["verdict"], claims["authorization"], claims["override_eligible"]) == ("MALICIOUS", "deny", False)


def test_encrypted_content_is_an_override_eligible_incomplete_analysis():
    data = encrypted_pdf("secret")
    r, jti = convert_scan(data)
    body = r.json()
    assert body["verdict"] in ("UNABLE_TO_SCAN", "SUSPICIOUS") and body["authorization"] == "consent_required"
    codes = {x["code"]: x for x in body["reasons"]}
    assert codes["PDF_ENCRYPTED_CONTENT_UNAVAILABLE"]["category"] == "document"
    assert all(x["override_eligible"] for x in body["reasons"])
    claims = verified(data, body, jti)
    assert "PDF_ENCRYPTED_CONTENT_UNAVAILABLE" in claims["reason_codes"] and claims["override_eligible"]
    assert not claims["coverage_complete"]


def test_damaged_page_content_is_unable_to_scan_with_a_document_reason():
    bad_lzw = bytes.fromhex("789c730ae15250d0773354303251084903b2cd8d80c840212405c8d608c82f492cc9d75408c9e2720de10200cb0109c8")
    from tests import custom_fixtures as fx
    from tests.pdf_fixtures import make_pdf
    data = make_pdf(objects={4: fx.stream_object("/Filter /LZWDecode", bad_lzw)})
    body = convert_scan(data)[0].json()
    assert body["verdict"] == "UNABLE_TO_SCAN" and body["authorization"] == "consent_required"
    assert [x["code"] for x in body["reasons"]] == ["PDF_CONTENT_LZW_DECODE_FAILED"] and body["receipt"]


# ----------------------------------------------------------------------------- operational failures


def _fake_worker(mode: str, timeout: float | None = None):
    async def run(data, engine="reference"):
        return await worker.run(data, cmd=[sys.executable, "-m", "tests.fake_worker", mode], timeout=timeout, engine=engine)
    return run


@pytest.mark.parametrize("mode, code", [("crash", "WORKER_CRASHED"), ("garbage", "WORKER_INVALID_REPORT"),
                                        ("sleep", "WORKER_TIMEOUT")])
def test_worker_failures_deny_without_receipt(monkeypatch, mode, code):
    monkeypatch.setattr(main, "run_scan", _fake_worker(mode, timeout=2 if mode == "sleep" else None))
    body = convert_scan((BENIGN / "pdf-01-word-export.pdf").read_bytes())[0].json()
    assert body["verdict"] == "UNABLE_TO_SCAN" and body["authorization"] == "deny"
    assert body["receipt"] is None and not body["override_eligible"]
    assert [(x["code"], x["category"], x["override_eligible"]) for x in body["reasons"]] == [(code, "operational", False)]


def test_wrong_scanner_roster_denies(monkeypatch):
    async def reference_only(data, engine="reference"):
        return await isolated(data, "reference")
    monkeypatch.setattr(main, "run_scan", reference_only)
    body = convert_scan(CASE["1-pdf-clean"])[0].json()
    assert body["authorization"] == "deny" and body["receipt"] is None
    assert body["reasons"][0]["code"] == "SCANNER_ROSTER_MISMATCH"


@pytest.mark.parametrize("missing", ["network_verified", "capabilities_dropped", "audit_hook"])
def test_unverified_isolation_denies_even_a_clean_file(monkeypatch, missing):
    async def partial(data, engine="reference"):
        report = await in_process(data, engine)
        return report.model_copy(update={"isolation": VERIFIED | {missing: False}})
    monkeypatch.setattr(main, "run_scan", partial)
    body = convert_scan(CASE["1-pdf-clean"])[0].json()
    assert body["verdict"] == "SAFE"  # the documents scanned clean...
    assert body["authorization"] == "deny" and body["receipt"] is None and not body["isolation_verified"]  # ...but untrusted
    assert [x["code"] for x in body["reasons"]] == ["ISOLATION_UNVERIFIED"]


def test_isolation_not_enforced_denies(monkeypatch):
    monkeypatch.setattr(worker, "REQUIRE_ISOLATION", False)
    body = convert_scan(CASE["1-pdf-clean"])[0].json()
    assert body["authorization"] == "deny" and body["receipt"] is None
    assert [x["code"] for x in body["reasons"]] == ["ISOLATION_NOT_ENFORCED"]


def test_strict_worker_refusal_is_operational():
    statuses = [ScannerStatus(name="pdf", status="failed", error="required isolation unavailable: network_verified")]
    reasons, authorization, _ = classify(Verdict.UNABLE_TO_SCAN, statuses, [], [])
    assert [r.code for r in reasons] == ["ISOLATION_UNVERIFIED"] and authorization == "deny"


def test_scanner_error_alone_is_explained_without_blaming_either_side():
    status = [ScannerStatus(name="pdf-integrity", status="failed", error="x", error_kind="unexpected")]
    _, authorization, explanation = classify(Verdict.UNABLE_TO_SCAN, status, [], [])
    assert authorization == "deny" and "try again" not in explanation and "our side" not in explanation
    assert "try again" in classify(Verdict.UNABLE_TO_SCAN, status, [], ["WORKER_CRASHED"])[2]


def test_scanner_programming_error_denies(monkeypatch):
    scanner = next(s for s in unified_engine.SCANNERS if s.name == "pdf-chains")

    def broken(filename, data):
        raise RuntimeError("bug")
    monkeypatch.setattr(scanner, "scan", broken)
    body = convert_scan(CASE["1-pdf-clean"])[0].json()
    assert body["authorization"] == "deny" and body["receipt"] is None
    assert "SCANNER_INTERNAL_ERROR" in [x["code"] for x in body["reasons"]]


def test_scanner_not_ready_denies(monkeypatch):
    scanner = next(s for s in unified_engine.SCANNERS if s.name == "yara-x-engine")
    monkeypatch.setattr(scanner, "error", "rules failed to compile")
    monkeypatch.setattr(scanner, "_rules", None)
    assert not main.engine_ready("unified")
    assert client.get("/health").json()["ready_for_conversion"] is False
    body = convert_scan(CASE["1-pdf-clean"])[0].json()
    assert body["authorization"] == "deny" and body["receipt"] is None
    codes = [x["code"] for x in body["reasons"]]
    assert codes[0] == "SCANNER_NOT_READY" and "SCANNER_INTERNAL_ERROR" in codes


@pytest.mark.parametrize("kind, name, expected", [
    ("malformed_input", "office", "DOCUMENT_MALFORMED"),
    ("invalid_structure", "pdf", "DOCUMENT_STRUCTURE_UNSUPPORTED"),
    ("invalid_structure", "yara-x", "SCANNER_INTERNAL_ERROR"),  # YARA-X reads raw bytes: never the document
    ("unexpected", "pdf", "SCANNER_INTERNAL_ERROR"),
])
def test_scanner_failure_classification(kind, name, expected):
    reasons, authorization, _ = classify(
        Verdict.UNABLE_TO_SCAN, [ScannerStatus(name=name, status="failed", error="x", error_kind=kind)], [], [])
    assert [r.code for r in reasons] == [expected]
    assert authorization == ("consent_required" if expected.startswith("DOCUMENT_") else "deny")


def test_unknown_coverage_code_is_never_eligible():
    issue = CoverageIssue(code="PDF_SOMETHING_NEW", scanner="pdf-integrity", detail="new")
    reasons, authorization, _ = classify(Verdict.UNABLE_TO_SCAN, [], [issue], [])
    assert authorization == "deny" and not reasons[0].override_eligible and reasons[0].category == "document"


def test_operational_failure_overrides_suspicious_and_document_reasons():
    issue = CoverageIssue(code="PDF_ENCRYPTED_CONTENT_UNAVAILABLE", scanner="pdf-integrity", detail="x")
    for verdict in (Verdict.SUSPICIOUS, Verdict.UNABLE_TO_SCAN, Verdict.SAFE):
        assert classify(verdict, [], [issue], ["WORKER_CRASHED"])[1] == "deny"
    assert classify(Verdict.MALICIOUS, [], [issue], [])[1] == "deny"


def test_unable_to_scan_without_reason_is_never_eligible():
    reasons, authorization, _ = classify(Verdict.UNABLE_TO_SCAN, [], [], [])
    assert [r.code for r in reasons] == ["ANALYSIS_INCOMPLETE_UNCLASSIFIED"] and authorization == "deny"


# ----------------------------------------------------------------------------- authentication and hashes


def test_missing_token_is_refused_with_a_code():
    r = client.post("/scan?engine=unified", content=b"%PDF-1.4")
    assert r.status_code == 401 and r.json()["code"] == "AUTH_MISSING"


def test_token_from_an_unknown_key_is_refused():
    r, _ = convert_scan(CASE["1-pdf-clean"], key=Ed25519PrivateKey.generate())
    assert r.status_code == 401 and r.json()["code"] == "AUTH_INVALID"


def test_expired_and_replayed_tokens_are_refused():
    data = CASE["1-pdf-clean"]
    r, _ = convert_scan(data, now=0)
    assert r.status_code == 401 and r.json()["code"] == "AUTH_EXPIRED_OR_INVALID_CLAIMS"
    headers = {"Authorization": f"Bearer {token(data)}"}
    assert client.post("/scan?engine=unified", content=data, headers=headers).status_code == 200
    r = client.post("/scan?engine=unified", content=data, headers=headers)
    assert r.status_code == 401 and r.json()["code"] == "AUTH_REPLAYED"


def test_no_scan_key_configured_refuses_everything(monkeypatch):
    monkeypatch.setattr(auth, "PUBLIC_KEY", None)
    monkeypatch.setattr(auth, "CONVERSION_PUBLIC_KEY", None)
    r, _ = convert_scan(CASE["1-pdf-clean"])
    assert r.status_code == 401 and r.json()["code"] == "AUTH_NOT_CONFIGURED"


@pytest.mark.parametrize("change", ["bytes", "size"])
def test_token_for_other_bytes_is_refused(change):
    data = CASE["1-pdf-clean"]
    other = data.replace(b"1", b"2", 1) if change == "bytes" else data + b"\n"
    t = token(data)
    r = client.post("/scan?engine=unified", content=other, headers={"Authorization": f"Bearer {t}"})
    assert r.status_code == 403 and r.json()["code"] == "TOKEN_FILE_MISMATCH"


def test_conversion_tokens_cannot_use_the_reference_engine():
    r, _ = convert_scan(CASE["1-pdf-clean"], engine="reference")
    assert r.status_code == 403 and r.json()["code"] == "ENGINE_NOT_APPROVED"


def test_security_lab_tokens_keep_working_and_never_get_receipts():
    data = CASE["1-pdf-clean"]
    r = client.post("/scan?engine=unified", content=data, headers=auth_headers(data))
    body = r.json()
    assert r.status_code == 200 and body["verdict"] == "SAFE" and body["authorization"] == "allow"
    assert body["receipt"] is None
    r = client.post("/scan", content=data, headers=auth_headers(data))  # the Lab's default engine still works
    assert r.status_code == 200 and r.json()["engine"] == "reference" and r.json()["receipt"] is None


def test_no_receipt_without_a_receipt_key(monkeypatch):
    monkeypatch.setattr(receipts, "PRIVATE_KEY", None)
    body = convert_scan(CASE["1-pdf-clean"])[0].json()
    assert body["authorization"] == "allow" and body["receipt"] is None  # no receipt: the Conversion Engine denies
    assert client.get("/health").json()["ready_for_conversion"] is False


# ----------------------------------------------------------------------------- upload limit


def test_upload_limit_is_enforced_for_conversion_scans():
    data = b"%PDF-1.4\n" + b"0" * main.MAX_UPLOAD_BYTES
    r, _ = convert_scan(data)
    assert r.status_code == 413 and r.json()["code"] == "UPLOAD_TOO_LARGE"
    assert main.MAX_UPLOAD_BYTES == worker.MAX_INPUT_BYTES == 10 * 1024 * 1024


def test_upload_limit_cannot_be_bypassed_by_understating_content_length():
    data = b"%PDF-1.4\n" + b"0" * main.MAX_UPLOAD_BYTES

    def chunks():
        yield data
    r = client.post("/scan?engine=unified", content=chunks(), headers={"Authorization": f"Bearer {token(data)}"})
    assert r.status_code == 413 and r.json()["code"] == "UPLOAD_TOO_LARGE"


# ----------------------------------------------------------------------------- receipt verification


def _receipt(data: bytes = b"doc", **outcome) -> str:
    claims = {"scan_request_id": "r", "token_jti": "j" * 32, "sha256": hashlib.sha256(data).hexdigest(),
              "size": len(data), "engine": "unified", "verdict": "SAFE", "authorization": "allow",
              "isolation_verified": True, "reason_codes": []} | outcome
    return receipts.sign(claims, RECEIPT_KEY, now=1_000_000)


def _verify(receipt: str, data: bytes = b"doc", trusted=TRUSTED, now: float = 1_000_100, **kw):
    return receipts.verify(receipt, trusted, sha256=hashlib.sha256(data).hexdigest(), size=len(data), now=now, **kw)


def test_receipt_verifies_and_binds_the_bytes():
    assert _verify(_receipt())["authorization"] == "allow"
    with pytest.raises(receipts.ReceiptError, match="RECEIPT_FILE_MISMATCH"):
        _verify(_receipt(), data=b"dod")
    with pytest.raises(receipts.ReceiptError, match="RECEIPT_FILE_MISMATCH"):
        receipts.verify(_receipt(), TRUSTED, sha256=hashlib.sha256(b"doc").hexdigest(), size=4, now=1_000_100)
    with pytest.raises(receipts.ReceiptError, match="RECEIPT_REQUEST_MISMATCH"):
        _verify(_receipt(), token_jti="k" * 32)


def test_receipt_expires_after_five_minutes():
    receipt = _receipt()
    assert _verify(receipt, now=1_000_299)
    for now in (1_000_300, 1_000_000 - 31):
        with pytest.raises(receipts.ReceiptError, match="RECEIPT_EXPIRED"):
            _verify(receipt, now=now)


def test_tampered_receipts_are_rejected():
    payload, sig = _receipt(verdict="SUSPICIOUS", authorization="consent_required").split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    forged = receipts._b64(json.dumps(claims | {"authorization": "allow", "verdict": "SAFE"}).encode())
    for receipt in (f"{forged}.{sig}", f"{payload}.{sig[:-2]}AA", f"{payload}.", "garbage", ""):
        with pytest.raises(receipts.ReceiptError):
            _verify(receipt)


def test_receipt_with_unverified_isolation_or_authorizing_malicious_is_rejected():
    for outcome in ({"isolation_verified": False}, {"verdict": "MALICIOUS", "authorization": "allow"}):
        with pytest.raises(receipts.ReceiptError, match="RECEIPT_WRONG_TYPE"):
            _verify(_receipt(**outcome))


def test_key_rotation():
    new_key = Ed25519PrivateKey.generate()
    old_id, new_id = receipts.key_id(RECEIPT_KEY.public_key()), receipts.key_id(new_key.public_key())
    old_receipt = _receipt()
    new_receipt = receipts.sign({**json.loads(base64.urlsafe_b64decode(old_receipt.split(".")[0] + "=="))},
                                new_key, now=1_000_000)
    both = {old_id: RECEIPT_KEY.public_key(), new_id: new_key.public_key()}
    assert _verify(old_receipt, trusted=both)["kid"] == old_id  # during the switch, both verify
    assert _verify(new_receipt, trusted=both)["kid"] == new_id
    with pytest.raises(receipts.ReceiptError, match="RECEIPT_UNKNOWN_KEY"):  # old key retired
        _verify(old_receipt, trusted={new_id: new_key.public_key()})
    # A receipt naming the new key but signed by the retired one does not verify.
    payload, sig = old_receipt.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    relabelled = json.dumps(claims | {"kid": new_id}, separators=(",", ":"), sort_keys=True).encode()
    with pytest.raises(receipts.ReceiptError, match="RECEIPT_INVALID_SIGNATURE"):
        _verify(f"{receipts._b64(relabelled)}.{sig}", trusted=both)


def test_receipt_key_matches_the_scan_keys_script_id():
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    der = RECEIPT_KEY.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    assert receipts.key_id(RECEIPT_KEY.public_key()) == hashlib.sha256(der).hexdigest()[:16]


def test_receipt_private_key_never_stays_in_the_environment():
    assert receipts.KEY_ENV not in os.environ
    assert receipts.KEY_ENV not in worker.child_env()


def test_health_reports_conversion_readiness():
    health = client.get("/health").json()
    assert health["ready_for_conversion"] is True and health["conversion_auth_configured"] is True
    assert health["receipt_key_id"] in TRUSTED and health["max_upload_bytes"] == 10 * 1024 * 1024
    assert "PRIVATE" not in json.dumps(health).upper()


# ----------------------------------------------------------------------------- hostile-client review


PINS = {"commit": main.VERSIONS["commit"], "scanners": sorted(main.engine_scanners("unified")),
        "ruleset_sha256": main.VERSIONS["ruleset_sha256"], "engine_ruleset_sha256": main.VERSIONS["engine_ruleset_sha256"],
        "scanner_versions": {k: main.VERSIONS[k] for k in ("yara-x", "oletools", "olefile", "pypdf")}}


def test_a_real_receipt_verifies_against_the_pinned_build():
    data = CASE["1-pdf-clean"]
    r, jti = convert_scan(data)
    claims = receipts.verify(r.json()["receipt"], TRUSTED, sha256=hashlib.sha256(data).hexdigest(), size=len(data),
                             token_jti=jti, pins=PINS)
    assert claims["authorization"] == "allow"


@pytest.mark.parametrize("pin, value", [("commit", "0" * 40), ("scanners", ["yara-x"]),
                                        ("scanner_versions", {"pypdf": "6.19.0"}), ("ruleset_sha256", "f" * 64)])
def test_a_different_build_fails_verification(pin, value):
    data = CASE["1-pdf-clean"]
    r, jti = convert_scan(data)
    with pytest.raises(receipts.ReceiptError, match="RECEIPT_BUILD_MISMATCH"):
        receipts.verify(r.json()["receipt"], TRUSTED, sha256=hashlib.sha256(data).hexdigest(), size=len(data),
                        token_jti=jti, pins=PINS | {pin: value})


def test_missing_version_claims_or_another_engine_fail_verification():
    with pytest.raises(receipts.ReceiptError, match="RECEIPT_WRONG_TYPE"):  # _receipt() carries no versions
        _verify(_receipt(), pins={"scanner_versions": PINS["scanner_versions"]})
    with pytest.raises(receipts.ReceiptError, match="RECEIPT_BUILD_MISMATCH"):
        _verify(_receipt(engine="reference"))


def test_outcome_data_cannot_override_reserved_receipt_claims():
    hostile = {k: "x" for k in ("typ", "iss", "aud", "kid", "rid")} | {"iat": 0, "exp": 10**12}
    claims = _verify(_receipt(**hostile))
    assert claims["kid"] in TRUSTED and claims["typ"] == receipts.TYPE and claims["aud"] == receipts.AUDIENCE
    assert claims["exp"] - claims["iat"] == receipts.LIFETIME_SECONDS and claims["rid"] != "x"


@pytest.mark.parametrize("payload", [b"[1, 2]", b'{"kid": ["a"]}', b"not json", b'"text"'])
def test_malformed_receipts_only_ever_raise_receipt_errors(payload):
    for receipt in (f"{receipts._b64(payload)}.{receipts._b64(b'sig')}", f"{receipts._b64(payload)}.!!", "a.b.c"):
        with pytest.raises(receipts.ReceiptError):
            _verify(receipt)


def test_a_lab_token_claiming_the_conversion_issuer_gets_no_receipt():
    data = CASE["1-pdf-clean"]
    claims = {"aud": auth.AUDIENCE, "iat": int(__import__("time").time()), "jti": "a" * 32, "issuer": "conversion",
              "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    claims["exp"] = claims["iat"] + 120
    payload = json.dumps(claims).encode()
    from tests.scan_client import KEY as LAB_KEY
    lab_token = f"{receipts._b64(payload)}.{receipts._b64(LAB_KEY.sign(payload))}"
    r = client.post("/scan?engine=unified", content=data, headers={"Authorization": f"Bearer {lab_token}"})
    assert r.status_code == 200 and r.json()["receipt"] is None


def test_shared_lab_and_conversion_key_is_not_ready_and_issues_no_receipt(monkeypatch):
    monkeypatch.setattr(auth, "PUBLIC_KEY", CONVERSION_KEY.public_key())
    assert client.get("/health").json()["ready_for_conversion"] is False
    assert convert_scan(CASE["1-pdf-clean"])[0].json()["receipt"] is None


def test_a_malicious_answer_stays_denied_whatever_the_body_says():
    data = CASE["5b-pdf-auto-js-exports-attachment"]
    r, jti = convert_scan(data)
    body = r.json() | {"verdict": "SAFE", "authorization": "allow"}  # a client editing the JSON
    claims = verified(data, body, jti)
    assert (claims["verdict"], claims["authorization"]) == ("MALICIOUS", "deny")


def test_one_token_buys_one_scan_even_for_other_bytes():
    data = CASE["1-pdf-clean"]
    t = token(data)
    assert client.post("/scan?engine=unified", content=data, headers={"Authorization": f"Bearer {t}"}).status_code == 200
    for body in (data, data + b"\n"):
        r = client.post("/scan?engine=unified", content=body, headers={"Authorization": f"Bearer {t}"})
        assert r.status_code == 401 and r.json()["code"] == "AUTH_REPLAYED"


def test_logs_carry_no_document_content_filename_token_or_receipt(caplog):
    marker = b"FM-PRIVATE-MARKER-7f3a"
    data = CASE["1-pdf-clean"] + b"% " + marker + b"\n"
    t = token(data)
    with caplog.at_level("DEBUG"):
        r = client.post("/scan?engine=unified", content=data,
                        headers={"Authorization": f"Bearer {t}", "X-Filename": "customer-contract.pdf"})
        client.post("/scan?engine=unified", content=data, headers={"Authorization": "Bearer bad.token"})
    text = caplog.text
    assert r.status_code == 200 and r.json()["receipt"]
    for secret in (marker.decode(), "customer-contract", t, r.json()["receipt"], hashlib.sha256(data).hexdigest()):
        assert secret not in text
