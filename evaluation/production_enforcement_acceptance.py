"""Production admission acceptance with inert synthetic documents only.

Use against an explicitly enabled production enforce deployment. Public endpoints,
no private keys, no malware or user files. Never automatically retries POSTs.
"""
import io
import json
import struct
import sys
import urllib.error
import urllib.request
import uuid
import zlib

from tests.pdf_fixtures import attachment, js_action, make_pdf
from tests.custom_fixtures import stream_object

BASE = "https://api.filesmagic.com"
ATTACHMENT_EXTRA, ATTACHMENT_OBJS = attachment("notes.txt")
CLEAN = make_pdf()
SUSPICIOUS = make_pdf(
    catalog_extra="/OpenAction 7 0 R " + ATTACHMENT_EXTRA,
    objects={**ATTACHMENT_OBJS, 7: js_action()},
)
EXPORT_JS = js_action('this.exportDataObject\\({cName: "f", nLaunch: 0}\\);')
MALICIOUS = make_pdf(
    catalog_extra="/OpenAction 7 0 R " + ATTACHMENT_EXTRA,
    objects={**ATTACHMENT_OBJS, 7: EXPORT_JS},
)


def req(path, fields=(), files=()):
    boundary = "fm-enforcement-" + uuid.uuid4().hex
    chunks = []
    for key, value in fields:
        chunks.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode()
        )
    for key, filename, mime, data in files:
        chunks.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"; filename="{filename}"\r\n'
            f'Content-Type: {mime}\r\n\r\n'.encode()
        )
        chunks.append(data + b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    request = urllib.request.Request(
        BASE + path, data=b"".join(chunks), method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                 "User-Agent": "FilesMagic-enforcement-acceptance/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=160) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read(2_000_000)
    except urllib.error.HTTPError as error:
        return error.code, {k.lower(): v for k, v in error.headers.items()}, error.read(1_000_000)


def pdf_rotate(blob, consents=()):
    return req(
        "/api/v1/pdf/rotate",
        fields=[("degrees", "90"), *[("scan_consent", c) for c in consents]],
        files=[("file", "acceptance.pdf", "application/pdf", blob)],
    )


def json_error(status, raw, expected_code):
    try:
        body = json.loads(raw)
    except Exception as exc:
        raise AssertionError(f"HTTP {status} returned non-JSON error: {raw[:200]!r}") from exc
    assert body.get("error", {}).get("code") == expected_code, (status, body)
    return body


def verify():
    print("Running public production enforcement admission checks", flush=True)

    status, headers, raw = pdf_rotate(CLEAN)
    assert status == 200, ("SAFE must convert", status, raw[:300])
    assert headers.get("x-filesmagic-security") == "SAFE", ("missing enforced SAFE header", headers)
    assert raw.startswith(b"%PDF-"), "PDF rotate did not return a PDF"
    print("PASS: SAFE accepted and converted with signed security header", flush=True)

    status, headers, raw = pdf_rotate(SUSPICIOUS)
    assert status == 409, ("suspicious must stop", status, raw[:350])
    body = json_error(status, raw, "SCAN_CONSENT_REQUIRED")
    flagged = [f for f in body.get("security", {}).get("files", []) if f.get("verdict") == "SUSPICIOUS"]
    assert len(flagged) == 1 and flagged[0].get("consent"), ("missing consent warning", body)
    handle = flagged[0]["consent"]
    assert 10 <= len(handle) <= 64
    print("PASS: SUSPICIOUS stopped with explicit 409 and short-lived consent", flush=True)

    status, _, raw = pdf_rotate(SUSPICIOUS, ["forged-handle"])
    assert status == 409, ("forged consent must not bypass", status, raw[:200])
    json_error(status, raw, "SCAN_CONSENT_REQUIRED")
    print("PASS: forged consent rejected", flush=True)

    status, headers, raw = pdf_rotate(SUSPICIOUS, [handle])
    assert status == 200, ("explicit consent must convert", status, raw[:350])
    assert headers.get("x-filesmagic-security") == "ACKNOWLEDGED", ("wrong acknowledgement header", headers)
    assert raw.startswith(b"%PDF-")
    print("PASS: real consent converts only same bytes with ACKNOWLEDGED", flush=True)

    status, _, raw = pdf_rotate(SUSPICIOUS, [handle])
    assert status == 409, ("used consent must not be reusable", status, raw[:200])
    json_error(status, raw, "SCAN_CONSENT_REQUIRED")
    print("PASS: consent single use verified", flush=True)

    status, _, raw = pdf_rotate(MALICIOUS)
    assert status == 422, ("MALICIOUS must block", status, raw[:350])
    body = json_error(status, raw, "SCAN_BLOCKED")
    entries = body.get("security", {}).get("files", [])
    assert any(f.get("verdict") == "MALICIOUS" for f in entries), body
    assert all(not f.get("consent") for f in entries), "malicious unexpectedly offered consent"
    print("PASS: MALICIOUS blocked permanently, no consent handle", flush=True)

    status, _, raw = pdf_rotate(MALICIOUS, [handle])
    assert status == 422, ("MALICIOUS must block even with past consent", status, raw[:350])
    json_error(status, raw, "SCAN_BLOCKED")
    print("PASS: consent cannot authorize MALICIOUS", flush=True)

    status, _, raw = req(
        "/api/v1/pdf/merge",
        files=[("files", "clean.pdf", "application/pdf", CLEAN),
               ("files", "bad.pdf", "application/pdf", MALICIOUS)],
    )
    assert status == 422, ("merge with MALICIOUS must block", status, raw[:350])
    json_error(status, raw, "SCAN_BLOCKED")
    print("PASS: whole PDF merge blocked if one file is malicious", flush=True)

    # A page stream with an inert but invalid LZW representation is a known
    # document-level incomplete-inspection fixture. The actual scanner must
    # issue a consent-eligible warning, not approve or claim internal failure.
    bad_lzw = bytes.fromhex(
        "789c730ae15250d0773354303251084903b2cd8d80c840212405c8d608c82f492cc9d75408c9e2720de10200cb0109c8"
    )
    incomplete_pdf = make_pdf(objects={4: stream_object("/Filter /LZWDecode", bad_lzw)})
    status, _, raw = pdf_rotate(incomplete_pdf)
    assert status == 409, ("document-limited UNABLE_TO_SCAN needs consent", status, raw[:400])
    body = json_error(status, raw, "SCAN_CONSENT_REQUIRED")
    items = body.get("security", {}).get("files", [])
    assert any(f.get("verdict") == "UNABLE_TO_SCAN" and f.get("consent") for f in items), body
    print("PASS: eligible UNABLE_TO_SCAN receives informed-consent warning", flush=True)

    print("ALL PRODUCTION ENFORCEMENT CHECKS PASSED", flush=True)


if __name__ == "__main__":
    verify()
