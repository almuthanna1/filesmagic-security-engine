"""Synthetic-only live acceptance of FilesMagic's server-side security policy.

Runs only after the operator turns on enforcement. Test materials are inert:
the PDF JavaScript snippets are non-networking structural scanner fixtures and
are NEVER executed. This script sends no secret keys or user documents.
"""
import io
import json
import time
import uuid
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from PIL import Image
from tests.pdf_fixtures import attachment, js_action, make_pdf

HOST = "https://api.filesmagic.com"
TIMEOUT = 150


def post(path, files, fields):
    boundary = "fm-accept-" + uuid.uuid4().hex
    parts = []
    for key, value in fields:
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n').encode())
    for name, filename, typ, data in files:
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\nContent-Type: {typ}\r\n\r\n').encode())
        parts.append(data + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    req = Request(HOST + path, data=b"".join(parts), method="POST", headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "User-Agent": "FilesMagic-Inert-Enforcement-Acceptance/1",
    })
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, dict(resp.headers), resp.read(4_000_000)
    except HTTPError as err:
        return err.code, dict(err.headers), err.read(100_000)


def parse(response):
    status, headers, body = response
    try:
        data = json.loads(body) if status >= 400 else None
    except Exception:
        raise AssertionError(f"unexpected non-JSON {status} response: {body[:400]!r}")
    return status, headers, data


def code(response):
    status, _, body = parse(response)
    return status, (body or {}).get("error", {}).get("code")


def rotate(pdf, consent=None):
    fields = [("degrees", "90")]
    if consent:
        fields.append(("scan_consent", consent))
    return post("/api/v1/pdf/rotate", [("file", "synthetic.pdf", "application/pdf", pdf)], fields)


def log_result(name, response):
    status, headers, _ = response
    print(f"{name}: HTTP {status}, x-filesmagic-security={headers.get('X-FilesMagic-Security', '-')}, request_id={headers.get('X-Request-ID', '-')}", flush=True)


def check():
    attach, objects = attachment("notes.txt")
    suspicious = make_pdf(catalog_extra="/OpenAction 7 0 R " + attach, objects={
        **objects, 7: js_action("app.alert(1);")
    })
    # A scanner-only synthetic fixture. This is never opened in a PDF viewer.
    # The attachment consists of inert text, and the JavaScript has no network targets.
    malicious = make_pdf(catalog_extra="/OpenAction 7 0 R " + attach, objects={
        **objects, 7: js_action('this.exportDataObject\\({cName: "f", nLaunch: 0}\\);')
    })
    safe = make_pdf()

    # Render may be finishing its environment-variable redeploy. Do not proceed
    # until the non-SAFE document is actually gated (not merely scanned).
    flag = None
    for attempt in range(9):
        response = rotate(suspicious)
        status, err = code(response)
        log_result("enforcement gate probe", response)
        if (status, err) == (409, "SCAN_CONSENT_REQUIRED"):
            flag = response
            break
        if status == 200 or (status == 503 and err in ("SCAN_UNAVAILABLE", "SERVER_BUSY")):
            if attempt < 8:
                time.sleep(13)
                continue
        raise AssertionError(f"unexpected enforcement probe: HTTP {status}, code={err}")
    assert flag is not None, "backend never activated mandatory security enforcement"

    # A safe document is authorized and converted, marked with a header.
    result = rotate(safe)
    log_result("SAFE rotate", result)
    assert result[0] == 200 and result[1].get("X-FilesMagic-Security") == "SAFE", "SAFE must have valid receipt and security header"
    assert result[2].startswith(b"%PDF-"), "SAFE rotate did not produce a PDF"

    # A forged handle must not unlock a suspicious document.
    forged = rotate(suspicious, consent="x" * 43)
    log_result("forged consent", forged)
    assert code(forged) == (409, "SCAN_CONSENT_REQUIRED"), "forged handle bypassed gate"

    # A real handle is issued for the SAME bytes, once.
    _, _, body = parse(flag)
    assert isinstance(body.get("security"), dict)
    files = body["security"].get("files")
    assert isinstance(files, list) and len(files) == 1
    one = files[0]
    assert one["verdict"] == "SUSPICIOUS" and one.get("findings")
    handle = one.get("consent")
    assert isinstance(handle, str) and len(handle) > 16 and 0 < one["consent_expires_in"] <= 300
    print("SUSPICIOUS: HTTP 409 with user-visible findings and short-lived consent", flush=True)
    approved = rotate(suspicious, consent=handle)
    log_result("explicit consent", approved)
    assert approved[0] == 200 and approved[1].get("X-FilesMagic-Security") == "ACKNOWLEDGED"
    assert approved[2].startswith(b"%PDF-"), "approved rotate did not produce PDF"

    replayed = rotate(suspicious, consent=handle)
    log_result("replay of consumed handle", replayed)
    assert code(replayed) == (409, "SCAN_CONSENT_REQUIRED"), "replayed consent must not authorize"

    # Malicious: NEVER issue consent, even when a handle is forged.
    denied = rotate(malicious)
    log_result("MALICIOUS denial", denied)
    status, _, body = parse(denied)
    assert (status, body.get("error", {}).get("code")) == (422, "SCAN_BLOCKED"), f"malicious was not blocked: {status}, {body}"
    flagged = body.get("security", {}).get("files", [])
    assert flagged and flagged[0]["verdict"] == "MALICIOUS", f"expected MALICIOUS, got {flagged}"
    assert all("consent" not in x for x in flagged)
    forged_malicious = rotate(malicious, consent="A" * 43)
    log_result("MALICIOUS forged override denial", forged_malicious)
    assert code(forged_malicious) == (422, "SCAN_BLOCKED")

    # Merge mixed inputs: no file is parsed if any member has a deny verdict.
    merged = post("/api/v1/pdf/merge", [
        ("files", "a.pdf", "application/pdf", safe),
        ("files", "b.pdf", "application/pdf", malicious),
    ], [])
    log_result("merge SAFE + MALICIOUS", merged)
    assert code(merged) == (422, "SCAN_BLOCKED"), "mixed merge must be blocked in full"

    # Incomplete scan from an encrypted PDF is a document issue, not an outage.
    from tests.pdf_fixtures import encrypted_pdf
    encrypted = encrypted_pdf("not-a-real-password")
    incomplete = rotate(encrypted)
    log_result("encrypted / incomplete PDF", incomplete)
    assert code(incomplete) == (409, "SCAN_CONSENT_REQUIRED"), "document-limited scan should require acknowledgment"
    incomplete_body = parse(incomplete)[2]
    assert incomplete_body["security"]["files"][0]["verdict"] in ("UNABLE_TO_SCAN", "SUSPICIOUS")

    # Unscanned media must remain usable, and must not claim it was scanned.
    buf = io.BytesIO()
    Image.new("RGB", (2, 2), (12, 34, 56)).save(buf, format="PNG")
    image = post("/api/v1/convert", [("file", "sample.png", "image/png", buf.getvalue())],
                 [("source", "png"), ("target", "jpg")])
    log_result("unscanned PNG -> JPG", image)
    assert image[0] == 200 and image[2].startswith(b"\xff\xd8"), "PNG->JPG changed unexpectedly"
    assert not image[1].get("X-FilesMagic-Security"), "PNG must not claim a security scan"

    print("ALL PRODUCTION ENFORCEMENT ACCEPTANCE CASES PASSED", flush=True)


if __name__ == "__main__":
    check()
