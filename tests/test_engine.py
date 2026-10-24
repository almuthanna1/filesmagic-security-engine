import pytest
from fastapi.testclient import TestClient

from app import main
from app.decision import decide
from app.main import app
from app.models import Finding, Severity, Verdict
from tests.scan_client import auth_headers, post_scan

client = TestClient(app)


def finding(severity: Severity) -> Finding:
    return Finding(scanner="test", category="test", severity=severity, description="test finding")


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["scanners_registered"] == len(main.SCANNERS) == 3  # YARA-X, Office, PDF
    assert r.json()["scanners_ready"] == 3


def test_health_counts_registered_scanners(monkeypatch):
    monkeypatch.setattr(main, "SCANNERS", [])
    body = client.get("/health").json()
    assert body["scanners_registered"] == body["scanners_ready"] == 0


def test_scan_without_scanners_is_not_safe(monkeypatch):
    monkeypatch.setattr(main, "SCANNERS", [])
    r = post_scan(client, b"hello world", "hello.txt")
    assert r.status_code == 200
    body = r.json()
    assert body["filename"] == "hello.txt"
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN
    assert body["verdict"] != Verdict.SAFE
    assert body["findings"] == []


def test_scan_requires_token():
    assert client.post("/scan", content=b"x").status_code == 401


def test_scan_combines_scanner_results(monkeypatch):
    class Clean:
        name = "clean"

        def scan(self, filename, data):
            return []

    class Broken:
        name = "broken"

        def scan(self, filename, data):
            raise RuntimeError("scanner crashed")

    class Flags:
        name = "flags"

        def scan(self, filename, data):
            return [finding(Severity.HIGH)]

    def post():
        return post_scan(client, b"x", "a.bin").json()["verdict"]

    monkeypatch.setattr(main, "SCANNERS", [Clean()])
    assert post() == Verdict.SAFE
    monkeypatch.setattr(main, "SCANNERS", [Clean(), Broken()])
    assert post() == Verdict.UNABLE_TO_SCAN
    monkeypatch.setattr(main, "SCANNERS", [Broken(), Flags()])
    assert post() == Verdict.MALICIOUS


def test_oversized_upload_rejected_by_exact_check(monkeypatch):
    # No Content-Length (chunked upload): caught while the body is streamed.
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 100)
    data = b"x" * 101
    r = client.post("/scan", content=iter([data[:60], data[60:]]), headers=auth_headers(data))
    assert r.status_code == 413
    assert "too large" in r.json()["detail"]


def test_oversized_upload_rejected_before_body_is_read(monkeypatch):
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 100)
    monkeypatch.setattr(main, "SCANNERS", [])  # never reached
    data = b"x" * 101
    r = client.post("/scan", content=data, headers=auth_headers(data) | {"Origin": "http://localhost:3000"})
    assert r.status_code == 413
    assert "too large" in r.json()["detail"]
    assert r.headers["access-control-allow-origin"] == "http://localhost:3000"  # browser can read it


def test_upload_at_limit_is_accepted(monkeypatch):
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 100)
    monkeypatch.setattr(main, "SCANNERS", [])
    assert post_scan(client, b"x" * 100).status_code == 200


def test_cors_allows_only_listed_origins():
    allowed = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:3000"

    blocked = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in blocked.headers


def test_parse_cors_origins():
    assert main.parse_cors_origins(" https://lab.example/ , http://localhost:3000,") == [
        "https://lab.example",
        "http://localhost:3000",
    ]
    with pytest.raises(ValueError):
        main.parse_cors_origins("https://lab.example,*")


@pytest.mark.parametrize(
    "severities, run, failed, expected",
    [
        ([], 0, 0, Verdict.UNABLE_TO_SCAN),  # no scanners -> never SAFE
        ([], 2, 0, Verdict.SAFE),
        ([], 2, 1, Verdict.UNABLE_TO_SCAN),  # a scanner failed -> never SAFE
        ([Severity.INFO], 1, 0, Verdict.SAFE),
        ([Severity.INFO], 0, 0, Verdict.UNABLE_TO_SCAN),
        ([Severity.LOW], 1, 0, Verdict.SUSPICIOUS),
        ([Severity.MEDIUM], 1, 1, Verdict.SUSPICIOUS),
        ([Severity.HIGH], 1, 0, Verdict.MALICIOUS),
        ([Severity.LOW, Severity.CRITICAL], 2, 0, Verdict.MALICIOUS),
    ],
)
def test_decide(severities, run, failed, expected):
    assert decide([finding(s) for s in severities], run, failed) == expected
