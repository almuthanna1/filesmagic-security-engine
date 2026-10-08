import pytest
from fastapi.testclient import TestClient

from app import main
from app.decision import decide
from app.main import app
from app.models import Finding, Severity, Verdict

client = TestClient(app)


def finding(severity: Severity) -> Finding:
    return Finding(scanner="test", category="test", severity=severity, description="test finding")


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_scan_accepts_upload_and_is_not_safe():
    r = client.post("/scan", files={"file": ("hello.txt", b"hello world", "text/plain")})
    assert r.status_code == 200
    body = r.json()
    assert body["filename"] == "hello.txt"
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN
    assert body["verdict"] != Verdict.SAFE
    assert body["findings"] == []


def test_scan_requires_file():
    assert client.post("/scan").status_code == 422


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
        return client.post("/scan", files={"file": ("a.bin", b"x")}).json()["verdict"]

    monkeypatch.setattr(main, "SCANNERS", [Clean()])
    assert post() == Verdict.SAFE
    monkeypatch.setattr(main, "SCANNERS", [Clean(), Broken()])
    assert post() == Verdict.UNABLE_TO_SCAN
    monkeypatch.setattr(main, "SCANNERS", [Broken(), Flags()])
    assert post() == Verdict.MALICIOUS


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
