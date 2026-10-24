import pytest

from app import auth, main, worker
from tests.scan_client import KEY


async def in_process(data: bytes):
    # Runs main.SCANNERS (as monkeypatched by a test) in this process. The real isolated
    # worker is exercised in test_security.py.
    return worker.analyse(main.SCANNERS, data)


@pytest.fixture(autouse=True)
def engine(monkeypatch):
    monkeypatch.setattr(auth, "PUBLIC_KEY", KEY.public_key())
    monkeypatch.setattr(main, "run_scan", in_process)
    auth.reset()
    yield
    auth.reset()
