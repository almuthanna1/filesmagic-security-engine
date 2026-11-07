import pytest

from app import auth, main, worker
from app import engine as unified_engine
from tests.scan_client import KEY


async def in_process(data: bytes, engine: str = "reference"):
    # Runs main.SCANNERS (as monkeypatched by a test), or the unified engine with its correlation,
    # in this process. The real isolated worker is exercised in test_security.py and test_api_engines.py.
    if engine == "unified":
        return unified_engine.correlate(worker.analyse(unified_engine.SCANNERS, data))
    return worker.analyse(main.SCANNERS, data)


@pytest.fixture(autouse=True)
def engine(monkeypatch):
    monkeypatch.setattr(auth, "PUBLIC_KEY", KEY.public_key())
    monkeypatch.setattr(main, "run_scan", in_process)
    auth.reset()
    yield
    auth.reset()
