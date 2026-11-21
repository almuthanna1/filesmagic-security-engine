import pytest

from app import auth, main, worker
from app import engine as unified_engine
from app.engine import vba_analysis, vba_chains
from tests.scan_client import KEY


async def in_process(data: bytes, engine: str = "unified"):
    # The unified engine (as monkeypatched by a test) with its correlation, in this process. The
    # real isolated worker is exercised in test_security.py and test_api_engines.py.
    return unified_engine.correlate(worker.analyse(unified_engine.SCANNERS, data))


@pytest.fixture(autouse=True)
def engine(monkeypatch):
    monkeypatch.setattr(auth, "PUBLIC_KEY", KEY.public_key())
    monkeypatch.setattr(main, "run_scan", in_process)
    auth.reset()
    # The VBA extraction/analysis caches are keyed by bytes; tests patch the extractor under them.
    vba_analysis.extract.cache_clear()
    vba_chains.analyse_cached.cache_clear()
    yield
    auth.reset()
    vba_analysis.extract.cache_clear()
    vba_chains.analyse_cached.cache_clear()
