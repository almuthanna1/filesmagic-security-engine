"""EICAR / Didier Stevens study tooling: acquisition checks, sample preparation, benchmark.

No network access and no EICAR content here: downloads go through an injected fake fetcher
with synthetic bytes, and the benchmark runs on the locally generated inert samples only.
"""

import csv
import hashlib
import io
import json
import zipfile

import pytest

from app import worker
from evaluation import acquire, benchmark, prepare_samples
from evaluation.evaluate import EvaluationAborted, load_manifest
from tests.custom_fixtures import obfuscated_javascript_pdf


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ============================================================================= allowlist


def test_the_allowlist_is_pinned_https_only_and_excludes_the_dropper():
    resources = acquire.load_allowlist()
    assert {r["id"] for r in resources} == {"eicar-com-txt", "eicar-com-zip", "ds-pdfid", "ds-mpdf",
                                            "ds-make-pdf-javascript", "ds-make-pdf-embedded"}
    for r in resources:
        assert r["url"].startswith("https://") and r["active_content"] and r["license"]
        assert r["sha256"] or all(m["sha256"] for m in r["members"].values())
    excluded = json.loads(acquire.ALLOWLIST.read_text(encoding="utf-8"))["excluded"]
    assert any("macro dropper" in e["what"] for e in excluded)


GOOD = {"id": "x", "source": "s", "page": "https://secure.eicar.org/", "url": "https://secure.eicar.org/x.txt",
        "kind": "file", "save_as": "x.txt", "size": 5, "sha256": "0" * 64, "role": "r", "active_content": "none", "license": "l"}


@pytest.mark.parametrize("change, message", [
    ({"url": "http://secure.eicar.org/x.txt"}, "not HTTPS"),
    ({"url": "https://example.com/x.txt"}, "is not allowed"),
    ({"url": "https://secure.eicar.org/x.txt?a=1"}, "query or fragment"),
    ({"sha256": None}, "needs a pinned sha256"),
    ({"save_as": "../x.txt"}, "simple file name"),
    ({"kind": "zip", "sha256": None}, "expected members"),
    ({"size": 10 * 1024 * 1024}, "too large"),
])
def test_the_allowlist_rejects_anything_unexpected(tmp_path, change, message):
    path = tmp_path / "allowlist.json"
    path.write_text(json.dumps({"resources": [GOOD | change]}))
    with pytest.raises(acquire.AcquisitionError, match=message):
        acquire.load_allowlist(path)


# ============================================================================= acquisition


def resource(data: bytes, **kw) -> dict:
    return GOOD | {"size": len(data), "sha256": sha(data)} | kw


def test_verified_download_is_stored_with_provenance(tmp_path):
    data = b"inert"
    records = acquire.acquire([resource(data)], tmp_path / "cache", fetcher=lambda url: (data, 200))
    assert (tmp_path / "cache" / "x" / "x.txt").read_bytes() == data
    [rec] = records
    assert rec["url"] == GOOD["url"] and rec["sha256"] == sha(data) and rec["size"] == 5 and rec["retrieved_utc"]
    assert json.loads((tmp_path / "cache" / "provenance.json").read_text())["resources"][0]["id"] == "x"


@pytest.mark.parametrize("served, message", [(b"inert!", "size 6"), (b"INERT", "does not match the pinned")])
def test_download_that_fails_its_pins_is_not_kept(tmp_path, served, message):
    with pytest.raises(acquire.AcquisitionError, match=message):
        acquire.acquire([resource(b"inert")], tmp_path / "cache", fetcher=lambda url: (served, 200))
    assert not (tmp_path / "cache" / "x").exists()


def test_redirects_are_refused():
    with pytest.raises(acquire.AcquisitionError, match="refused redirect"):
        acquire._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://elsewhere.test/")


def test_acquisition_cache_inside_the_repository_is_refused():
    with pytest.raises(acquire.AcquisitionError, match="inside the repository"):
        acquire.outside_repository(acquire.REPO_ROOT / "evaluation" / "cache")


def make_zip(members: dict, encrypted: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in members.items():
            zf.writestr(name, content)
    data = bytearray(buf.getvalue())
    if encrypted:  # zipfile cannot write encrypted entries: set the flag bit as one would read it
        for sig, flags_at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = data.find(sig)
            data[pos + flags_at] |= 0x1
    return bytes(data)


ARCHIVE = {"kind": "zip", "sha256": None, "members": {"note.txt": {"size": 5, "sha256": sha(b"inert")}}}


def test_archive_members_are_verified_and_extracted(tmp_path):
    data = make_zip({"note.txt": b"inert"})
    acquire.acquire([resource(data, **ARCHIVE)], tmp_path / "cache", fetcher=lambda url: (data, 200))
    assert (tmp_path / "cache" / "x" / "extracted" / "note.txt").read_bytes() == b"inert"


@pytest.mark.parametrize("members, kw, message", [
    ({"../note.txt": b"inert"}, {}, "unsafe member path"),
    ({"dir/note.txt": b"inert"}, {}, "unsafe member path"),
    ({"note.txt": b"inert", "extra.exe": b"x"}, {}, "unexpected member"),
    ({"note.txt": b"inert"}, {"encrypted": True}, "password-protected"),
    ({"note.txt": b"INERT"}, {}, "does not match"),
    ({"note.txt": b"inert but longer"}, {}, "declares 16 bytes"),
    ({"other.txt": b"inert"}, {}, "unexpected member"),
])
def test_unsafe_or_unexpected_archives_are_rejected(members, kw, message):
    data = make_zip(members, **kw)
    with pytest.raises(acquire.AcquisitionError, match=message):
        acquire.verify(resource(data, **ARCHIVE), data)


def test_archive_missing_an_expected_member_is_rejected():
    two = ARCHIVE | {"members": ARCHIVE["members"] | {"b.txt": {"size": 1, "sha256": sha(b"b")}}}
    data = make_zip({"note.txt": b"inert"})
    with pytest.raises(acquire.AcquisitionError, match="lacks expected members: b.txt"):
        acquire.verify(resource(data, **two), data)


def test_dry_run_downloads_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(acquire, "fetch", lambda url: pytest.fail("network used in a dry run"))
    assert acquire.main(["--out", str(tmp_path / "cache"), "--dry-run"]) == 0
    assert "Dry run: nothing downloaded" in capsys.readouterr().out


# ============================================================================= preparation


@pytest.fixture
def prepared(tmp_path):
    out = tmp_path / "samples"
    record = prepare_samples.prepare(out)
    return out, record


def test_local_preparation_builds_a_valid_labelled_manifest(prepared):
    out, record = prepared
    assert record["by_source"] == {"generated-local": 10, "generated-didier-stevens": 0, "downloaded-eicar": 0}
    assert len(record["not_built"]) == 2  # without a verified cache, nothing acquired is used
    rows = load_manifest(out / "manifest.csv", out)
    assert {r["ground_truth"] for r in rows} == {"BENIGN"}
    by_id = {r["sample_id"]: r for r in rows}
    assert by_id["pdf-js-obfuscated-local"]["tags"] == "expect:pdf-javascript;expect:pdf-auto-action;expect:pdf-name-obfuscation"
    assert by_id["docx-clean-local"]["tags"] == "expect:none"
    assert by_id["pdf-js-openaction-local"]["active_content"] == "yes"


def test_preparation_needs_a_new_directory_outside_the_repository(prepared, tmp_path):
    with pytest.raises(prepare_samples.PreparationError, match="not empty"):
        prepare_samples.prepare(prepared[0])
    with pytest.raises(acquire.AcquisitionError, match="inside the repository"):
        prepare_samples.prepare(acquire.REPO_ROOT / "evaluation" / "samples")


def test_cached_tool_that_fails_its_pin_stops_preparation(tmp_path):
    (tmp_path / "cache" / "ds-pdfid").mkdir(parents=True)
    (tmp_path / "cache" / "ds-pdfid" / "pdfid.py").write_text("print('tampered')")
    with pytest.raises(prepare_samples.PreparationError, match="ds-pdfid: cached file fails verification"):
        prepare_samples.prepare(tmp_path / "samples", tmp_path / "cache")


@pytest.mark.parametrize("flag", ["-a", "--autoopen", "-b", "--button"])
def test_launch_options_of_make_pdf_embedded_are_refused(tmp_path, flag):
    with pytest.raises(prepare_samples.PreparationError, match="launch JavaScript"):
        prepare_samples.run_tool(tmp_path, ["make-pdf-embedded.py", flag, "note.txt", "out.pdf"])


# ============================================================================= benchmark


def test_worker_reports_each_scanners_duration():
    from app.scanners import SCANNERS

    report = worker.analyse(SCANNERS, obfuscated_javascript_pdf())
    assert all(s.duration_ms is not None and s.duration_ms >= 0 for s in report.scanners)


def test_benchmark_records_per_scanner_findings_features_and_timing(prepared, tmp_path):
    out, _ = prepared
    benchmark.run(out / "manifest.csv", out, tmp_path / "run", trials=2, require_isolation=False)
    results = {r["sample_id"]: r for r in json.loads((tmp_path / "run" / "results.json").read_text())["samples"]}

    obfuscated = results["pdf-js-obfuscated-local"]["features"]
    assert obfuscated["pdf-javascript"] == {"yara-x": "no", "pdf": "yes", "office": "—", "custom": "—"}
    assert obfuscated["pdf-name-obfuscation"]["custom"] == "yes"
    template = results["docx-external-template-local"]["features"]["office-external-autoload"]
    assert template["office"] == "yes" and template["pdf"] == "—"
    for r in results.values():
        assert r["trials"] == 2 and r["deterministic"] and len(r["timing_ms"]["worker_total"]) == 2
        assert all(len(s["duration_ms"]) == 2 for s in r["scanners"].values())
        if r["control"] == "negative":
            assert r["verdict"] == "SAFE" and not any(s["non_info_findings"] for s in r["scanners"].values())

    summary = json.loads((tmp_path / "run" / "summary.json").read_text())
    assert summary["comparisons"]["false_positive_candidates"] == []
    assert ["pdf-js-obfuscated-local", "pdf-name-obfuscation"] in summary["comparisons"]["detected_only_by_custom"]
    assert summary["timing"]["scanner:office"]["n"] == 2 * 6  # six Office samples, two trials each
    with (tmp_path / "run" / "timings.csv").open() as f:
        assert len(list(csv.DictReader(f))) == 2 * 10
    report = (tmp_path / "run" / "report.md").read_text(encoding="utf-8")
    assert "NOT A VALID RESEARCH RUN" in report and "| pdf-javascript | 1/3 | 3/3 | — | — | not run |" in report


# ============================================================================= research-run gates


def test_host_with_a_usable_route_is_not_offline():
    default_route = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nenp0s3\t00000000\t0202000A\t0003\t0\t0\t100\t00000000\n"
    assert benchmark.host_network(lambda p: default_route if p.endswith("/route") else "")["offline"] is False
    assert benchmark.host_network(lambda p: "Iface\tDestination\n" if p.endswith("/route") else "")["offline"] is True


def test_dependency_drift_is_detected(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("pypdf==0.0.1\nwin_unicode_console==0.5; platform_system == \"Windows\"\n")
    [drift] = benchmark.dependency_drift(req)
    assert drift.startswith("pypdf: required 0.0.1, installed ")


def test_strict_run_aborts_before_reading_the_manifest(tmp_path):
    # This host is not a verified-offline Linux VM, and the tree is not the expected commit.
    with pytest.raises(EvaluationAborted):
        benchmark.run(tmp_path / "no-such-manifest.csv", tmp_path, tmp_path / "run", expect_commit="0" * 40)
    status = json.loads((tmp_path / "run" / "run_status.json").read_text())
    assert status["status"] == "aborted_environment" and status["reason"]


def test_pdfid_keywords_map_to_features():
    ref = {"keywords": {"/JavaScript": {"count": 1, "hexcodecount": 1}, "/OpenAction": {"count": 1, "hexcodecount": 0}}}
    assert benchmark.pdfid_features(ref) == {"pdf-javascript": "yes", "pdf-auto-action": "yes",
                                             "pdf-embedded-file": "no", "pdf-name-obfuscation": "yes"}
    assert benchmark.pdfid_features({"error": "TimeoutExpired"}) == {}


# ============================================================================= review fixes (regressions)


@pytest.mark.parametrize("argv", [
    ["make-pdf-embedded.py", "-ab", "note.txt", "out.pdf"],  # combined short flags
    ["make-pdf-embedded.py", "-ta", "note.txt", "out.pdf"],  # a flag after another flag
    ["make-pdf-embedded.py", "--auto", "note.txt", "out.pdf"],  # optparse long-option prefix
    ["make-pdf-embedded.py", "--butt", "note.txt", "out.pdf"],
    ["make-pdf-embedded.py", "--autoopen=1", "note.txt", "out.pdf"],
])
def test_every_spelling_of_the_launch_options_is_refused(argv):
    assert prepare_samples.forbidden_options(argv)


@pytest.mark.parametrize("argv", [
    ["make-pdf-embedded.py", "-m", "Inert attachment test", "note.txt", "out.pdf"],  # the real command
    ["make-pdf-embedded.py", "-mab", "note.txt", "out.pdf"],  # "ab" is -m's value, not options
    ["-c", "import mPDF  # -a -b", "out.pdf"],  # python -c: the code string is not an option
    ["make-pdf-javascript.py", "out.pdf"],
])
def test_the_commands_actually_used_are_allowed(argv):
    assert prepare_samples.forbidden_options(argv) == []


def test_malformed_allowlist_entry_is_rejected_cleanly(tmp_path):
    path = tmp_path / "allowlist.json"
    path.write_text(json.dumps({"resources": [{k: v for k, v in GOOD.items() if k != "size"}]}))
    with pytest.raises(acquire.AcquisitionError, match="allowlist is malformed: KeyError"):
        acquire.load_allowlist(path)


def test_archive_member_with_corrupt_data_is_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("note.txt", b"inert")
    data = bytearray(buf.getvalue())
    start = 30 + len("note.txt")
    data[start:start + 4] = b"\xff\xff\xff\xff"
    with pytest.raises(acquire.AcquisitionError, match="cannot be read|does not match"):
        acquire.extract(ARCHIVE, bytes(data))


def test_provenance_keeps_earlier_records_when_a_subset_is_acquired(tmp_path):
    a, b = resource(b"inert", id="a", save_as="a.txt"), resource(b"other", id="b", save_as="b.txt")
    cache = tmp_path / "cache"
    acquire.acquire([a], cache, fetcher=lambda url: (b"inert", 200))
    acquire.acquire([b], cache, fetcher=lambda url: (b"other", 200))
    assert [r["id"] for r in json.loads((cache / "provenance.json").read_text())["resources"]] == ["a", "b"]


def test_only_rejects_ids_outside_the_allowlist(tmp_path, capsys):
    assert acquire.main(["--out", str(tmp_path / "c"), "--dry-run", "--only", "no-such-id"]) == 2
    assert "not in the allowlist: no-such-id" in capsys.readouterr().err


def body(duration=5.0):
    return {"verdict": "SAFE", "complete": True, "findings": [], "duration_ms": duration,
            "scanners": [{"name": n, "status": "completed", "duration_ms": 1.0} for n in benchmark.SCANNERS]}


ROW = {"sample_id": "s", "source": "generated-local", "file_type": "pdf", "ground_truth": "BENIGN", "sha256": "0" * 64,
       "_size": 1, "tags": "expect:pdf-javascript"}


def test_timings_stay_aligned_when_a_trial_has_no_report():
    trials = [{"wall_ms": 9.0, "body": None, "failure_reason": "http_error"},
              {"wall_ms": 7.0, "body": body(), "failure_reason": ""}]
    r = benchmark.sample_result(ROW, trials)
    assert r["timing_ms"] == {"harness_wall": [9.0, 7.0], "worker_total": [None, 5.0], "worker_overhead": [None, 1.0]}
    assert r["scanners"]["pdf"]["duration_ms"] == [None, 1.0]


def test_a_scan_without_any_report_counts_as_failed_not_as_missed():
    r = benchmark.sample_result(ROW, [{"wall_ms": 9.0, "body": None, "failure_reason": "http_error"}])
    assert r["features"]["pdf-javascript"]["pdf"] == "failed" and r["verdict"] == "ERROR"


def test_samples_left_after_isolation_is_lost_are_recorded_as_not_run(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    class Response:
        status_code = 200

        def json(self):
            return body() | {"isolation_required": False, "isolation_missing": []}  # not verified

    class Client:
        def post(self, *args, **kwargs):
            return Response()

    rows = []
    for name in ("a", "b", "c"):
        path = tmp_path / name
        path.write_bytes(b"x")
        rows.append(ROW | {"sample_id": name, "_path": path, "duplicate_of": ""})
    results, status, not_run = benchmark.scan(rows, 2, Client(), Ed25519PrivateKey.generate(), require_isolation=True)
    assert status == "failed_isolation_lost" and [r["sample_id"] for r in results] == ["a"] and not_run == ["b", "c"]
