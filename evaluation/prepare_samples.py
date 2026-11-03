"""Build the inert sample set and its manifest (the OFFLINE step, inside the evaluation VM).

Three clearly separated origins, recorded in the manifest's `source` column:
  generated-local           built here from the repository's own inert fixture builders
  generated-didier-stevens  written by Didier Stevens' make-pdf tools (pinned, reviewed copies)
  downloaded-eicar          the EICAR test file, copied from the verified acquisition cache

Every acquired file is re-verified against evaluation/allowlist.json before it is used. Didier
Stevens' scripts run only as the fixed commands below, in a child process with an empty
environment, from a fresh directory holding just the verified files; make-pdf-embedded's -a and
-b options (launch JavaScript) are refused. No document content is executed or rendered:
"JavaScript" samples carry only the text app.alert(...).

Ground truth: every generated document is BENIGN (an inert structural indicator is not
malware); EICAR is SECURITY_TEST. The expected indicators of each sample are in `tags`
("expect:<feature>"; "expect:none" for negative controls).

    python -m evaluation.prepare_samples --out ~/fm-eval/eicar-didier [--acquired ~/fm-acquired]
"""

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from evaluation import acquire
from evaluation.evaluate import REQUIRED_COLUMNS

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_TIMEOUT_SECONDS = 60
MAX_GENERATED_BYTES = 1024 * 1024
# make-pdf-embedded options that add launch JavaScript. optparse also accepts combined short flags
# ("-ab", "-ma") and unambiguous long-option prefixes ("--auto"), so those are refused too.
FORBIDDEN_SHORT, FORBIDDEN_LONG = {"a", "b"}, ("--autoopen", "--button")
INERT_ATTACHMENT = b"FilesMagic capstone inert attachment: plain text, no code.\n"
TEMPLATE_URL = "https://template.example.invalid/normal.dotm"  # RFC 2606 .invalid: never resolves
CLEAN_PDF_WITH_MPDF = (  # what make-pdf-helloworld.py (Python 2 only) does, with mPDF's own calls
    "import sys, mPDF\n"
    "o = mPDF.cPDF(sys.argv[1])\n"
    "o.header()\n"
    "o.template1()\n"
    "o.stream(5, 0, 'BT /F1 12 Tf 100 700 Td 15 TL (Hello World) Tj ET')\n"
    "o.xrefAndTrailer('1 0 R')\n"
)


class PreparationError(RuntimeError):
    pass


# ----------------------------------------------------------------------------- locally generated


def local_samples() -> list[dict]:
    """(sample_id, file_type, bytes, expected features, builder description) built from the
    repository's inert test fixture builders."""
    from tests import custom_fixtures as fx
    from tests.pdf_fixtures import js_action, make_pdf

    rel = fx.REL
    return [
        dict(id="pdf-clean-local", type="pdf", data=make_pdf(), expect=[], builder="tests.pdf_fixtures.make_pdf()"),
        dict(id="pdf-js-openaction-local", type="pdf", expect=["pdf-javascript", "pdf-auto-action"],
             data=make_pdf(catalog_extra="/OpenAction 5 0 R", objects={5: js_action()}),
             builder="make_pdf + /OpenAction -> JavaScript action app.alert(1)"),
        dict(id="pdf-js-obfuscated-local", type="pdf", data=fx.obfuscated_javascript_pdf(),
             expect=["pdf-javascript", "pdf-auto-action", "pdf-name-obfuscation"],
             builder="tests.custom_fixtures.obfuscated_javascript_pdf(): /S /J#61vaScript /J#53 (app.alert(1);)"),
        dict(id="pdf-js-obfuscated-objstm-local", type="pdf", data=fx.obfuscated_javascript_pdf(in_object_stream=True),
             expect=["pdf-javascript", "pdf-auto-action", "pdf-name-obfuscation"],
             builder="the same action inside a FlateDecode object stream"),
        dict(id="docx-clean-local", type="docx", data=fx.office_package("docx"), expect=[],
             builder="tests.custom_fixtures.office_package('docx')"),
        dict(id="docx-external-hyperlink-local", type="docx", expect=[],
             data=fx.office_package("docx", main_rels=(("rId9", f"{rel}/hyperlink", "https://example.com/", "External"),)),
             builder="clean DOCX with an ordinary external hyperlink (negative control)"),
        dict(id="docx-external-template-local", type="docx", expect=["office-external-autoload"],
             data=fx.office_package("docx", main_rels=(("rId9", f"{rel}/attachedTemplate", TEMPLATE_URL, "External"),)),
             builder=f"DOCX with an external attachedTemplate relationship to {TEMPLATE_URL} (never fetched)"),
        dict(id="docx-macro-declaration-mismatch-local", type="docx",
             expect=["office-macro-project", "office-macro-declaration-mismatch"],
             data=fx.zip_parts(fx.office_parts("docm", main_type=fx.MAIN_TYPES["docx"])),
             builder="macro-free DOCX declaration carrying a vbaProject.bin part of placeholder text (no VBA)"),
        dict(id="xlsx-clean-local", type="xlsx", data=fx.office_package("xlsx"), expect=[],
             builder="tests.custom_fixtures.office_package('xlsx')"),
        dict(id="pptx-clean-local", type="pptx", data=fx.office_package("pptx"), expect=[],
             builder="tests.custom_fixtures.office_package('pptx')"),
    ]


# ----------------------------------------------------------------------------- acquired resources


def verified_cache(acquired: Path) -> dict[str, Path]:
    """Re-verify every allowlisted file in the acquisition cache. A file that is present but
    does not match its pins stops preparation; a missing one is simply unavailable."""
    found = {}
    for r in acquire.load_allowlist():
        path = acquired / r["id"] / r["save_as"]
        if not path.is_file():
            continue
        try:
            acquire.verify(r, path.read_bytes())
        except acquire.AcquisitionError as e:
            raise PreparationError(f"{r['id']}: cached file fails verification ({e}); re-acquire it") from None
        found[r["id"]] = path
    return found


VALUE_OPTIONS = set("fmn")  # make-pdf-embedded's short options that take a value


def forbidden_options(argv: list[str]) -> list[str]:
    """Arguments that would enable make-pdf-embedded's -a/-b, read the way optparse reads them:
    a short cluster ("-tab") is flags left to right until a value-taking option takes the rest;
    a long option may be any unambiguous prefix ("--auto"). Errs towards refusing."""
    if argv[:1] == ["-c"]:  # python -c <code> <args>: the code string is not an option
        argv = argv[2:]
    found = []
    for arg in argv:
        if arg.startswith("--") and len(arg) > 2:
            name = arg.split("=", 1)[0]
            if any(opt.startswith(name) for opt in FORBIDDEN_LONG):
                found.append(arg)
        elif arg.startswith("-") and len(arg) > 1:
            for letter in arg[1:]:
                if letter in FORBIDDEN_SHORT:
                    found.append(arg)
                    break
                if letter in VALUE_OPTIONS:
                    break  # the rest of the cluster is this option's value
    return found


def run_tool(tools: Path, argv: list[str]) -> None:
    """One fixed Didier Stevens command, never a shell: python -E -s <argv> in `tools`."""
    from app.worker import child_env

    if refused := forbidden_options(argv):
        raise PreparationError(f"refused tool options {refused}: they add launch JavaScript")
    try:
        subprocess.run([sys.executable, "-E", "-s", *argv], cwd=tools, env=child_env(), stdin=subprocess.DEVNULL,
                       capture_output=True, timeout=TOOL_TIMEOUT_SECONDS, check=True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        raise PreparationError(f"Didier Stevens tool {argv[0]!r} failed: {type(e).__name__}") from None


def didier_samples(cache: dict[str, Path], work: Path) -> list[dict]:
    needed = ("ds-mpdf", "ds-make-pdf-javascript", "ds-make-pdf-embedded")
    if not all(k in cache for k in needed):
        return []
    tools = work / "tools"
    tools.mkdir()
    for k in needed:  # only verified files in the tools' import directory
        shutil.copyfile(cache[k], tools / cache[k].name)
    (work / "note.txt").write_bytes(INERT_ATTACHMENT)
    commit = "7d625d0b05c4638b981a2a2cc9a8481d7b73e56d"
    specs = [
        dict(id="pdf-clean-didier", expect=[], argv=["-c", CLEAN_PDF_WITH_MPDF],
             builder=f"mPDF.py (DidierStevensSuite@{commit[:7]}): header, template1, text stream"),
        dict(id="pdf-js-didier", expect=["pdf-javascript", "pdf-auto-action"], argv=["make-pdf-javascript.py"],
             builder=f"make-pdf-javascript.py (DidierStevensSuite@{commit[:7]}), default app.alert script"),
        # -f h: its default FlateDecode path fails on Python 3 in mPDF.appendBinary (bytes(bytes, 'ascii')),
        # an upstream bug; ASCIIHexDecode avoids it. -n: embed the plain name, not this machine's path.
        dict(id="pdf-embedded-didier", expect=["pdf-embedded-file"],
             argv=["make-pdf-embedded.py", "-f", "h", "-n", "note.txt", "-m", "Inert attachment test",
                   str(work / "note.txt")],
             builder=f"make-pdf-embedded.py (DidierStevensSuite@{commit[:7]}) -f h -n note.txt: inert note, no -a/-b"),
    ]
    samples = []
    for spec in specs:
        out = work / f"{spec['id']}.pdf"
        run_tool(tools, [*spec["argv"], str(out)])
        data = out.read_bytes()
        if not data.startswith(b"%PDF-") or len(data) > MAX_GENERATED_BYTES:
            raise PreparationError(f"{spec['id']}: the tool did not produce a PDF within {MAX_GENERATED_BYTES} bytes")
        samples.append(dict(spec, type="pdf", data=data))
    return samples


def eicar_samples(cache: dict[str, Path]) -> list[dict]:
    samples = []
    if "eicar-com-txt" in cache:
        samples.append(dict(id="eicar-com-txt", type="txt", data=cache["eicar-com-txt"].read_bytes(),
                            expect=["eicar-test-string"], builder="https://secure.eicar.org/eicar.com.txt"))
    if "eicar-com-zip" in cache:
        samples.append(dict(id="eicar-com-zip", type="zip", data=cache["eicar-com-zip"].read_bytes(),
                            expect=["eicar-test-string"], builder="https://secure.eicar.org/eicar_com.zip"))
    return samples


# ----------------------------------------------------------------------------- manifest


def manifest_row(sample: dict, source: str, path: str, date: str) -> dict:
    eicar = source == "downloaded-eicar"
    expect = sample["expect"]
    return {
        "sample_id": sample["id"], "sha256": hashlib.sha256(sample["data"]).hexdigest(), "path": path,
        "file_type": sample["type"],
        "ground_truth": "SECURITY_TEST" if eicar else "BENIGN",
        "ground_truth_basis": ("EICAR standard anti-malware test file, verified against its pinned SHA-256" if eicar else
                               "generated for this study; inert by construction: the indicator is present, no payload"),
        "source": source, "source_ref": sample["builder"], "acquired_date": date, "split": "dev",
        "active_content": "yes" if {"pdf-javascript", "pdf-auto-action"} & set(expect) else "no",
        "encrypted": "no",
        "tags": ";".join(f"expect:{f}" for f in expect) or "expect:none",
        "notes": "negative control" if not expect else ("not a document format" if eicar else "indicator-bearing"),
    }


def prepare(out: Path, acquired: Path | None = None, now: datetime | None = None) -> dict:
    """Write samples under `out` (outside the repository), manifest.csv and preparation.json."""
    out = acquire.outside_repository(out)
    if out.exists() and any(out.iterdir()):
        raise PreparationError(f"{out} is not empty; use a new directory per prepared set")
    date = (now or datetime.now(timezone.utc)).date().isoformat()
    cache = verified_cache(acquire.outside_repository(acquired)) if acquired else {}
    with tempfile.TemporaryDirectory() as tmp:
        groups = [("generated-local", local_samples()), ("generated-didier-stevens", didier_samples(cache, Path(tmp))),
                  ("downloaded-eicar", eicar_samples(cache))]
    rows = []
    for source, samples in groups:
        for s in samples:
            rel = f"{source}/{s['id']}.{s['type']}"
            (out / source).mkdir(parents=True, exist_ok=True)
            (out / rel).write_bytes(s["data"])
            rows.append(manifest_row(s, source, rel, date))
    with (out / "manifest.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REQUIRED_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    missing = {"generated-didier-stevens": not groups[1][1], "downloaded-eicar": not groups[2][1]}
    record = {
        "prepared_utc": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "acquisition_cache": str(acquired) if acquired else None,
        "acquired_resources_verified": sorted(cache), "samples": len(rows),
        "by_source": {source: len(samples) for source, samples in groups},
        "not_built": [f"{source}: acquisition cache missing or incomplete" for source, m in missing.items() if m],
    }
    (out / "preparation.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, required=True, help="new, empty samples directory outside the repository")
    parser.add_argument("--acquired", type=Path, help="verified acquisition cache (from evaluation.acquire)")
    args = parser.parse_args(argv)
    try:
        record = prepare(args.out, args.acquired)
    except (PreparationError, acquire.AcquisitionError) as e:
        print(f"Preparation stopped: {e}", file=sys.stderr)
        return 2
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
