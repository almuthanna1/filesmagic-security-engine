"""Controlled case matrix for the custom-engine study (inert synthetic documents only).

Each case is built in memory from the repository's own inert fixture builders, then scanned
`--trials` times through the real isolated worker subprocess (app.worker.run), exactly as
/scan does. From each worker report it derives, with the engine's own decide():
  - every reference scanner's verdict on its own (its findings, its completion status),
  - the aggregate verdict of the scanners the worker ran (the existing four-scanner engine),
  - per-scanner durations measured inside the worker, and the harness's wall time per scan.

Ground truth: every case is BENIGN; "indicator" says which inert structure it carries (an
indicator is not malware). Nothing here measures malware detection accuracy.

This is a development harness, not a research run: it does not enforce strict isolation or a
clean tree (evaluation.benchmark does that). Its output records the platform, commit and
whether isolation was complete, so numbers are compared only within one environment.

    python -m evaluation.cases --trials 20 --out <dir> [--engine unified]
"""

import argparse
import asyncio
import hashlib
import json
import platform
import sys
import time
from pathlib import Path

from app import worker
from app.decision import decide
from app.models import Severity
from evaluation.evaluate import environment, latency
from evaluation.prepare_samples import TEMPLATE_URL
from tests import custom_fixtures as fx
from tests.office_fixtures import make_ole
from tests.pdf_fixtures import attachment, js_action, make_pdf

FORM_KEYSTROKE_JS = ("<< /Type /Annot /Subtype /Widget /FT /Tx /T (amount) /Rect [0 0 50 20] /AA << /K "
                     "<< /S /JavaScript /JS (AFNumber_Keystroke\\(2, 0, 0, 0, \"\", true\\);) >> >> >>")
CLICK_LINK_JS = "<< /Type /Annot /Subtype /Link /Rect [0 0 50 50] /A " + js_action("app.alert\\(1\\);") + " >>"
LINKED_PICTURE = "https://images.example.invalid/pixel.png"  # RFC 2606 .invalid: never resolves
SHARE_PICTURE = "file://fileserver.invalid/share/pixel.png"
INERT_OLE = make_ole({"Contents": b"inert placeholder bytes"})  # an OLE container with no object in it
EXPORT_JS = js_action("this.exportDataObject\\({cName: \"f\", nLaunch: 0}\\);")  # "f": the fixture's attachment key


def cases() -> list[dict]:
    att_extra, att_objs = attachment("notes.txt")
    rel = fx.REL
    case = lambda id, indicator, data: dict(id=id, ground_truth="BENIGN", indicator=indicator, data=data)  # noqa: E731
    return [
        case("1-pdf-clean", "none (negative control)", make_pdf()),
        case("2-pdf-form-keystroke-js", "form-field keystroke JavaScript (user-triggered /AA /K)",
             make_pdf(catalog_extra="/AcroForm << /Fields [5 0 R] >>", page_extra="/Annots [5 0 R]",
                      objects={5: FORM_KEYSTROKE_JS})),
        case("2b-pdf-open-at-page-click-js", "/OpenAction page destination + click-only link JavaScript",
             make_pdf(catalog_extra="/OpenAction [3 0 R /Fit]", page_extra="/Annots [5 0 R]", objects={5: CLICK_LINK_JS})),
        case("2c-pdf-open-at-page-page-open-js", "/OpenAction page destination + that page's own open trigger /AA /O",
             make_pdf(catalog_extra="/OpenAction [3 0 R /Fit]", page_extra="/AA << /O 5 0 R >>", objects={5: js_action()})),
        case("3-pdf-escaped-openaction-js", "/OpenAction JavaScript written /J#61vaScript /J#53",
             fx.obfuscated_javascript_pdf()),
        case("4-pdf-objstm-escaped-js", "the same action inside a FlateDecode object stream",
             fx.obfuscated_javascript_pdf(in_object_stream=True)),
        case("5a-pdf-auto-js-unrelated-attachment", "/OpenAction JavaScript + a text attachment it never references",
             make_pdf(catalog_extra="/OpenAction 7 0 R " + att_extra, objects={**att_objs, 7: js_action()})),
        case("5b-pdf-auto-js-exports-attachment", "/OpenAction JavaScript that exports the attachment (nLaunch 0)",
             make_pdf(catalog_extra="/OpenAction 7 0 R " + att_extra, objects={**att_objs, 7: EXPORT_JS})),
        case("6a-docx-hyperlink", "ordinary external hyperlink (negative control)",
             fx.office_package("docx", main_rels=(("rId9", f"{rel}/hyperlink", "https://example.com/", "External"),))),
        case("6b-docx-external-template", f"external attachedTemplate {TEMPLATE_URL} (never fetched)",
             fx.office_package("docx", main_rels=(("rId9", f"{rel}/attachedTemplate", TEMPLATE_URL, "External"),))),
        case("6c-docx-template-referenced-by-settings", "the same template, referenced by w:attachedTemplate in "
             "the settings part, as Word writes it",
             fx.linked_docx(settings='<w:attachedTemplate r:id="rId1"/>',
                            settings_rels=(("rId1", f"{rel}/attachedTemplate", TEMPLATE_URL, "External"),))),
        case("6d-docx-linked-picture", f"a picture shown from {LINKED_PICTURE} (a:blip r:link; never fetched)",
             fx.linked_docx(body='<w:p><w:r><w:drawing><a:blip r:link="rId9"/></w:drawing></w:r></w:p>',
                            main_rels=(("rId9", f"{rel}/image", LINKED_PICTURE, "External"),))),
        case("6g-docx-linked-picture-file-share", f"the same picture on a file share {SHARE_PICTURE} (never fetched)",
             fx.linked_docx(body='<w:p><w:r><w:drawing><a:blip r:link="rId9"/></w:drawing></w:r></w:p>',
                            main_rels=(("rId9", f"{rel}/image", SHARE_PICTURE, "External"),))),
        case("6e-docx-embedded-object-displayed", "an inert OLE container shown by o:OLEObject Type=Embed",
             fx.linked_docx(body='<w:p><w:r><w:object><o:OLEObject Type="Embed" r:id="rId10"/></w:object></w:r></w:p>',
                            main_rels=(("rId10", f"{rel}/oleObject", "embeddings/oleObject1.bin"),),
                            parts={"word/embeddings/oleObject1.bin": INERT_OLE})),
        case("6f-docx-embedded-object-not-displayed", "the same object with its relationship but no element",
             fx.linked_docx(main_rels=(("rId10", f"{rel}/oleObject", "embeddings/oleObject1.bin"),),
                            parts={"word/embeddings/oleObject1.bin": INERT_OLE})),
        case("7-docx-macro-declaration-mismatch", "macro-free DOCX declaration with a vbaProject.bin placeholder",
             fx.zip_parts(fx.office_parts("docm", main_type=fx.MAIN_TYPES["docx"]))),
    ]


def verdicts(report) -> dict[str, str]:
    """Each scanner's own verdict, and the aggregate, with the rules /scan applies."""
    out = {}
    for s in report.scanners:
        if s.status == "not_applicable":
            out[s.name] = "n/a"
        else:
            own = [f for f in report.findings if f.scanner == s.name]
            out[s.name] = decide(own, scanners_run=1, scanners_failed=s.status == "failed").value
    applicable = sum(s.status != "not_applicable" for s in report.scanners)
    failed = sum(s.status == "failed" for s in report.scanners)
    out["aggregate"] = decide(report.findings, scanners_run=applicable, scanners_failed=failed).value
    return out


def scan_case(case: dict, trials: int, cmd: list[str]) -> dict:
    runs = []
    for _ in range(trials):
        start = time.perf_counter()
        report = asyncio.run(worker.run(case["data"], cmd))
        runs.append((round((time.perf_counter() - start) * 1000, 3), report))
    first = runs[0][1]
    rules = lambda r: sorted({f"{f.scanner}:{f.rule_id}:{f.severity.value}" for f in r.findings  # noqa: E731
                              if f.severity != Severity.INFO})
    every = lambda r: [(f.scanner, f.rule_id, f.severity.value, f.description) for f in r.findings]  # noqa: E731
    durations = [{s.name: s.duration_ms for s in r.scanners} for _, r in runs]
    return {
        "id": case["id"], "ground_truth": case["ground_truth"], "indicator": case["indicator"],
        "sha256": hashlib.sha256(case["data"]).hexdigest(), "size_bytes": len(case["data"]),
        "verdicts": verdicts(first),
        # Same verdicts and the same complete findings (INFO included) in every trial.
        "deterministic": all(verdicts(r) == verdicts(first) and every(r) == every(first) for _, r in runs),
        "status": {s.name: s.status for s in first.scanners},
        "rules": rules(first),
        "findings": [dict(scanner=s, rule_id=i, severity=v, description=d) for s, i, v, d in every(first)],
        "isolation_missing": worker.missing_controls(first.isolation),
        "timing_ms": {"harness_wall": latency([w for w, _ in runs]),
                      **{s.name: latency([d[s.name] for d in durations]) for s in first.scanners}},
        # Raw per-trial values: wall time of the whole scan (worker start-up included) and each
        # scanner's own time inside the worker.
        "trials": [{"harness_wall_ms": w, "scanner_ms": d} for (w, _), d in zip(runs, durations)],
    }


def markdown(results: list[dict]) -> str:
    names = list(results[0]["status"]) + ["aggregate"]
    lines = ["| case | " + " | ".join(names) + " | wall p50 ms |", "|---|" + "---|" * (len(names) + 1)]
    for r in results:
        lines.append(f"| {r['id']} | " + " | ".join(r["verdicts"][n] for n in names)
                     + f" | {r['timing_ms']['harness_wall']['median_ms']} |")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--engine", choices=["reference", "unified"], default="reference",
                        help="reference: the four scanners /scan runs; unified: the custom engine candidate")
    args = parser.parse_args(argv)
    cmd = worker.command() + ["--engine=unified"] * (args.engine == "unified")
    results = [scan_case(c, args.trials, cmd) for c in cases()]
    env = environment(None) | {"platform": platform.platform(), "python": sys.version.split()[0],
                               "worker_command": cmd[3:], "trials": args.trials}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps({"environment": env, "results": results}, indent=2))
    (args.out / "matrix.md").write_text(markdown(results) + "\n")
    print(markdown(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
