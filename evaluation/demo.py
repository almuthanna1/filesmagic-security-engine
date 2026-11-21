"""Capstone demonstrations: three inert files, the findings that decide them, and the verdict.

    python -m evaluation.demo            # all three
    python -m evaluation.demo pdf|vba|word

Runs the production scanner roster in-process (app.worker.analyse -> correlate -> decide ->
classify), the same steps POST /scan performs inside its isolated worker. Nothing is executed:
the files are synthetic, with placeholder commands and no payload. `--save DIR` writes them out.
"""
import sys
from pathlib import Path

from app import engine
from app.decision import classify, decide
from app.engine.correlate import correlate
from app.worker import analyse
from evaluation.cases import cases
from evaluation.vba_cases import CASES, case_bytes
from tests import custom_fixtures as fx

C = {c["id"]: c["data"] for c in cases()}
V = {cid: case_bytes(cid, m) for cid, m, *_ in CASES}

DEMOS = {
    "pdf": ("PDF action chain", [
        ("auto-js-unrelated-attachment.pdf", C["5a-pdf-auto-js-unrelated-attachment"]),
        ("auto-js-exports-attachment.pdf", C["5b-pdf-auto-js-exports-attachment"]),
    ]),
    "vba": ("VBA call path (inert)", [
        ("v04-benign-formatting.docm", V["v04-benign-formatting"]),
        ("v01-autoopen-calls-shell.docm", V["v01-autoopen-calls-shell"]),
        ("v09-strreverse-progid-run.docm", V["v09-strreverse-progid-run"]),
    ]),
    "word": ("External relationship and Word field", [
        ("hyperlink.docx", C["6a-docx-hyperlink"]),
        ("external-template.docx", C["6c-docx-template-referenced-by-settings"]),
        ("ddeauto-field.docx", fx.field_docx(fx.complex_field('DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/c placeholder"'))),
    ]),
}


def show(name: str, data: bytes) -> str:
    report = correlate(analyse(engine.SCANNERS, data))
    applicable = sum(s.status != "not_applicable" for s in report.scanners)
    failed = sum(s.status == "failed" for s in report.scanners)
    verdict = decide(report.findings, scanners_run=applicable, scanners_failed=failed,
                     coverage_complete=report.coverage_complete)
    # As production with verified isolation: no operational reason.
    _, authorization, _ = classify(verdict, report.scanners, report.coverage_issues, [])
    print(f"\n  {name}  ({len(data)} bytes)")
    print("    scanners: " + ", ".join(f"{s.name}={s.status}" for s in report.scanners))
    for f in sorted(report.findings, key=lambda f: -list(type(f.severity)).index(f.severity)):
        if f.severity.value == "INFO":
            continue
        print(f"    {f.severity.value:8} {f.scanner}:{f.rule_id}")
        print(f"             {f.description[:220]}")
        for e in (f.evidence or [])[:3]:
            print(f"             evidence: {str(e)[:200]}")
    print(f"    => verdict {verdict.value}, authorization {authorization}")
    return verdict.value


def main(argv: list[str]) -> None:
    save = Path(argv[argv.index("--save") + 1]) if "--save" in argv else None
    chosen = [a for a in argv if a in DEMOS] or list(DEMOS)
    for key in chosen:
        title, files = DEMOS[key]
        print(f"\n=== {title} ===")
        for name, data in files:
            show(name, data)
            if save:
                save.mkdir(parents=True, exist_ok=True)
                (save / name).write_bytes(data)


if __name__ == "__main__":
    main(sys.argv[1:])
