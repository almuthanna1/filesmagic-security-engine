"""Comparison report and poster figures from one frozen pair of case-matrix runs.

Reads <run>/reference/results.json and <run>/unified/results.json (evaluation.cases) and writes,
into --out: summary.json, comparison.md and four SVG figures. Every number comes from those two
files; the per-case captions are authored text, checked against the data (a caption that says a
verdict changed must match a changed verdict, and the other way round).

Statistics: each case is one synthetic fixture scanned `trials` times. Trials measure timing
variation on one machine; they are not independent samples, and detection is counted per
fixture (n = number of cases), never per trial. p95 uses the harness's nearest-rank method
(evaluation.evaluate.latency).

    python -m evaluation.poster --run docs/evidence/custom-engine-<commit> --out docs/poster/figures
"""

import argparse
import json
import sys
from html import escape
from pathlib import Path

from evaluation.evaluate import latency

FONT = "Arial, Helvetica, sans-serif"
INK, INK2, MUTED, GRID, AXIS, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"
REFERENCE_COLOR, UNIFIED_COLOR = "#2a78d6", "#eb6834"  # categorical slots 1 and 2 (validated pair)
VERDICT_STYLE = {  # status palette, always with a text label: (fill, label ink)
    "SAFE": ("#0ca30c", "#ffffff"), "SUSPICIOUS": ("#fab219", "#0b0b0b"),
    "MALICIOUS": ("#d03b3b", "#ffffff"), "UNABLE_TO_SCAN": ("#898781", "#ffffff"),
}
VERDICT_ORDER = ["SAFE", "SUSPICIOUS", "MALICIOUS"]

# Document scenarios (the approved plan's seven cases and their variants), in display order.
SCENARIOS = [
    ("PDF without automatic code", ["1-pdf-clean", "2-pdf-form-keystroke-js", "2b-pdf-open-at-page-click-js"]),
    ("PDF with automatic JavaScript", ["2c-pdf-open-at-page-page-open-js", "3-pdf-escaped-openaction-js",
                                       "4-pdf-objstm-escaped-js"]),
    ("PDF script and attachment", ["5a-pdf-auto-js-unrelated-attachment", "5b-pdf-auto-js-exports-attachment"]),
    ("Word external content", ["6a-docx-hyperlink", "6b-docx-external-template", "6c-docx-template-referenced-by-settings",
                               "6d-docx-linked-picture", "6g-docx-linked-picture-file-share"]),
    ("Word embedded objects and macros", ["6e-docx-embedded-object-displayed", "6f-docx-embedded-object-not-displayed",
                                          "7-docx-macro-declaration-mismatch"]),
]
# Role of each fixture in the evaluation (an explicit assumption, stated on the poster):
#   control        nothing active
#   benign-content ordinary active content benign documents carry (forms, links, pictures, objects)
#   indicator      an inert structural threat indicator from the approved plan
ROLE = {
    "1-pdf-clean": "control", "6a-docx-hyperlink": "control",
    "2-pdf-form-keystroke-js": "benign-content", "2b-pdf-open-at-page-click-js": "benign-content",
    "6d-docx-linked-picture": "benign-content", "6e-docx-embedded-object-displayed": "benign-content",
    "6f-docx-embedded-object-not-displayed": "benign-content",
}
# (short label, caption, verdict changed?) - checked against the data in check_captions().
CAPTION = {
    "1-pdf-clean": ("Clean PDF", "No findings in either engine.", False),
    "2-pdf-form-keystroke-js": ("Form keystroke script", "False 'automatic' claim removed; any script is still "
                                "MEDIUM (PDF policy).", False),
    "2b-pdf-open-at-page-click-js": ("Open-at-page + click script", "False 'automatic' claims removed (PDF scanner "
                                     "and YARA-X).", False),
    "2c-pdf-open-at-page-page-open-js": ("Page-open script", "Kept: the page's own /AA /O runs on open.", False),
    "3-pdf-escaped-openaction-js": ("#-escaped OpenAction script", "Automatic chain found through escaped names.", False),
    "4-pdf-objstm-escaped-js": ("Same, in object stream", "Automatic chain found inside a compressed object stream.",
                                False),
    "5a-pdf-auto-js-unrelated-attachment": ("Auto script + unrelated file", "Script never uses the attachment: no "
                                            "HIGH escalation.", True),
    "5b-pdf-auto-js-exports-attachment": ("Auto script exports file", "Same chain exports the attachment: HIGH, with "
                                          "the path as evidence.", False),
    "6a-docx-hyperlink": ("Hyperlink relationship", "Relationship no element references: recorded (INFO).", False),
    "6b-docx-external-template": ("Unreferenced template", "Template relationship nothing references: kept, use not "
                                  "demonstrated.", False),
    "6c-docx-template-referenced-by-settings": ("Template via settings", "attachedTemplate confirmed with the full "
                                                "chain.", False),
    "6d-docx-linked-picture": ("Linked picture (https)", "Recorded as INFO; not escalated (documented risk policy).", False),
    "6g-docx-linked-picture-file-share": ("Linked picture (file://)", "Stays SUSPICIOUS: credential exposure "
                                          "(reference rule).", False),
    "6e-docx-embedded-object-displayed": ("Embedded object, shown", "Shown in the document; runs only when "
                                          "activated (INFO).", False),
    "6f-docx-embedded-object-not-displayed": ("Embedded object, not shown", "Present but no element shows it (INFO).",
                                              False),
    "7-docx-macro-declaration-mismatch": ("Macro part, macro-free type", "Macro call graph undetermined: the "
                                          "placeholder part is not a VBA project.", False),
}
UNDETERMINED_RULES = {"ENGINE_VBA_CALL_PATH_UNDETERMINED", "ENGINE_OFFICE_ACTIVATION_UNDETERMINED",
                      "ENGINE_PDF_CHAINS_REPAIRED", "CUSTOM_PDF_COVERAGE_LIMITED", "CUSTOM_OFFICE_COVERAGE_LIMITED"}


# ----------------------------------------------------------------------------- analysis


def load(path: Path) -> tuple[dict, dict]:
    data = json.loads(path.read_text())
    return data["environment"], {r["id"]: r for r in data["results"]}


def key(f: dict) -> tuple:
    return f["scanner"], f["rule_id"], f["severity"]


def compare(reference: dict, unified: dict) -> list[dict]:
    rows = []
    for title, ids in SCENARIOS:
        for case in ids:
            r, u = reference[case], unified[case]
            ref_f, uni_f = {key(f) for f in r["findings"]}, {key(f) for f in u["findings"]}
            notes = [f["description"] for f in u["findings"] if f["rule_id"] == "ENGINE_CORRELATION"]
            rows.append({
                "id": case, "scenario": title, "role": ROLE.get(case, "indicator"), "label": CAPTION[case][0],
                "caption": CAPTION[case][1], "indicator": r["indicator"], "sha256": r["sha256"],
                "reference": r["verdicts"]["aggregate"], "unified": u["verdicts"]["aggregate"],
                "added": sorted(f for f in uni_f - ref_f if f[1] != "ENGINE_CORRELATION"),
                "removed": sorted(ref_f - uni_f),
                "qualified": notes,
                "undetermined": sorted({f[1] for f in uni_f if f[1] in UNDETERMINED_RULES}),
                "incomplete": sorted(n for n, s in u["status"].items() if s == "failed")
                + sorted(n for n, s in r["status"].items() if s == "failed"),
                "deterministic": r["deterministic"] and u["deterministic"],
            })
    return rows


def check_captions(rows: list[dict]) -> None:
    for row in rows:
        changed = row["reference"] != row["unified"]
        if changed != CAPTION[row["id"]][2]:
            raise ValueError(f"caption for {row['id']} says changed={not changed}, data says {changed}")


def timing(results: dict) -> dict:
    """Pooled over every trial of every case: wall time, in-worker scanning (sum of scanner times),
    their difference (worker start-up, IPC and report validation), and each scanner where it ran."""
    wall, scanning, startup, per_scanner = [], [], [], {}
    for r in results.values():
        for t in r["trials"]:
            work = sum(t["scanner_ms"].values())
            wall.append(t["harness_wall_ms"])
            scanning.append(round(work, 3))
            startup.append(round(t["harness_wall_ms"] - work, 3))
            for name, ms in t["scanner_ms"].items():
                if r["status"][name] == "completed":
                    per_scanner.setdefault(name, []).append(ms)
    return {"cases": len(results), "trials_per_case": len(next(iter(results.values()))["trials"]),
            "wall": latency(wall), "scanning": latency(scanning), "startup_and_ipc": latency(startup),
            "per_scanner": {n: latency(v) for n, v in per_scanner.items()},
            "per_case_wall": {c: r["timing_ms"]["harness_wall"] for c, r in results.items()}}


# ----------------------------------------------------------------------------- SVG helpers


def svg(width: int, height: int, body: list[str], title: str) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" '
            f'height="{height}" font-family="{FONT}" role="img" aria-label="{escape(title)}">'
            f'<title>{escape(title)}</title><rect width="{width}" height="{height}" fill="{SURFACE}"/>'
            + "".join(body) + "</svg>\n")


def text(x, y, s, size=16, fill=INK, weight="normal", anchor="start", italic=False) -> str:
    style = ' font-style="italic"' if italic else ""
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" font-weight="{weight}" '
            f'text-anchor="{anchor}"{style}>{escape(str(s))}</text>')


def pill(x, y, verdict, w=150, h=30) -> str:
    fill, ink = VERDICT_STYLE[verdict]
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="15" fill="{fill}"/>'
            + text(x + w / 2, y + h / 2 + 6, verdict, 15, ink, "bold", "middle"))


# ----------------------------------------------------------------------------- figure 1


def figure_matrix(rows: list[dict], cases: int, trials: int) -> str:
    width, top, row_h = 1500, 130, 46
    body = [text(40, 48, "Detection comparison: reference engine vs. unified engine", 28, weight="bold"),
            text(40, 80, f"{cases} inert synthetic fixtures, ground truth BENIGN; each scanned {trials} times per "
                 "engine with identical results every time. Verdicts, not accuracy.", 17, INK2)]
    cols = {"case": 40, "ref": 520, "uni": 700, "note": 890}
    body += [text(cols["case"], top - 12, "Scenario / fixture", 15, MUTED, "bold"),
             text(cols["ref"], top - 12, "Reference (4 scanners)", 15, MUTED, "bold"),
             text(cols["uni"], top - 12, "Unified engine", 15, MUTED, "bold"),
             text(cols["note"], top - 12, "What the unified engine changes", 15, MUTED, "bold")]
    y = top
    for title, _ in SCENARIOS:
        body.append(f'<line x1="40" x2="{width - 40}" y1="{y}" y2="{y}" stroke="{AXIS}" stroke-width="1"/>')
        body.append(text(40, y + 28, title, 18, INK, "bold"))
        y += 40
        for row in (r for r in rows if r["scenario"] == title):
            changed = row["reference"] != row["unified"]
            if changed:
                body.append(f'<rect x="30" y="{y - 4}" width="{width - 60}" height="{row_h - 4}" rx="6" '
                            f'fill="none" stroke="{INK}" stroke-width="2"/>')
            body.append(text(56, y + 24, f"{row['id'].split('-')[0]}  {row['label']}", 16))
            body.append(pill(cols["ref"], y + 4, row["reference"]))
            body.append(pill(cols["uni"], y + 4, row["unified"]))
            body.append(text(cols["note"], y + 24, ("Verdict changed. " if changed else "") + row["caption"], 15,
                             INK if changed else INK2, "bold" if changed else "normal"))
            y += row_h
    body.append(text(40, y + 34, "Outlined row: the only verdict that differs. All other changes are evidence: findings "
                     "added, superseded or qualified (see comparison.md).", 15, INK2))
    return svg(width, int(y + 60), body, "Detection comparison matrix")


# ----------------------------------------------------------------------------- figure 2


def figure_pdf(reference: dict, unified: dict) -> str:
    width, height = 1500, 640
    body = [text(40, 48, "Why 5a and 5b get different verdicts: evidence must share one action chain", 28,
                 weight="bold"),
            text(40, 80, "Both PDFs: an /OpenAction JavaScript action and one embedded text file. They differ only in "
                 "whether the script names that file.", 17, INK2)]
    panels = [("5a-pdf-auto-js-unrelated-attachment", 40, "app.alert(1)", False),
              ("5b-pdf-auto-js-exports-attachment", 780, "exportDataObject({cName: \"f\"})", True)]
    for case, x, script, linked in panels:
        ref, uni = reference[case], unified[case]
        auto_ref = next(f for f in ref["findings"] if f["rule_id"] == "PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD")
        engine = [f for f in uni["findings"] if f["scanner"] == "pdf-chains" and f["severity"] != "INFO"]
        body.append(text(x, 130, f"{case.split('-')[0]}: {CAPTION[case][0]}", 22, weight="bold"))

        def box(bx, by, label, sub):
            return (f'<rect x="{bx}" y="{by}" width="200" height="74" rx="8" fill="#eef3fb" stroke="{REFERENCE_COLOR}" '
                    f'stroke-width="2"/>' + text(bx + 100, by + 31, label, 16, INK, "bold", "middle")
                    + text(bx + 100, by + 55, sub, 13, INK2, anchor="middle"))
        body += [box(x, 160, "catalog /OpenAction", "trigger: document opens"),
                 box(x + 250, 160, "JavaScript action", script[:30]),
                 box(x + 500, 160, "embedded file 'f'", "notes.txt (inert text)"),
                 f'<line x1="{x + 200}" y1="197" x2="{x + 244}" y2="197" stroke="{INK}" stroke-width="2"/>',
                 f'<path d="M{x + 238} 191 L{x + 248} 197 L{x + 238} 203 Z" fill="{INK}"/>']
        if linked:
            body += [f'<line x1="{x + 450}" y1="197" x2="{x + 494}" y2="197" stroke="{INK}" stroke-width="3"/>',
                     f'<path d="M{x + 488} 190 L{x + 499} 197 L{x + 488} 204 Z" fill="{INK}"/>',
                     text(x + 475, 258, "same chain: the script exports 'f'", 15, INK, "bold", "middle")]
        else:
            body += [f'<line x1="{x + 450}" y1="197" x2="{x + 498}" y2="197" stroke="{MUTED}" stroke-width="2" '
                     f'stroke-dasharray="6 5"/>', text(x + 475, 258, "no link: the script never names 'f'", 15, INK2,
                                                       anchor="middle")]
        body += [text(x, 320, "Reference PDF scanner (co-occurrence anywhere in the file)", 16, MUTED, "bold"),
                 text(x, 348, f"{auto_ref['rule_id']}  {auto_ref['severity']}", 16),
                 pill(x, 362, ref["verdicts"]["aggregate"], 170),
                 text(x, 440, "Unified engine (same action chain required)", 16, MUTED, "bold")]
        body += [text(x, 468 + 26 * i, f"{f['rule_id']}  {f['severity']}", 16) for i, f in enumerate(engine)]
        body.append(pill(x, 482 + 26 * (len(engine) - 1), uni["verdicts"]["aggregate"], 170))
    body.append(text(40, height - 30, "Rule IDs and verdicts as recorded in the frozen runs. Severity policy: HIGH -> "
                     "MALICIOUS, LOW/MEDIUM -> SUSPICIOUS (app/decision).", 15, INK2))
    return svg(width, height, body, "PDF correlation comparison, cases 5a and 5b")


# ----------------------------------------------------------------------------- figure 3


def figure_latency(ref_t: dict, uni_t: dict) -> str:
    width, height = 1500, 800
    n = ref_t["cases"] * ref_t["trials_per_case"]
    work = f"{ref_t['scanning']['median_ms']:.1f} and {uni_t['scanning']['median_ms']:.1f} ms"
    body = [text(40, 48, f"Latency: worker start-up dominates; detection work is {work} (p50)", 28, weight="bold"),
            text(40, 80, f"Per scan, {ref_t['cases']} fixtures x {ref_t['trials_per_case']} trials = {n} scans per "
                 "engine, one Windows 11 laptop, same session. Bars: p50; thin line: p50 to p95. Trials are "
                 "repeated scans of the same fixtures, not independent samples.", 16, INK2)]

    def panel(x, y, w, title, unit, rows, scale_max, step):
        out = [text(x, y, title, 19, INK, "bold")]
        plot_x, plot_w, bar_h = x + 190, w - 260, 34
        ticks = [step * i for i in range(int(scale_max / step) + 1)]
        top, bottom = y + 22, y + 22 + len(rows) * 58
        for t in ticks:
            px = plot_x + plot_w * t / scale_max
            out += [f'<line x1="{px:.1f}" x2="{px:.1f}" y1="{top}" y2="{bottom}" stroke="{GRID}" stroke-width="1"/>',
                    text(px, bottom + 22, f"{t:g}", 14, MUTED, anchor="middle")]
        out.append(text(plot_x + plot_w / 2, bottom + 46, unit, 14, MUTED, anchor="middle"))
        for i, (label, color, stats) in enumerate(rows):
            by = top + 12 + i * 58
            p50, p95 = stats["median_ms"], stats["p95_ms"]
            bw, ww = plot_w * p50 / scale_max, plot_w * p95 / scale_max
            out += [text(x, by + bar_h / 2 + 6, label, 16),
                    f'<rect x="{plot_x}" y="{by}" width="{bw:.1f}" height="{bar_h}" rx="4" fill="{color}"/>',
                    f'<line x1="{plot_x + bw:.1f}" x2="{plot_x + ww:.1f}" y1="{by + bar_h / 2}" y2="{by + bar_h / 2}" '
                    f'stroke="{INK}" stroke-width="2"/>',
                    f'<line x1="{plot_x + ww:.1f}" x2="{plot_x + ww:.1f}" y1="{by + 9}" y2="{by + bar_h - 9}" '
                    f'stroke="{INK}" stroke-width="2"/>',
                    text(plot_x + ww + 10, by + bar_h / 2 + 6, f"p50 {p50:.1f} · p95 {p95:.1f}", 15, INK2)]
        out.append(f'<line x1="{plot_x}" x2="{plot_x}" y1="{top}" y2="{bottom}" stroke="{AXIS}" stroke-width="1"/>')
        return out

    wall_max = max(ref_t["wall"]["p95_ms"], uni_t["wall"]["p95_ms"])
    work_max = max(ref_t["scanning"]["p95_ms"], uni_t["scanning"]["p95_ms"])
    body += panel(40, 140, 1420, "A. Whole scan (wall time, including worker start-up)", "milliseconds",
                  [("Reference", REFERENCE_COLOR, ref_t["wall"]), ("Unified", UNIFIED_COLOR, uni_t["wall"])],
                  _nice(wall_max * 1.1), _step(wall_max * 1.1))
    body += panel(40, 345, 1420, "B. Start-up and IPC (wall minus detection work)", "milliseconds",
                  [("Reference", REFERENCE_COLOR, ref_t["startup_and_ipc"]),
                   ("Unified", UNIFIED_COLOR, uni_t["startup_and_ipc"])],
                  _nice(wall_max * 1.1), _step(wall_max * 1.1))
    body += panel(40, 550, 1420, "C. Detection work inside the worker (sum of scanner times)", "milliseconds",
                  [("Reference", REFERENCE_COLOR, ref_t["scanning"]), ("Unified", UNIFIED_COLOR, uni_t["scanning"])],
                  _nice(work_max * 1.1), _step(work_max * 1.1))
    body.append(text(40, height - 18, f"Panels A and B share one axis (0 to {_nice(wall_max * 1.1):g} ms); panel C "
                     f"has its own (0 to {_nice(work_max * 1.1):g} ms). Source: summary.json, frozen runs.", 15, INK2))
    return svg(width, height, body, "Latency comparison, reference vs unified engine")


def _step(v: float) -> float:
    for s in (0.25, 0.5, 1, 2, 5, 10, 25, 50, 100, 200, 250, 500):
        if v / s <= 8:
            return s
    return 1000


def _nice(v: float) -> float:
    s = _step(v)
    return s * -(-v // s)


# ----------------------------------------------------------------------------- figure 4

# The approved architecture (FigJam board HT9iPI8a8LIdn1OrxPBidB, frame 12:134, read Nov 6, 2026):
# every section, node, label and connector as it is there. Positions are the board's canvas
# coordinates; only the empty band between sections 03 and 04 is narrowed (SHIFT) for print.
SECTIONS = [  # id, name, x, y, w, h, fill, stroke
    ("01", "01 INPUT", 3776, 914, 928, 272, "#e8f1fe", "#7fb4f0"),
    ("02", "02 ISOLATED ANALYSIS", 4864, 1066, 640, 449, "#e6f6f4", "#7fd3c7"),
    ("03", "03 CUSTOM DETECTION", 5680, 1048, 528, 608, "#efeafd", "#b39ef0"),
    ("04", "04 EVIDENCE AND DECISION", 7024, 1264, 1192, 329, "#fdf3e1", "#f0c873"),
    ("05", "05 OFFLINE RESEARCH VALIDATION", 5856, 1952, 928, 272, "#eef0f3", "#b8bfc8"),
]
NODES = {  # id: (label, section or None, x, y, w, h, shape, fill, stroke); x/y relative to section
    "2:41": ("Document Upload", "01", 48, 48, 224, 128, "pill", "#cfe5ff", "#3d8fe0"),
    "2:44": ("Type and Size Gate", "01", 336, 48, 224, 128, "box", "#cfe5ff", "#3d8fe0"),
    "2:47": ("Quarantine Buffer", "01", 656, 96, 224, 128, "box", "#cfe5ff", "#3d8fe0"),
    "2:51": ("Restricted Scan Worker", "02", 48, 81, 224, 128, "box", "#cbf3ee", "#2fb8a6"),
    "2:54": ("Format Router", "02", 368, 81, 224, 128, "box", "#cbf3ee", "#2fb8a6"),
    "2:57": ("Time and Memory Limits", "02", 368, 273, 224, 128, "box", "#d2f2cc", "#43b04a"),
    "2:61": ("Adapted Signature Matcher", "03", 48, 48, 224, 128, "box", "#ddd3fd", "#8c6be0"),
    "2:64": ("PDF Object and Stream Analysis", "03", 48, 240, 224, 128, "box", "#ddd3fd", "#8c6be0"),
    "2:67": ("OOXML and OLE Analysis", "03", 48, 432, 224, 128, "box", "#ddd3fd", "#8c6be0"),
    "2:71": ("Normalize Findings", "04", 48, 117, 224, 128, "box", "#fde9a6", "#e7b52c"),
    "2:74": ("Contextual Evidence Correlation", "04", 336, 117, 224, 128, "box", "#fde9a6", "#e7b52c"),
    "2:77": ("Deterministic Risk Policy", "04", 624, 81, 200, 200, "diamond", "#fde0c2", "#ee9a45"),
    "2:80": ("Verdict and Evidence Report", "04", 920, 50, 224, 128, "pill", "#cdf3d2", "#45b856"),
    "2:84": ("Reference Scanners", "05", 48, 48, 224, 128, "box", "#dcdcdc", "#9a9a9a"),
    "2:87": ("Comparative Benchmark", "05", 352, 96, 224, 128, "box", "#dcdcdc", "#9a9a9a"),
    "2:90": ("Coverage and Latency", "05", 656, 16, 224, 128, "box", "#dcdcdc", "#9a9a9a"),
    "2:94": ("Fail Closed", None, 6165, 768, 224, 128, "box", "#ffc9bf", "#e8604c"),
}
EDGES = [  # (from, to, label, dashed)
    ("2:41", "2:44", "", False), ("2:44", "2:47", "", False), ("2:47", "2:51", "", False),
    ("2:51", "2:54", "", False), ("2:51", "2:57", "", True), ("2:54", "2:61", "", False),
    ("2:54", "2:64", "", False), ("2:54", "2:67", "", False), ("2:61", "2:71", "", False),
    ("2:64", "2:71", "", False), ("2:67", "2:71", "", False), ("2:71", "2:74", "", False),
    ("2:74", "2:77", "", False), ("2:77", "2:80", "", False), ("2:44", "2:94", "Invalid file", True),
    ("2:51", "2:94", "Error or timeout", True), ("2:94", "2:80", "", False),
    ("2:80", "2:87", "Offline evaluation", True), ("2:84", "2:87", "", True), ("2:87", "2:90", "", True),
]
SHIFT_FROM, SHIFT = 7000, 560  # board x at or beyond which everything moves left, and by how much


def figure_architecture() -> str:
    x0, y0, scale = 3776 - 40, 768 - 100, 0.4
    sec = {s[0]: s for s in SECTIONS}

    def place(x, y):
        return ((x - (SHIFT if x >= SHIFT_FROM else 0) - x0) * scale, (y - y0) * scale)

    def rect_of(node_id):
        label, s, x, y, w, h, *_ = NODES[node_id]
        ax, ay = (sec[s][2] + x, sec[s][3] + y) if s else (x, y)
        px, py = place(ax, ay)
        return px, py, w * scale, h * scale

    body = [text(16, 30, "Approved architecture of the FilesMagic custom security engine", 22, weight="bold")]
    for _, name, x, y, w, h, fill, stroke in SECTIONS:
        px, py = place(x, y)
        body += [f'<rect x="{px:.1f}" y="{py:.1f}" width="{w * scale:.1f}" height="{h * scale:.1f}" rx="10" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>', text(px + 4, py - 7, name, 12, INK2, "bold")]
    for a, b, label, dashed in EDGES:
        ax, ay, aw, ah = rect_of(a)
        bx, by, bw, bh = rect_of(b)
        dash = ' stroke-dasharray="6 5"' if dashed else ""
        if b == "2:94":  # up to Fail Closed
            pts = [(ax + aw / 2, ay), (ax + aw / 2, by + bh / 2), (bx, by + bh / 2)]
        elif a == "2:94":  # Fail Closed down to the verdict
            pts = [(ax + aw, ay + ah / 2), (bx + bw / 2, ay + ah / 2), (bx + bw / 2, by)]
        elif a == "2:80":  # offline evaluation, around the right side to the benchmark
            right = ax + aw + 24
            pts = [(ax + aw, ay + ah / 2), (right, ay + ah / 2), (right, by + bh / 2), (bx + bw, by + bh / 2)]
        else:
            mid = (ax + aw + bx) / 2
            pts = [(ax + aw, ay + ah / 2), (mid, ay + ah / 2), (mid, by + bh / 2), (bx, by + bh / 2)]
        d = "M" + " L".join(f"{x:.1f} {y:.1f}" for x, y in pts)
        (ex, ey), (fx, fy) = pts[-2], pts[-1]
        ux, uy = (fx > ex) - (fx < ex), (fy > ey) - (fy < ey)
        head = (f"M{fx:.1f} {fy:.1f} L{fx - 8 * ux - 5 * uy:.1f} {fy - 8 * uy - 5 * ux:.1f} "
                f"L{fx - 8 * ux + 5 * uy:.1f} {fy - 8 * uy + 5 * ux:.1f} Z")
        body += [f'<path d="{d}" fill="none" stroke="#5f5e5a" stroke-width="1.6"{dash}/>',
                 f'<path d="{head}" fill="#5f5e5a"/>']
        if label:
            lx, ly = ((pts[0][0] + pts[-1][0]) / 2, pts[1][1] - 6) if b == "2:94" else (pts[1][0] + 6, (pts[1][1] + pts[2][1]) / 2)
            body.append(text(lx, ly, label, 12, INK2, anchor="middle" if b == "2:94" else "start", italic=True))
    for node_id, (label, _, _, _, w, h, shape, fill, stroke) in NODES.items():
        px, py, pw, ph = rect_of(node_id)
        if shape == "diamond":
            cx, cy = px + pw / 2, py + ph / 2
            body.append(f'<path d="M{cx} {py} L{px + pw} {cy} L{cx} {py + ph} L{px} {cy} Z" fill="{fill}" '
                        f'stroke="{stroke}" stroke-width="1.5"/>')
        else:
            rx = ph / 2 if shape == "pill" else 6
            body.append(f'<rect x="{px:.1f}" y="{py:.1f}" width="{pw:.1f}" height="{ph:.1f}" rx="{rx:.1f}" '
                        f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>')
        words, lines, line = label.split(), [], ""
        for word in words:  # wrap to the box
            if len(line + " " + word) * 6.2 > pw - 12 and line:
                lines.append(line)
                line = word
            else:
                line = (line + " " + word).strip()
        lines.append(line)
        for i, ln in enumerate(lines):
            body.append(text(px + pw / 2, py + ph / 2 + 4 + (i - (len(lines) - 1) / 2) * 14, ln, 11.5, INK, anchor="middle"))
    xs = [place(s[2] + s[4], 0)[0] for s in SECTIONS]
    return svg(int(max(xs) + 170), int(place(0, 2224)[1] + 30), body, "Approved custom engine architecture")


# ----------------------------------------------------------------------------- report


def markdown(rows: list[dict], ref_t: dict, uni_t: dict, ref_env: dict) -> str:
    out = [f"Frozen runs: commit `{ref_env['engine_commit'][:7]}`, {ref_t['cases']} fixtures x "
           f"{ref_t['trials_per_case']} trials per engine.", "",
           "| Case | Role | Reference | Unified | Added (non-correlation) | Removed | Qualified | Undetermined |",
           "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        fmt = lambda fs: "<br>".join(f"{s}:{i} ({v})" for s, i, v in fs) or "-"  # noqa: E731
        out.append(f"| {r['id']} | {r['role']} | {r['reference']} | {r['unified']} | {fmt(r['added'])} | "
                   f"{fmt(r['removed'])} | {'<br>'.join(r['qualified']) or '-'} | {', '.join(r['undetermined']) or '-'} |")
    out += ["", "| Latency (ms, pooled) | Reference p50 | Reference p95 | Unified p50 | Unified p95 |", "|---|---|---|---|---|"]
    for k in ("wall", "startup_and_ipc", "scanning"):
        out.append(f"| {k} | {ref_t[k]['median_ms']} | {ref_t[k]['p95_ms']} | {uni_t[k]['median_ms']} | {uni_t[k]['p95_ms']} |")
    out += ["", "| Scanner (unified run) | runs | p50 ms | p95 ms |", "|---|---|---|---|"]
    out += [f"| {n} | {s['n']} | {s['median_ms']} | {s['p95_ms']} |" for n, s in uni_t["per_scanner"].items()]
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    ref_env, reference = load(args.run / "reference" / "results.json")
    uni_env, unified = load(args.run / "unified" / "results.json")
    if ref_env["engine_commit"] != uni_env["engine_commit"]:
        raise SystemExit("the two runs are from different commits")
    rows = compare(reference, unified)
    check_captions(rows)
    ref_t, uni_t = timing(reference), timing(unified)
    args.out.mkdir(parents=True, exist_ok=True)
    figures = {"fig1-detection-matrix.svg": figure_matrix(rows, ref_t["cases"], ref_t["trials_per_case"]),
               "fig2-pdf-correlation-5a-5b.svg": figure_pdf(reference, unified),
               "fig3-latency.svg": figure_latency(ref_t, uni_t),
               "fig4-architecture.svg": figure_architecture()}
    for name, content in figures.items():
        (args.out / name).write_text(content, encoding="utf-8")
    summary = {"commit": ref_env["engine_commit"], "environment": ref_env, "rows": rows,
               "timing": {"reference": ref_t, "unified": uni_t}}
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2))
    (args.out / "comparison.md").write_text(markdown(rows, ref_t, uni_t, ref_env), encoding="utf-8")
    print(f"Wrote {', '.join(figures)}, summary.json, comparison.md to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
