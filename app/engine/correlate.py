"""Chain findings and evidence correlation for the custom engine.

PdfChainScanner turns app.engine.pdf_chains into findings, one rule per kind of chain, each with
a fixed severity (nothing is added up):

  ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT     HIGH    automatic chain launches or exports an
                                                        embedded file of this document
  ENGINE_PDF_AUTO_CHAIN_LAUNCH                  HIGH    automatic chain contains a /Launch action
  ENGINE_PDF_AUTO_CHAIN_OPENS_EMBEDDED_DOCUMENT MEDIUM  automatic GoToE opens an embedded document
                                                        (not analysed recursively)
  ENGINE_PDF_AUTO_CHAIN_SCRIPT                  MEDIUM  automatic chain runs JavaScript, no payload
  ENGINE_PDF_USER_TRIGGERED_SCRIPT              INFO    scripts that run only on user interaction
  ENGINE_PDF_CHAINS_REPAIRED                    INFO    pypdf repaired the structure

correlate() then reconciles the reference scanners' findings, by rule ID. Each replacement has
its own precondition; if it does not hold, the reference finding stands (fail closed):
  - PDF_AUTO_JAVASCRIPT and PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD (PDF scanner) are replaced by the
    chain rules: the first marks everything reachable from an automatic trigger as automatic, the
    second combines an automatic script with any attachment anywhere in the file. Precondition:
    the PDF scanner and the chain scanner completed on an unrepaired structure.
  - PDF_JavaScript_With_Automatic_Action (YARA-X) is replaced by the engine's refined signature
    ENGINE_PDF_JavaScript_With_Automatic_Trigger (app/engine/rules/pdf.yar), which fires only
    where it fires and stays silent only where the bytes prove every trigger non-automatic.
    Precondition: the engine's YARA-X scanner completed. No parser result is involved, so the
    signature evidence stays independent of pypdf.
  - A signature claim of an automatic trigger that no automatic script chain confirms is kept and
    marked unconfirmed (a signature can see bytes a parser does not).
  - OFFICE_MACRO_AUTOEXEC_EXECUTION (Office scanner: an automatic entry and a dangerous capability
    anywhere in the same VBA project) is never removed. VbaChainScanner (app.engine.vba_chains)
    adds whether an automatic procedure's calls reach the capability: ENGINE_VBA_AUTOEXEC_REACHES_
    CAPABILITY (HIGH, with the call path) confirms it; ENGINE_VBA_NO_CALL_PATH and
    ENGINE_VBA_CALL_PATH_UNDETERMINED (INFO) qualify it. "No call path" holds for the source only:
    the P-code Office may run instead cannot be checked for VBA stomping in the isolated worker.
  - Accounting (benign-corpus validation, docs/evidence/benign-corpus): an engine finding may
    carry "accounts for <scanner>:<rule>" lines. It then replaces that reference finding, if both
    scanners completed (and, for PDF, the structure needed no repair). Only four rules may replace
    a finding of higher severity, each after examining every item behind it, and only up to the
    severity it was validated on (SUPERSEDING): a reference finding rated higher saw something
    this examination does not model, and stands.
      ENGINE_OFFICE_LOCAL_FILE_TARGETS (INFO) for OFFICE_EXTERNAL_NETWORK_PATH: every relationship
        behind it (listed exactly as the Office scanner lists them) is a picture (referenced only by
        a:blip or v:imagedata) or a linked workbook (only by externalBook, absoluteUrl, relativeUrl)
        whose target is an unambiguous drive path naming no host (app.engine.file_paths, RFC 8089).
        The type alone is not enough: an image relationship referenced by a hyperlink is a link.
        What it shows: the document does not direct Windows to a server of its author's choosing.
        Not that the drive is a local disk (a mapped drive or junction on the opening machine).
      ENGINE_OFFICE_LOCAL_TEMPLATE (LOW) for OFFICE_EXTERNAL_AUTOLOAD: every relationship behind it
        is an attached template on such a path, referenced only by w:attachedTemplate. Still LOW:
        the template is not inspected and can carry macros; only an author-chosen server is ruled out.
      ENGINE_PDF_ATTACHMENTS_VERIFIED (INFO) for PDF_EMBEDDED_FILE and PDF_Embedded_File: every
        attachment in every object of the file is, from its bytes, an OpenDocument package without
        code, embedded objects or automatically loaded content, under its type's extension (passive
        hyperlinks are allowed and counted), or a C2PA manifest store (Content Credentials) holding
        only data and pictures without script, active markup or external references, under a name
        without another extension (its signature is not validated); and no action runs a script,
        launches a file or opens an embedded document (app.engine.pdf_attachments, app.engine.c2pa).
      ENGINE_PDF_NO_ATTACHMENTS (INFO) for PDF_Embedded_File (YARA-X) only: a complete reading of
        every object of the file finds no file specification with /EF and no embedded file stream,
        and every byte sequence the signature matches is the key /EmbeddedFiles of an empty name tree
        (pdf_attachments, point 5), as removing an attachment or metadata often leaves it. The PDF
        scanner must also have completed with no attachment finding and no repair. Text that only
        contains the bytes, a non-empty or dangling tree, or an older revision keeps the signature.
    Any other accounting finding only merges a reference finding of the same or lower severity, so
    one piece of evidence is counted once (ENGINE_OFFICE_EXTERNAL_ON_OPEN for AUTOLOAD when every
    relationship behind it is used on open; ENGINE_PDF_ATTACHMENTS_UNVERIFIED, LOW, for the two
    LOW attachment findings). The reference scanner's name stays in the evidence line.
Every decision is listed in an INFO finding, ENGINE_CORRELATION, under the engine scanner that made
it, so nothing changes silently; its evidence ends with every reference finding that scanner
removed, as it was ("raw <scanner>:<rule> <SEVERITY>: <description>").
"""

import re

from app.engine import ooxml_links, pdf_chains, vba_chains
from app.engine.file_paths import local_drive_path
from app.models import MAX_COVERAGE_ISSUES, CoverageIssue, Finding, Severity, WorkerReport
from app.scanners.custom.indicators import NOT_PROOF, clean, listing

NAME = "pdf-chains"
CATEGORY = "pdf-action-chain"
SIGNATURES = "yara-x-engine"  # the engine's own YARA-X rules (app.engine.EngineSignatures)
STRUCTURAL = {("pdf", "PDF_AUTO_JAVASCRIPT"), ("pdf", "PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD")}
REFERENCE_SIGNATURE = ("yara-x", "PDF_JavaScript_With_Automatic_Action")
REFINED_SIGNATURE = (SIGNATURES, "ENGINE_PDF_JavaScript_With_Automatic_Trigger")
SCRIPT_RULES = {"ENGINE_PDF_AUTO_CHAIN_SCRIPT", "ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT"}
VBA = "vba-chains"
REFERENCE_MACRO = ("office", "OFFICE_MACRO_AUTOEXEC_EXECUTION")
LINKS = "ooxml-links"
REFERENCE_AUTOLOAD = ("office", "OFFICE_EXTERNAL_AUTOLOAD")
NETWORK_PATH = ("office", "OFFICE_EXTERNAL_NETWORK_PATH")
# Relationship type -> the only elements that may reference it: they load the target as data. A
# file: hyperlink can start a program, so a relationship any other element uses is not superseded.
DATA_ELEMENTS = {"image": {"blip", "imagedata"}, "externallinkpath": {"externalBook", "absoluteUrl", "relativeUrl"}}
SIGNATURE_ATTACHMENT = ("yara-x", "PDF_Embedded_File")
ATTACHMENT_REFERENCE = [("pdf", "PDF_EMBEDDED_FILE"), SIGNATURE_ATTACHMENT]
NO_ATTACHMENTS = (NAME, "ENGINE_PDF_NO_ATTACHMENTS")
# ENGINE_PDF_NO_ATTACHMENTS also needs the PDF scanner to agree: completed, no attachment, no repair.
PDF_DISAGREES = {("pdf", "PDF_EMBEDDED_FILE"), ("pdf", "PDF_EMBEDDED_EXECUTABLE"), ("pdf", "PDF_STRUCTURE_REPAIRED")}
# An engine finding names each reference finding it accounts for with this evidence line: all the
# relationships or attachments behind that finding, re-listed and examined by the engine.
ACCOUNTS = "accounts for {}:{}"
ACCOUNTS_LINE = re.compile(r"accounts for ([\w-]+):(\w+)")
# Only these may account for a reference finding of higher severity, up to the severity given: each
# rests on complete, independently examined evidence (module docstring). Any other engine finding
# may only merge a reference finding of the same or lower severity.
SUPERSEDING = {(LINKS, "ENGINE_OFFICE_LOCAL_FILE_TARGETS"): Severity.MEDIUM,
               (LINKS, "ENGINE_OFFICE_LOCAL_TEMPLATE"): Severity.MEDIUM,
               (NAME, "ENGINE_PDF_ATTACHMENTS_VERIFIED"): Severity.LOW,
               NO_ATTACHMENTS: Severity.LOW}
RANK = {s: i for i, s in enumerate(Severity)}
REFERENCE_OBJECTS = {("office", r) for r in ("OFFICE_EMBEDDED_OLE", "OFFICE_EMBEDDED_BINARY", "OFFICE_PACKAGE_OBJECT",
                                             "OFFICE_PACKAGE_EXECUTABLE", "OFFICE_EQUATION_EDITOR")}
# Risk policy for activation findings: severity follows what the target can do if the application
# fetches it, never the mere chance that it does. Whether anything is fetched depends on the
# consuming application: Office blocks external content by default in workbooks and presentations,
# and files from the internet open in Protected View (Microsoft support: "Block or unblock external
# content in Office documents"; "What is Protected View?"). So:
#   MEDIUM  a target that can bring code into the document when it opens: an attached template
#           (it can carry macros), a frame, an OLE link that updates automatically (as the
#           reference scanner's OFFICE_EXTERNAL_AUTOLOAD);
#   INFO    a linked picture: Word's ordinary "Link to File" output, which the C4-C6 policy keeps
#           below LOW ("LOW marks a structure that standard Office generators do not produce").
#           Its risk is a web beacon (the server learns the document was opened); credential
#           exposure through a UNC or file:// target is already OFFICE_EXTERNAL_NETWORK_PATH (MEDIUM).
LINK_RULES = {  # activation -> (rule, severity, summary); hyperlinks (click) are not reported
    ooxml_links.ON_OPEN: ("ENGINE_OFFICE_EXTERNAL_ON_OPEN", Severity.MEDIUM,
                          "A part Office loads references an external target the document asks for when it opens "
                          "(fetched unless the application blocks external content)."),
    ooxml_links.IMAGE: ("ENGINE_OFFICE_LINKED_PICTURE", Severity.INFO,
                        "The document shows a picture stored outside the file; it is fetched only if the application "
                        "loads external content, and then tells that server the document was opened."),
    ooxml_links.ON_ACTION: ("ENGINE_OFFICE_EXTERNAL_ON_USER_ACTION", Severity.INFO,
                            "External targets are used only when the user updates or expands them."),
    ooxml_links.DISPLAYED: ("ENGINE_OFFICE_EMBEDDED_OBJECT_DISPLAYED", Severity.INFO,
                            "Embedded objects are shown in the document; they run only when activated."),
    ooxml_links.UNDETERMINED: ("ENGINE_OFFICE_ACTIVATION_UNDETERMINED", Severity.INFO,
                               "Whether these relationships are used could not be determined."),
}

RULES = {  # rule -> (severity, summary)
    "ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT": (
        Severity.HIGH, "An automatic action chain launches or exports a file embedded in this PDF."),
    "ENGINE_PDF_AUTO_CHAIN_LAUNCH": (Severity.HIGH, "An automatic action chain contains a /Launch action."),
    "ENGINE_PDF_AUTO_CHAIN_OPENS_EMBEDDED_DOCUMENT": (
        Severity.MEDIUM, "An automatic action chain opens an embedded document, which this engine does not "
                         "analyse recursively."),
    "ENGINE_PDF_AUTO_CHAIN_SCRIPT": (
        Severity.MEDIUM, "An automatic action chain runs JavaScript; no embedded file is used on that chain."),
}


def finding(rule: str, severity: Severity, description: str, scanner: str = NAME, category: str = CATEGORY,
            evidence: list[str] = ()) -> Finding:
    """`evidence`: every item the description summarises (it shows three), for display as a list."""
    return Finding(scanner=scanner, category=category, severity=severity, rule_id=rule,
                   description=description + (NOT_PROOF if severity != Severity.INFO else ""),
                   evidence=[clean(e, 300) for e in list(evidence)[:50]])


def chain_text(chain: pdf_chains.Chain) -> str:
    steps = " -> ".join(f"{a.kind} ({a.where})" for a in chain.actions)
    return clean(f"{chain.trigger}: {steps}", 160)


def chain_findings(result: pdf_chains.PdfChains) -> list[Finding]:
    evidence: dict[str, list[str]] = {}
    for chain in (c for c in result.chains if c.automatic):
        linked = result.linked(chain)
        delivered = [f"{how}s {clean(name, 40)!r}" for _, name, how in linked if how in ("launch", "export")]
        opened = [f"opens {clean(name, 40)!r}" for _, name, how in linked if how == "open"]
        launches = [a for a in chain.actions if a.kind == "Launch" and not a.payload]
        if delivered:
            evidence.setdefault("ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT", []).append(
                f"{chain_text(chain)} ({', '.join(delivered)})")
        if launches:
            evidence.setdefault("ENGINE_PDF_AUTO_CHAIN_LAUNCH", []).append(
                f"{chain_text(chain)} (target {', '.join(repr(a.target) for a in launches)})")
        if opened:
            evidence.setdefault("ENGINE_PDF_AUTO_CHAIN_OPENS_EMBEDDED_DOCUMENT", []).append(
                f"{chain_text(chain)} ({', '.join(opened)})")
        if not delivered and any(a.script for a in chain.actions):
            evidence.setdefault("ENGINE_PDF_AUTO_CHAIN_SCRIPT", []).append(chain_text(chain))
    user = [chain_text(c) for c in result.chains if not c.automatic and any(a.script for a in c.actions)]
    found = [finding(rule, RULES[rule][0], f"{RULES[rule][1]} Evidence: {listing(items)}.", evidence=items)
             for rule, items in evidence.items()]
    if user:
        found.append(finding("ENGINE_PDF_USER_TRIGGERED_SCRIPT", Severity.INFO,
                             f"{len(user)} JavaScript action chain(s) run only on user interaction (a click, "
                             f"keystroke or form event), not automatically. Evidence: {listing(user)}.", evidence=user))
    if result.repaired:
        found.append(finding("ENGINE_PDF_CHAINS_REPAIRED", Severity.INFO,
                             f"The PDF structure needed {result.repaired} repair(s); chain analysis is a best-effort "
                             "reading, so reference findings are not superseded."))
    return found + attachment_findings(result)


def attachment_findings(result: pdf_chains.PdfChains) -> list[Finding]:
    """One finding for all attachments (app.engine.pdf_attachments). It accounts for the reference
    attachment findings only when the attachment list is complete."""
    if result.files_problem:
        return [finding("ENGINE_PDF_ATTACHMENTS_INCOMPLETE", Severity.INFO,
                        f"Attachments could not all be read ({clean(result.files_problem, 160)}); the reference "
                        "attachment findings stand.")]
    if not result.files:
        # No marker for the signature to have matched, one not explained, or a repaired reading.
        if not result.empty_trees or result.repaired:
            return []
        return [finding("ENGINE_PDF_NO_ATTACHMENTS", Severity.INFO,
                        "The PDF carries no attachment: every object of the file was read, and none is a file "
                        "specification with /EF or an embedded file stream. Each raw /EmbeddedFile byte sequence "
                        "is the key /EmbeddedFiles of an empty name tree, which names no file. Evidence: "
                        f"{listing(result.empty_trees)}.",
                        evidence=result.empty_trees + [ACCOUNTS.format(*SIGNATURE_ATTACHMENT)])]
    items = [f"{a.name}: {a.verified or 'not verified: ' + a.reason}" for a in result.files]
    actions = [chain_text(c) for c in result.chains if any(a.script or a.kind in ("Launch", "GoToE") for a in c.actions)]
    accounts = [ACCOUNTS.format(*r) for r in ATTACHMENT_REFERENCE]
    if all(a.verified for a in result.files) and not actions:
        return [finding("ENGINE_PDF_ATTACHMENTS_VERIFIED", Severity.INFO,
                        "Every attachment was read and verified from its bytes: an OpenDocument file without macros, "
                        "scripts, embedded objects or automatically loaded external content, saved under its type's "
                        "extension (it may hold hyperlinks, which open only on a click), or a C2PA manifest store "
                        "(Content Credentials) holding only data and pictures without script, active markup or "
                        "external references, whose signature was not validated. No action in this PDF runs a "
                        "script, launches a file or opens an embedded document. This shows what the attachments do "
                        f"not contain, not that they are harmless or authentic. Evidence: {listing(items)}.",
                        evidence=items + accounts)]
    why = [f"actions that could use an attachment: {listing(actions)}"] if actions else []
    return [finding("ENGINE_PDF_ATTACHMENTS_UNVERIFIED", Severity.LOW,
                    "The PDF carries attachments that could not be verified as content without code. "
                    f"Evidence: {listing([i for i in items if 'not verified' in i] + why)}.",
                    evidence=items + why + accounts)]


class PdfChainScanner:
    name = NAME

    def scan(self, filename: str, data: bytes) -> list[Finding] | None:
        result = pdf_chains.scan(data)
        return None if result is None else chain_findings(result)


# Keep source snippets small in API responses and browser-only scan history.
# The file is never opened or executed, and anything omitted is stated explicitly.
MAX_VBA_DISPLAY_MODULES = 8
MAX_VBA_DISPLAY_CHARS = 420
_UNSAFE_SOURCE_CONTROLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_SIMPLE_MSGBOX = re.compile(r'MsgBox\s+"((?:[^"]|"")*)"\s*', re.IGNORECASE)
_SIMPLE_SUB = re.compile(r"(?:Public\s+|Private\s+|Friend\s+)?Sub\s+[A-Za-z_]\w*\s*(?:\(\s*\))?",
                         re.IGNORECASE)


def _vba_behavior(source: str) -> str:
    """Describe only the exact three-statement message-box pattern, not arbitrary VBA."""
    lines = [line.strip() for line in source.splitlines()
             if line.strip() and not line.lstrip().startswith("'")
             and not re.match(r"(?i)^\s*(Attribute\s+VB_Name|Option\s+Explicit)\b", line)]
    if (len(lines) == 3 and _SIMPLE_SUB.fullmatch(lines[0])
            and (msg := _SIMPLE_MSGBOX.fullmatch(lines[1]))
            and lines[2].lower() == "end sub"):
        literal = msg.group(1).replace('""', '"')
        return f"When invoked, this procedure displays a message box: {clean(literal, 120)!r}. "
    return "Source was extracted but no complete behavior explanation is asserted. "


def _vba_source_findings(result: vba_chains.VbaChains) -> list[Finding]:
    found = []
    for module, source in result.sources[:MAX_VBA_DISPLAY_MODULES]:
        # Preserve indentation, line breaks and VBA literals. Never put input into HTML.
        displayed = _UNSAFE_SOURCE_CONTROLS.sub("?", source.replace("\r\n", "\n").replace("\r", "\n"))
        altered = displayed != source.replace("\r\n", "\n").replace("\r", "\n")
        clipped = len(displayed) > MAX_VBA_DISPLAY_CHARS
        excerpt = displayed[:MAX_VBA_DISPLAY_CHARS] if clipped else displayed
        module_name = clean(module, 48)
        shown = "excerpt limited" if clipped or altered else "complete extracted source"
        description = (
            f"Extracted VBA module {module_name!r} ({shown}). {_vba_behavior(source)}"
            "VBA source was not executed. Its compiled P-code was not verified for stomping; "
            "this INFO evidence does not alter the security verdict."
        )
        suffix = "\n[truncated: source continues]" if clipped else ""
        found.append(Finding(
            scanner=VBA, category="office-vba-source", severity=Severity.INFO,
            description=description, rule_id="ENGINE_VBA_SOURCE",
            evidence=[f"{module_name}:\n{excerpt}{suffix}"],
        ))
    if len(result.sources) > MAX_VBA_DISPLAY_MODULES:
        found.append(Finding(
            scanner=VBA, category="office-vba-source", severity=Severity.INFO,
            description=f"{len(result.sources) - MAX_VBA_DISPLAY_MODULES} additional VBA modules omitted "
                        "from the bounded source preview; not a complete source listing.",
            rule_id="ENGINE_VBA_SOURCE_OMITTED",
        ))
    return found


def vba_findings(result: vba_chains.VbaChains) -> list[Finding]:
    def make(rule: str, severity: Severity, text: str, items: list[str]) -> Finding:
        return finding(rule, severity, text, scanner=VBA, category="office-macro-chain", evidence=items)

    by = {o: [e for e in result.entries if e.outcome == o] for o in (vba_chains.LINKED, vba_chains.NO_PATH,
                                                                     vba_chains.UNDETERMINED)}
    found = []
    if linked := by[vba_chains.LINKED]:
        paths = [" -> ".join(clean(p, 60) for p in e.path) + f" ({'; '.join(e.capabilities)})" for e in linked]
        found.append(make("ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY", Severity.HIGH,
                          "An automatically running macro procedure reaches a dangerous operation through its calls. "
                          f"Evidence: {listing(paths)}.", paths))
    reasons = [clean(r, 120) for r in dict.fromkeys([r for e in by[vba_chains.UNDETERMINED] for r in e.reasons]
                                                    + result.problems)]
    if reasons:
        found.append(make("ENGINE_VBA_CALL_PATH_UNDETERMINED", Severity.INFO,
                          "Whether automatically running macro code reaches a dangerous operation could not be "
                          f"determined. Evidence: {listing(reasons)}.", reasons))
    if result.outcome == vba_chains.NO_PATH and by[vba_chains.NO_PATH]:
        entries = [clean(e.entry, 60) for e in by[vba_chains.NO_PATH]]
        found.append(make("ENGINE_VBA_NO_CALL_PATH", Severity.INFO,
                          "No call path leads from the automatically running macro procedures to a dangerous "
                          "operation in the extracted source. The compiled P-code was not checked (VBA stomping). "
                          f"Entries: {listing(entries)}.", entries))
    return found + _vba_source_findings(result)


def link_findings(result: ooxml_links.Links) -> list[Finding]:
    def make(rule: str, severity: Severity, text: str, items: list[str], accounts: list[str] = ()) -> Finding:
        return finding(rule, severity, f"{text} Evidence: {listing([clean(i, 240) for i in items])}.",
                       scanner=LINKS, category="office-activation", evidence=[*items, *accounts])

    reference = result.reference or {}
    paths, autoload = reference.get(NETWORK_PATH[1], []), reference.get(REFERENCE_AUTOLOAD[1], [])
    acts = [result.activation(t) for t in autoload]
    local_templates = result.reference is not None and bool(autoload) and all(
        t.type.lower() == "attachedtemplate" and local_drive_path(t.target) and a is not None
        and a.state == ooxml_links.ON_OPEN and a.elements == ("attachedTemplate",) for t, a in zip(autoload, acts))

    def loaded_as_data(t: ooxml_links.ReferenceTarget) -> bool:
        a = result.activation(t)
        return a is not None and bool(a.elements) and set(a.elements) <= DATA_ELEMENTS.get(t.type.lower(), set())

    by: dict[str, list[ooxml_links.Activation]] = {}
    for a in result.activations:
        if not (local_templates and a in acts):
            by.setdefault(a.state, []).append(a)
    # The same relationships as the Office scanner's OFFICE_EXTERNAL_AUTOLOAD, all used on open: one finding.
    merged = result.reference is not None and bool(autoload) and not local_templates and all(
        a is not None and a.state == ooxml_links.ON_OPEN for a in acts)
    found = [make(*LINK_RULES[state], [f"{a.chain} ({a.why})" for a in items],
                  [ACCOUNTS.format(*REFERENCE_AUTOLOAD)] if merged and state == ooxml_links.ON_OPEN else [])
             for state, items in by.items() if state in LINK_RULES]
    if local_templates:
        found.append(make("ENGINE_OFFICE_LOCAL_TEMPLATE", Severity.LOW,
                          "The document attaches a template from a drive path when it opens. The path names no host "
                          "(RFC 8089), so the document does not fetch a template from a server its author chose "
                          "(remote template injection); but Word loads that template, which is outside this file and "
                          "was not inspected, and a template can carry macros. The drive may still be network storage "
                          "the opening machine maps.",
                          [f"{a.chain} ({a.why})" for a in acts], [ACCOUNTS.format(*REFERENCE_AUTOLOAD)]))
    if result.reference is not None and paths and all(local_drive_path(t.target) and loaded_as_data(t) for t in paths):
        found.append(make("ENGINE_OFFICE_LOCAL_FILE_TARGETS", Severity.INFO,
                          "Every target the Office scanner reports as a network path is a picture or linked workbook, "
                          "used only as data, on a drive path that names no host (RFC 8089), so the document does not "
                          "direct Windows to a server its author chose. A drive or folder on the opening machine can "
                          "still be network storage that machine maps; the files are outside this document and were "
                          "not inspected.", [f"{t.rels_part} {t.id} ({t.type}) -> {t.target}" for t in paths],
                          [ACCOUNTS.format(*NETWORK_PATH)]))
    idle = by.get(ooxml_links.NOT_ACTIVATED, [])
    if external := [a for a in idle if a.relationship.external]:
        found.append(make("ENGINE_OFFICE_EXTERNAL_NOT_ACTIVATED", Severity.INFO,
                          "External relationships are declared, but nothing shows that Office uses them.",
                          [f"{a.relationship.id} -> {a.relationship.target}: {a.why}" for a in external]))
    internal = [a for a in idle if not a.relationship.external]
    if internal or result.unrelated_objects:
        found.append(make("ENGINE_OFFICE_EMBEDDED_OBJECT_NOT_DISPLAYED", Severity.INFO,
                          "Embedded object parts are present, but no element shows them in the document.",
                          [f"{a.relationship.target}: {a.why}" for a in internal]
                          + [f"{p}: no relationship leads to it" for p in result.unrelated_objects]))
    return found


class LinkScanner:
    name = LINKS

    def scan(self, filename: str, data: bytes) -> list[Finding] | None:
        result = ooxml_links.scan(data)
        return None if result is None else link_findings(result)


class VbaChainScanner:
    name = VBA

    def scan(self, filename: str, data: bytes) -> list[Finding] | None:
        result = vba_chains.scan(data)
        return None if result is None else vba_findings(result)


def accounted(f: Finding) -> list[tuple[str, str]]:
    """The reference findings (scanner, rule) an engine finding accounts for (ACCOUNTS lines)."""
    return [m.groups() for e in f.evidence if (m := ACCOUNTS_LINE.fullmatch(e))]


def correlate(report: WorkerReport) -> WorkerReport:
    status = {s.name: s.status for s in report.scanners}
    rules = {(f.scanner, f.rule_id) for f in report.findings}
    chains_ok = status.get(NAME) == "completed" and (NAME, "ENGINE_PDF_CHAINS_REPAIRED") not in rules
    coverage = list(report.coverage_issues)
    for scanner, rule, code, detail in [
        (NAME, "ENGINE_PDF_CHAINS_REPAIRED", "PDF_CHAIN_PARSER_REPAIRED", "PDF action-chain parsing required repair."),
        (NAME, "ENGINE_PDF_ATTACHMENTS_INCOMPLETE", "PDF_ATTACHMENT_COVERAGE_INCOMPLETE", "PDF attachment coverage is incomplete."),
        ("pdf", "PDF_STRUCTURE_REPAIRED", "PDF_STRUCTURE_REPAIRED", "PDF structural parsing required repair."),
        ("custom", "CUSTOM_PDF_COVERAGE_LIMITED", "CUSTOM_PDF_C1_COVERAGE_INCOMPLETE",
         "Custom PDF escaped-name inspection did not cover every object stream."),
    ]:
        if (scanner, rule) in rules and len(coverage) < MAX_COVERAGE_ISSUES and not any(issue.code == code for issue in coverage):
            coverage.append(CoverageIssue(code=code, scanner=scanner, detail=detail))
    report = report.model_copy(update={"coverage_complete": not coverage, "coverage_issues": coverage})
    # drop: reference finding -> the engine scanner that replaced it; notes: engine scanner -> its decisions
    drop, notes = {}, {}

    def note(scanner: str, text: str) -> None:
        notes.setdefault(scanner, []).append(text)

    if chains_ok and status.get("pdf") == "completed" and (found := rules & STRUCTURAL):
        drop |= dict.fromkeys(found, NAME)
        note(NAME, f"replaced {', '.join(sorted(r for _, r in found))} (PDF scanner) by the action-chain rules")
    if status.get(SIGNATURES) == "completed" and REFERENCE_SIGNATURE in rules:
        drop[REFERENCE_SIGNATURE] = SIGNATURES
        note(SIGNATURES, f"replaced {REFERENCE_SIGNATURE[1]} (YARA-X) by {REFINED_SIGNATURE[1]}, which "
             + ("also matched" if REFINED_SIGNATURE in rules else
                "did not match: the bytes show every /OpenAction and /AA here is not automatic"))
    claim = next((r for r in (REFINED_SIGNATURE, REFERENCE_SIGNATURE) if r in rules and r not in drop), None)
    if chains_ok and claim and not any(s == NAME and r in SCRIPT_RULES for s, r in rules):
        note(NAME, f"{claim[1]} ({claim[0]}) kept but not confirmed: no automatic action chain runs a script")

    # Accounting: an engine finding that re-listed and examined everything behind a reference
    # finding replaces it, keeping the reference scanner's name in its evidence. Both scanners must
    # have completed (and the PDF structure needed no repair). Lowering the severity is allowed only
    # for SUPERSEDING rules; anything else may only merge a finding of the same or lower severity.
    for f in report.findings:
        for scanner, rule in accounted(f):
            behind = [r for r in report.findings if (r.scanner, r.rule_id) == (scanner, rule)]
            if (not behind or status.get(scanner) != "completed" or status.get(f.scanner) != "completed"
                    or (f.scanner == NAME and not chains_ok)
                    or ((f.scanner, f.rule_id) == NO_ATTACHMENTS and (status.get("pdf") != "completed"
                                                                      or rules & PDF_DISAGREES))):
                continue
            highest = max(RANK[r.severity] for r in behind)
            lower, ceiling = highest > RANK[f.severity], SUPERSEDING.get((f.scanner, f.rule_id))
            if lower and (ceiling is None or highest > RANK[ceiling]):
                continue
            drop[(scanner, rule)] = f.scanner
            note(f.scanner, f"{'superseded' if lower else 'merged'} {rule} ({scanner}) into {f.rule_id}"
                 + (", which examined every item behind it" if lower else ": the same evidence, counted once"))

    if status.get(VBA) == "completed" and REFERENCE_MACRO in rules:
        # ponytail: never removed. Lowering it on "no call path" needs the P-code checked for VBA
        # stomping, which olevba does only on files on disk; the worker cannot write any.
        if (VBA, "ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY") in rules:
            note(VBA, f"{REFERENCE_MACRO[1]} (Office scanner) confirmed by a macro call path")
        elif (VBA, "ENGINE_VBA_NO_CALL_PATH") in rules:
            note(VBA, f"{REFERENCE_MACRO[1]} (Office scanner) kept although the source shows no call path from "
                      "the automatic procedures to the dangerous operation: the P-code that may run instead "
                      "cannot be checked for VBA stomping here")
        else:
            note(VBA, f"{REFERENCE_MACRO[1]} (Office scanner) kept: the macro call path could not be determined")
    if status.get(LINKS) == "completed":
        # Kept unless accounted for above: an element this analysis does not model, or Office
        # behaviour beyond the specification, could still use a relationship the graph calls not activated.
        engine = {r for s, r in rules if s == LINKS}
        if REFERENCE_AUTOLOAD in rules and REFERENCE_AUTOLOAD not in drop:
            note(LINKS, f"{REFERENCE_AUTOLOAD[1]} (Office scanner) " + (
                "confirmed: a part Office loads references an external target used on open"
                if "ENGINE_OFFICE_EXTERNAL_ON_OPEN" in engine else
                "kept: whether the relationship is used could not be determined"
                if "ENGINE_OFFICE_ACTIVATION_UNDETERMINED" in engine else
                "kept although no part Office loads references it: its use is not demonstrated"))
        if found := sorted(r for s, r in rules & REFERENCE_OBJECTS):
            note(LINKS, f"{', '.join(found)} (Office scanner) kept; " + (
                "the object is shown in the document and runs only when activated"
                if "ENGINE_OFFICE_EMBEDDED_OBJECT_DISPLAYED" in engine else
                "no element shows the object in the document"
                if "ENGINE_OFFICE_EMBEDDED_OBJECT_NOT_DISPLAYED" in engine else
                "its display could not be determined"))
    if not notes:
        return report
    findings = [f for f in report.findings if (f.scanner, f.rule_id) not in drop]
    raw = {}  # every removed reference finding, as it was, under the scanner that removed it (audit trail)
    for f in report.findings:
        if owner := drop.get((f.scanner, f.rule_id)):
            raw.setdefault(owner, []).append(f"raw {f.scanner}:{f.rule_id} {f.severity.value}: {f.description}")
    findings += [finding("ENGINE_CORRELATION", Severity.INFO, "Evidence correlation: " + "; ".join(items) + ".",
                         scanner=scanner, category="evidence-correlation", evidence=items + raw.get(scanner, []))
                 for scanner, items in notes.items()]
    return report.model_copy(update={"findings": findings})
