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
Every decision is listed in one INFO finding, ENGINE_CORRELATION, so nothing changes silently.
"""

from app.engine import ooxml_links, pdf_chains, vba_chains
from app.models import Finding, Severity, WorkerReport
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
    return found


class PdfChainScanner:
    name = NAME

    def scan(self, filename: str, data: bytes) -> list[Finding] | None:
        result = pdf_chains.scan(data)
        return None if result is None else chain_findings(result)


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
    return found


def link_findings(result: ooxml_links.Links) -> list[Finding]:
    def make(rule: str, severity: Severity, text: str, items: list[str]) -> Finding:
        return finding(rule, severity, f"{text} Evidence: {listing([clean(i, 240) for i in items])}.",
                       scanner=LINKS, category="office-activation", evidence=items)

    by: dict[str, list[ooxml_links.Activation]] = {}
    for a in result.activations:
        by.setdefault(a.state, []).append(a)
    found = [make(*LINK_RULES[state], [f"{a.chain} ({a.why})" for a in items])
             for state, items in by.items() if state in LINK_RULES]
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


def correlate(report: WorkerReport) -> WorkerReport:
    status = {s.name: s.status for s in report.scanners}
    rules = {(f.scanner, f.rule_id) for f in report.findings}
    chains_ok = status.get(NAME) == "completed" and (NAME, "ENGINE_PDF_CHAINS_REPAIRED") not in rules
    drop, notes = set(), []
    if chains_ok and status.get("pdf") == "completed" and (found := rules & STRUCTURAL):
        drop |= found
        notes.append(f"replaced {', '.join(sorted(r for _, r in found))} (PDF scanner) by the action-chain rules")
    if status.get(SIGNATURES) == "completed" and REFERENCE_SIGNATURE in rules:
        drop.add(REFERENCE_SIGNATURE)
        notes.append(f"replaced {REFERENCE_SIGNATURE[1]} (YARA-X) by {REFINED_SIGNATURE[1]}, which "
                     + ("also matched" if REFINED_SIGNATURE in rules else
                        "did not match: the bytes show every /OpenAction and /AA here is not automatic"))
    claim = next((r for r in (REFINED_SIGNATURE, REFERENCE_SIGNATURE) if r in rules and r not in drop), None)
    if chains_ok and claim and not any(s == NAME and r in SCRIPT_RULES for s, r in rules):
        notes.append(f"{claim[1]} ({claim[0]}) kept but not confirmed: no automatic action chain runs a script")
    if status.get(VBA) == "completed" and REFERENCE_MACRO in rules:
        # ponytail: never removed. Lowering it on "no call path" needs the P-code checked for VBA
        # stomping, which olevba does only on files on disk; the worker cannot write any.
        if (VBA, "ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY") in rules:
            notes.append(f"{REFERENCE_MACRO[1]} (Office scanner) confirmed by a macro call path")
        elif (VBA, "ENGINE_VBA_NO_CALL_PATH") in rules:
            notes.append(f"{REFERENCE_MACRO[1]} (Office scanner) kept although the source shows no call path from "
                         "the automatic procedures to the dangerous operation: the P-code that may run instead "
                         "cannot be checked for VBA stomping here")
        else:
            notes.append(f"{REFERENCE_MACRO[1]} (Office scanner) kept: the macro call path could not be determined")
    if status.get(LINKS) == "completed":
        # Never removed either: an element this analysis does not model, or Office behaviour beyond
        # the specification, could still use a relationship the graph calls not activated.
        engine = {r for s, r in rules if s == LINKS}
        if REFERENCE_AUTOLOAD in rules:
            notes.append(f"{REFERENCE_AUTOLOAD[1]} (Office scanner) " + (
                "confirmed: a part Office loads references an external target used on open"
                if "ENGINE_OFFICE_EXTERNAL_ON_OPEN" in engine else
                "kept: whether the relationship is used could not be determined"
                if "ENGINE_OFFICE_ACTIVATION_UNDETERMINED" in engine else
                "kept although no part Office loads references it: its use is not demonstrated"))
        if found := sorted(r for s, r in rules & REFERENCE_OBJECTS):
            notes.append(f"{', '.join(found)} (Office scanner) kept; " + (
                "the object is shown in the document and runs only when activated"
                if "ENGINE_OFFICE_EMBEDDED_OBJECT_DISPLAYED" in engine else
                "no element shows the object in the document"
                if "ENGINE_OFFICE_EMBEDDED_OBJECT_NOT_DISPLAYED" in engine else
                "its display could not be determined"))
    if not notes:
        return report
    findings = [f for f in report.findings if (f.scanner, f.rule_id) not in drop]
    findings.append(finding("ENGINE_CORRELATION", Severity.INFO, "Evidence correlation: " + "; ".join(notes) + ".",
                            evidence=notes))
    return report.model_copy(update={"findings": findings})
