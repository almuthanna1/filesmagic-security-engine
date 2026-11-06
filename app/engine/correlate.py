"""Chain findings and evidence correlation for the custom engine.

PdfChainScanner turns app.engine.pdf_chains into findings, one rule per kind of automatic chain,
each with a fixed severity (nothing is added up):

  ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT     HIGH    launches or exports an embedded file
                                                        of this document
  ENGINE_PDF_AUTO_CHAIN_LAUNCH                  HIGH    contains a /Launch action
  ENGINE_PDF_AUTO_CHAIN_OPENS_EMBEDDED_DOCUMENT MEDIUM  GoToE opens an embedded document (not
                                                        analysed recursively)
  ENGINE_PDF_AUTO_CHAIN_SCRIPT                  MEDIUM  runs JavaScript, no payload on the chain
  ENGINE_PDF_CHAINS_REPAIRED                    INFO    pypdf repaired the structure

correlate() then reconciles the reference scanners' findings with the chains, by rule ID:
  - PDF_AUTO_JAVASCRIPT and PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD (PDF scanner) are superseded: the
    first marks everything reachable from an automatic trigger as automatic, the second combines
    an automatic script with any attachment anywhere in the file. Superseded only when both the
    PDF scanner and the chain scanner completed on an unrepaired structure; otherwise kept.
  - PDF_JavaScript_With_Automatic_Action (YARA-X, bytes only) is never removed: a signature can
    see bytes a parser does not. When no automatic script chain exists it is marked unconfirmed.
Every decision is listed in one INFO finding, ENGINE_CORRELATION, so nothing changes silently.
"""

from app.engine import pdf_chains
from app.models import Finding, Severity, WorkerReport
from app.scanners.custom.indicators import NOT_PROOF, clean, listing

NAME = "pdf-chains"
CATEGORY = "pdf-action-chain"
SUPERSEDED = {("pdf", "PDF_AUTO_JAVASCRIPT"), ("pdf", "PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD")}
UNCONFIRMED_SIGNATURE = ("yara-x", "PDF_JavaScript_With_Automatic_Action")
SCRIPT_RULES = {"ENGINE_PDF_AUTO_CHAIN_SCRIPT", "ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT"}

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


def finding(rule: str, severity: Severity, description: str) -> Finding:
    return Finding(scanner=NAME, category=CATEGORY, severity=severity, rule_id=rule,
                   description=description + (NOT_PROOF if severity != Severity.INFO else ""))


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
    found = [finding(rule, RULES[rule][0], f"{RULES[rule][1]} Evidence: {listing(items)}.")
             for rule, items in evidence.items()]
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


def correlate(report: WorkerReport) -> WorkerReport:
    status = {s.name: s.status for s in report.scanners}
    rules = {(f.scanner, f.rule_id) for f in report.findings}
    if status.get(NAME) != "completed" or ("pdf-chains", "ENGINE_PDF_CHAINS_REPAIRED") in rules:
        return report  # no unambiguous chain view: every reference finding stands
    notes, findings = [], report.findings
    if status.get("pdf") == "completed" and (dropped := sorted(r for s, r in rules & SUPERSEDED)):
        findings = [f for f in findings if (f.scanner, f.rule_id) not in SUPERSEDED]
        notes.append(f"superseded {', '.join(dropped)} (PDF scanner) by the action-chain rules")
    if UNCONFIRMED_SIGNATURE in rules and not any(s == NAME and r in SCRIPT_RULES for s, r in rules):
        notes.append(f"{UNCONFIRMED_SIGNATURE[1]} (YARA-X, byte co-occurrence) kept but not confirmed: "
                     "no automatic action chain runs a script")
    if notes:
        findings = findings + [finding("ENGINE_CORRELATION", Severity.INFO, "Evidence correlation: "
                                       + "; ".join(notes) + ".")]
    return report.model_copy(update={"findings": findings})
