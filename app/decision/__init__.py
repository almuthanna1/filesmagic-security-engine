"""Deterministic verdict rules. Combines findings from all scanners into one verdict.

Rules, applied in order:
1. Any HIGH or CRITICAL finding           -> MALICIOUS
2. Any LOW or MEDIUM finding              -> SUSPICIOUS
3. No scanner ran, or any scanner failed  -> UNABLE_TO_SCAN
4. Otherwise (all scanners ran clean)     -> SAFE

Evidence wins over failures: a MALICIOUS finding from one scanner still counts
even if another scanner crashed. SAFE needs positive evidence that every
configured scanner actually analysed the file.
"""

from app.models import CoverageIssue, Finding, Reason, ScannerStatus, Severity, Verdict


def decide(findings: list[Finding], scanners_run: int, scanners_failed: int = 0, coverage_complete: bool = True) -> Verdict:
    severities = {f.severity for f in findings}
    if severities & {Severity.HIGH, Severity.CRITICAL}:
        return Verdict.MALICIOUS
    if severities & {Severity.LOW, Severity.MEDIUM}:
        return Verdict.SUSPICIOUS
    if scanners_run == 0 or scanners_failed > 0 or not coverage_complete:
        return Verdict.UNABLE_TO_SCAN
    return Verdict.SAFE


# ----------------------------------------------------------------------------- authorization policy
# docs/security-integration-v1.md is the contract for everything below.

_REPAIRED = "The document's internal structure is damaged; it could only be read after automatic repair."
_DECODE = "Part of the PDF's page content is damaged and could not be decoded, so it was not inspected."

#: Incomplete analysis caused by the document itself. Only these codes may be overridden with the
#: user's explicit consent. Any code not listed here (including a future one) is never eligible.
DOCUMENT_REASONS = {
    "PDF_ENCRYPTED_CONTENT_UNAVAILABLE": "The PDF's page content is password-protected, so it could not be inspected.",
    "PDF_CONTENT_FILTER_UNSUPPORTED": "The PDF stores page content in a compressed form this scanner does not decode.",
    "PDF_CONTENT_DECODE_FAILED": _DECODE,
    "PDF_CONTENT_LZW_DECODE_FAILED": _DECODE,
    "PDF_CONTENT_STREAM_UNRESOLVED": "A page of the PDF refers to content that is missing or not valid.",
    "PDF_CONTENT_STREAM_LIMIT": "The PDF has more page-content sections than the scanner inspects.",
    "PDF_CONTENT_TOTAL_LIMIT": "The PDF's page content is larger than the scanner inspects.",
    "PDF_PARSER_REPAIRED": _REPAIRED,
    "PDF_STRUCTURE_REPAIRED": _REPAIRED,
    "PDF_CHAIN_PARSER_REPAIRED": _REPAIRED,
    "PDF_ATTACHMENT_COVERAGE_INCOMPLETE": "Not every file attached inside the PDF could be inspected.",
    "CUSTOM_PDF_C1_COVERAGE_INCOMPLETE": "Some compressed object sections of the PDF could not be inspected.",
    "DOCUMENT_MALFORMED": "The document is damaged or truncated, so part of it could not be read.",
    "DOCUMENT_STRUCTURE_UNSUPPORTED": "The document's structure is invalid or exceeds the scanner's analysis limits.",
}

_OUR_SIDE = "The security check did not complete because of a problem on our side, not with your file."
#: The scan itself did not work, or cannot be trusted. Never eligible for override, never receipted.
OPERATIONAL_REASONS = {
    "WORKER_TIMEOUT": _OUR_SIDE,
    "WORKER_CRASHED": _OUR_SIDE,
    "WORKER_INVALID_REPORT": _OUR_SIDE,
    "WORKER_FAILED": _OUR_SIDE,
    "SCANNER_ROSTER_MISMATCH": _OUR_SIDE,
    "SCANNER_NOT_READY": _OUR_SIDE,
    "SCANNER_INTERNAL_ERROR": _OUR_SIDE,
    "ISOLATION_NOT_ENFORCED": "The scan did not run under the required security isolation.",
    "ISOLATION_UNVERIFIED": "The scan's security isolation could not be verified.",
}

#: Properties of the file that are not eligible for override. A code in none of the three tables
#: (e.g. a coverage code added by a later engine release) is treated like these.
UNOVERRIDABLE_REASONS = {
    "UNSUPPORTED_FILE_TYPE": "None of the security checks supports this file type.",
    "ANALYSIS_INCOMPLETE_UNCLASSIFIED": "The file could not be fully inspected, for a reason that does not allow an override.",
}

# YARA-X reads raw bytes: no document structure can make it fail, so its failures are ours.
_BYTE_SCANNERS = {"yara-x", "yara-x-engine"}
# Added by the worker for any failed scanner; the scanner's own status classifies it instead.
_FAILURE_COVERAGE = {"SCANNER_ANALYSIS_FAILED", "PDF_INTEGRITY_ANALYSIS_FAILED"}

EXPLANATIONS = {
    "allow": "No known threats were detected by the completed security checks. "
             "This is not a guarantee that the file is harmless.",
    "SUSPICIOUS": "The security checks found content that can be risky. Review the findings; "
                  "the file is converted only if you explicitly choose to continue.",
    "MALICIOUS": "The security checks found strong indicators of malicious content. This file cannot be converted.",
    "UNABLE_TO_SCAN": "The file could not be fully inspected, for the reasons listed. "
                      "You may choose to continue at your own risk.",
    "operational": "The security check could not be completed, so this file cannot be converted right now. "
                   "Please try again later.",
    "deny": "The file could not be fully inspected, and the reason does not allow an override. "
            "This file cannot be converted.",
}


def reason(code: str) -> Reason:
    if code in DOCUMENT_REASONS:
        return Reason(code=code, category="document", override_eligible=True, explanation=DOCUMENT_REASONS[code])
    if code in OPERATIONAL_REASONS:
        return Reason(code=code, category="operational", override_eligible=False, explanation=OPERATIONAL_REASONS[code])
    return Reason(code=code, category="document", override_eligible=False, explanation=UNOVERRIDABLE_REASONS.get(
        code, UNOVERRIDABLE_REASONS["ANALYSIS_INCOMPLETE_UNCLASSIFIED"]))


def classify(verdict: Verdict, scanners: list[ScannerStatus], coverage_issues: list[CoverageIssue],
             operational: list[str]) -> tuple[list[Reason], str, str]:
    """Reasons, authorization ("allow", "consent_required", "deny") and the user explanation.

    `operational` holds the API's own findings about the scan (worker failure, isolation,
    readiness). Consent can permit conversion only when every reason is a documented document
    reason; MALICIOUS and every operational reason deny, whatever else is true.
    """
    codes = list(operational)
    for s in scanners:
        if s.status != "failed" or s.error_kind == "worker":
            continue  # worker failures arrive in `operational` with their exact code
        if s.error_kind is None:
            codes.append("ISOLATION_UNVERIFIED")  # the strict worker refused to analyse
        elif s.name in _BYTE_SCANNERS or s.error_kind == "unexpected":
            codes.append("SCANNER_INTERNAL_ERROR")
        else:
            codes.append("DOCUMENT_MALFORMED" if s.error_kind == "malformed_input" else "DOCUMENT_STRUCTURE_UNSUPPORTED")
    codes += [i.code for i in coverage_issues if i.code not in _FAILURE_COVERAGE]
    if verdict == Verdict.UNABLE_TO_SCAN and not codes:
        codes.append("ANALYSIS_INCOMPLETE_UNCLASSIFIED")
    reasons = [reason(c) for c in dict.fromkeys(codes)]  # de-duplicated, in order

    if verdict == Verdict.MALICIOUS:
        return reasons, "deny", EXPLANATIONS["MALICIOUS"]
    if any(r.category == "operational" for r in reasons):
        return reasons, "deny", EXPLANATIONS["operational"]
    if not all(r.override_eligible for r in reasons):
        return reasons, "deny", EXPLANATIONS["deny"]
    if verdict == Verdict.SAFE:
        return reasons, "allow", EXPLANATIONS["allow"]
    return reasons, "consent_required", EXPLANATIONS[verdict.value]
