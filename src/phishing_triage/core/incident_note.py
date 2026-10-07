"""The Incident Note: a plain-text summary of a Triage Report for a ticket.

Generating it is a pure function: it only reads the report.
More sections (Not Checked, Recommended Actions) arrive in later tickets.
"""

from phishing_triage.core.attachments import display_filename
from phishing_triage.core.findings import Finding
from phishing_triage.core.observables import Observable, ObservableKind
from phishing_triage.core.report import TriageReport
from phishing_triage.core.urls import defang_domain, defang_url

# How each kind of Observable is labelled in the Observables section.
OBSERVABLE_LABELS = {
    ObservableKind.URL: "URL",
    ObservableKind.DOMAIN: "Domain",
    ObservableKind.SHA256: "SHA-256",
}


def incident_note(report: TriageReport) -> str:
    """Return the Incident Note for a Triage Report, ready to paste into a ticket."""
    sections = [_summary_line(report), _key_findings(report), _observables(report)]
    return "\n\n".join(sections) + "\n"


def _summary_line(report: TriageReport) -> str:
    """One line a busy analyst can scan: Verdict, Score, sender and subject."""
    sender = report.from_address or "(no From address)"
    subject = report.subject or "(no subject)"
    return (
        f"Verdict: {report.verdict.upper()} | Score: {report.score}/100"
        f" | Sender: {sender} | Subject: {subject}"
    )


def _key_findings(report: TriageReport) -> str:
    """Each Finding with its evidence, so the Verdict is justified in the ticket."""
    lines = ["Key Findings:"]
    lines += [f"- {describe_finding(finding)}" for finding in report.findings]
    if not report.findings:
        lines.append("- None.")
    return "\n".join(lines)


def _observables(report: TriageReport) -> str:
    """Every Observable, defanged so nobody can click it from the ticket.

    These are not yet IOCs: nothing has been judged malicious until
    Reputation Lookups arrive.
    """
    lines = ["Observables (defanged):"]
    lines += [f"- {_observable_line(o, report)}" for o in report.observables]
    if not report.observables:
        lines.append("- None.")
    return "\n".join(lines)


def _observable_line(observable: Observable, report: TriageReport) -> str:
    """One Observable, made safe to paste: URLs and domains defanged, hashes named."""
    label = OBSERVABLE_LABELS[observable.kind]
    if observable.kind is ObservableKind.URL:
        return f"{label}: {defang_url(observable.value)}"
    if observable.kind is ObservableKind.DOMAIN:
        return f"{label}: {defang_domain(observable.value)}"
    # A hash isn't clickable, so it needs no defanging. Name the file(s) it belongs to.
    filenames = [
        display_filename(a.filename) for a in report.attachments if a.sha256 == observable.value
    ]
    return f"{label}: {observable.value} ({', '.join(filenames)})"


def describe_finding(finding: Finding) -> str:
    """One Finding as text: its evidence, then its weight."""
    if finding.decisive:
        return f"{finding.evidence} (decisive)"
    return f"{finding.evidence} (+{finding.points} points)"
