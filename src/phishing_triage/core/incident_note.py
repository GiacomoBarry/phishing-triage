"""The Incident Note: a plain-text summary of a Triage Report for a ticket.

Generating it is a pure function: it only reads the report.
More sections (IOCs, Not Checked, Recommended Actions) arrive in later
tickets.
"""

from phishing_triage.core.findings import Finding
from phishing_triage.core.report import TriageReport


def incident_note(report: TriageReport) -> str:
    """Return the Incident Note for a Triage Report, ready to paste into a ticket."""
    sections = [_summary_line(report), _key_findings(report)]
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


def describe_finding(finding: Finding) -> str:
    """One Finding as text: its evidence, then its weight."""
    if finding.decisive:
        return f"{finding.evidence} (decisive)"
    return f"{finding.evidence} (+{finding.points} points)"
