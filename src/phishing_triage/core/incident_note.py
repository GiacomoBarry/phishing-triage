"""The Incident Note: a plain-text summary of a Triage Report for a ticket.

Generating it is a pure function: it only reads the report.
More sections (Findings, IOCs, Not Checked, Recommended Actions) arrive
in later tickets.
"""

from phishing_triage.core.report import TriageReport


def incident_note(report: TriageReport) -> str:
    """Return the Incident Note for a Triage Report, ready to paste into a ticket."""
    return _summary_line(report) + "\n"


def _summary_line(report: TriageReport) -> str:
    """One line a busy analyst can scan: Verdict, Score, sender and subject."""
    sender = report.from_address or "(no From address)"
    subject = report.subject or "(no subject)"
    return (
        f"Verdict: {report.verdict.upper()} | Score: {report.score}/100"
        f" | Sender: {sender} | Subject: {subject}"
    )
