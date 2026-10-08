"""The Incident Note: a plain-text summary of a Triage Report for a ticket.

Generating it is a pure function: it only reads the report. It has five
sections, in order: the summary line, Key Findings, the defanged
Observables, Not Checked and Recommended Actions.
"""

from phishing_triage.core.findings import Finding
from phishing_triage.core.observables import describe_observable
from phishing_triage.core.recommended_actions import recommended_actions
from phishing_triage.core.report import TriageReport


def incident_note(report: TriageReport) -> str:
    """Return the Incident Note for a Triage Report, ready to paste into a ticket."""
    sections = [
        _summary_line(report),
        _key_findings(report),
        _observables(report),
        _not_checked(report),
        _recommended_actions(report),
    ]
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

    Not every Observable is an IOC: the ones a Provider reported as
    malicious are listed again in Recommended Actions, to be blocked.
    """
    lines = ["Observables (defanged):"]
    lines += [f"- {describe_observable(o, report.attachments)}" for o in report.observables]
    if not report.observables:
        lines.append("- None.")
    return "\n".join(lines)


def _not_checked(report: TriageReport) -> str:
    """What no Provider checked, and why, so gaps are never mistaken for clean."""
    lines = ["Not Checked:"]
    if report.cap_reason:
        lines.append(report.cap_reason)
    lines += [
        f"- {describe_observable(item.observable, report.attachments)}: {'; '.join(item.reasons)}"
        for item in report.not_checked
    ]
    if not report.not_checked:
        lines.append("- Nothing: every Observable was checked by at least one Provider.")
    return "\n".join(lines)


def _recommended_actions(report: TriageReport) -> str:
    """Suggested next steps for the analyst. The tool never carries them out."""
    lines = ["Recommended Actions:"]
    lines += [f"- {action}" for action in recommended_actions(report)]
    return "\n".join(lines)


def describe_finding(finding: Finding) -> str:
    """One Finding as text: its evidence, then its weight."""
    if finding.decisive:
        return f"{finding.evidence} (decisive)"
    return f"{finding.evidence} (+{finding.points} points)"
