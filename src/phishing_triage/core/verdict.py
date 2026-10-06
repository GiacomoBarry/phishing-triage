"""Turning Findings into a Score and a Verdict (see ADR 0002)."""

from phishing_triage.core.findings import Finding
from phishing_triage.core.report import Verdict
from phishing_triage.core.settings import Settings

MAX_SCORE = 100


def score_and_verdict(
    findings: list[Finding], settings: Settings
) -> tuple[int, Verdict]:
    """Return the Score and the Verdict for a Triage's Findings.

    Any Decisive Finding makes the Verdict malicious, so a confirmed IOC can
    never be outvoted. Otherwise the Score's thresholds decide.
    """
    score = min(
        sum(finding.points for finding in findings if not finding.decisive),
        MAX_SCORE,
    )

    if any(finding.decisive for finding in findings):
        return score, Verdict.MALICIOUS
    if score >= settings.malicious_from:
        return score, Verdict.MALICIOUS
    if score >= settings.suspicious_from:
        return score, Verdict.SUSPICIOUS
    return score, Verdict.CLEAN
