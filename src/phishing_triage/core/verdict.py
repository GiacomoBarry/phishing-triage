"""Turning Findings into a Score and a Verdict (see ADR 0002)."""

from phishing_triage.core.findings import Finding
from phishing_triage.core.lookups import KINDS_NEEDING_EVIDENCE, NotChecked
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


def cap_for_missing_evidence(
    verdict: Verdict, not_checked: list[NotChecked]
) -> tuple[Verdict, str]:
    """Raise a clean Verdict to suspicious if any URL or attachment was Not Checked.

    Clean requires evidence: an unchecked link or attachment could be the
    payload. Returns the final Verdict and the reason it was raised ("" if not).
    """
    unchecked = [n for n in not_checked if n.observable.kind in KINDS_NEEDING_EVIDENCE]
    if verdict is not Verdict.CLEAN or not unchecked:
        return verdict, ""
    count = len(unchecked)
    noun = "URL or attachment was" if count == 1 else "URLs or attachments were"
    return Verdict.SUSPICIOUS, (
        f"Raised from clean to suspicious: {count} {noun} Not Checked,"
        " so there isn't the evidence to call this email clean."
    )
