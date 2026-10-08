"""Recommended Actions: sensible next steps for the analyst, chosen from a fixed list.

The tool only ever suggests these. Every action here is just text: no code
path blocks, searches, resets or emails anything. The analyst stays in control.

Choosing them is a pure function of the Triage Report, like the Incident Note.
The whole choice is the RECOMMENDED_ACTIONS table at the bottom: one row per
action, saying when it applies and what it says.
"""

from collections.abc import Callable
from dataclasses import dataclass

from phishing_triage.core.observables import Observable, ObservableKind, defanged, describe_observable
from phishing_triage.core.providers import Outcome
from phishing_triage.core.report import TriageReport, Verdict
from phishing_triage.core.rules import (
    DISPLAY_NAME_IMPERSONATION,
    LOOKALIKE_DOMAIN,
    NEWLY_REGISTERED_DOMAIN,
    REPLY_TO_MISMATCH,
)

# Findings that suggest a fake login page: a link pretending to be someone it isn't.
CREDENTIAL_PHISHING_SIGNS = (LOOKALIKE_DOMAIN, DISPLAY_NAME_IMPERSONATION, NEWLY_REGISTERED_DOMAIN)

# Findings that suggest the email isn't really from who it says.
IMPERSONATION_SIGNS = (REPLY_TO_MISMATCH, DISPLAY_NAME_IMPERSONATION)


@dataclass(frozen=True)
class RecommendedAction:
    """One row of the table: when the action applies, and what it says."""

    # Does this action apply to the report?
    applies: Callable[[TriageReport], bool]
    # The suggestion, worded for a human. A function when the wording
    # quotes something from the report, such as the IOCs to block.
    says: str | Callable[[TriageReport], str]


# --- Small questions about the report ---


def _malicious_observables(report: TriageReport) -> list[Observable]:
    """Every Observable a Provider reported as malicious (each one a Decisive Finding), in email order."""
    flagged = {result.observable for result in report.lookups if result.outcome is Outcome.MALICIOUS}
    return [observable for observable in report.observables if observable in flagged]


def _sender_domain(report: TriageReport) -> Observable | None:
    """The sender domain Observable, or None if the email has no From domain."""
    return next((o for o in report.observables if o.kind is ObservableKind.SENDER_DOMAIN), None)


def _has(report: TriageReport, kind: ObservableKind) -> bool:
    """Did the email contain at least one Observable of this kind?"""
    return any(observable.kind is kind for observable in report.observables)


def _fired(report: TriageReport, rule_ids: tuple[str, ...]) -> bool:
    """Did any of these rules give a Finding?"""
    return any(finding.rule_id in rule_ids for finding in report.findings)


def _not_clean(report: TriageReport) -> bool:
    """Is the Verdict malicious or suspicious?"""
    return report.verdict is not Verdict.CLEAN


# --- When each action applies ---


def _has_malicious_lookups(report: TriageReport) -> bool:
    return bool(_malicious_observables(report))


def _malicious_with_sender_domain(report: TriageReport) -> bool:
    return report.verdict is Verdict.MALICIOUS and _sender_domain(report) is not None


def _not_clean_with_links(report: TriageReport) -> bool:
    return _not_clean(report) and _has(report, ObservableKind.URL)


def _not_clean_with_attachments(report: TriageReport) -> bool:
    return _not_clean(report) and _has(report, ObservableKind.SHA256)


def _may_have_stolen_passwords(report: TriageReport) -> bool:
    return _not_clean_with_links(report) and _fired(report, CREDENTIAL_PHISHING_SIGNS)


def _sender_may_be_impersonated(report: TriageReport) -> bool:
    return _fired(report, IMPERSONATION_SIGNS)


def _anything_not_checked(report: TriageReport) -> bool:
    """Was anything Not Checked, or the Verdict raised for missing evidence?"""
    return bool(report.not_checked or report.cap_reason)


def _clean_and_fully_checked(report: TriageReport) -> bool:
    return report.verdict is Verdict.CLEAN and not _anything_not_checked(report)


# --- Wording that quotes the report ---


def _block_iocs(report: TriageReport) -> str:
    """The block action, with each IOC defanged on its own indented line."""
    lines = ["Block these malicious URLs, domains or attachment hashes:"]
    lines += [f"  - {describe_observable(o, report.attachments)}" for o in _malicious_observables(report)]
    return "\n".join(lines)


def _block_sender_domain(report: TriageReport) -> str:
    sender_domain = _sender_domain(report)
    # Only called when _malicious_with_sender_domain is true, so there is one.
    assert sender_domain is not None
    return f"Block the sender domain {defanged(sender_domain)}."


# The fixed list, in the order the actions appear in the Incident Note.
RECOMMENDED_ACTIONS: tuple[RecommendedAction, ...] = (
    RecommendedAction(_has_malicious_lookups, _block_iocs),
    RecommendedAction(_malicious_with_sender_domain, _block_sender_domain),
    RecommendedAction(
        _not_clean,
        "Search all mailboxes for copies of this email (same sender or subject) and remove them.",
    ),
    RecommendedAction(_not_clean_with_links, "Check web proxy logs for anyone who visited the email's links."),
    RecommendedAction(_not_clean_with_attachments, "Check whether anyone opened the attachment."),
    RecommendedAction(
        _may_have_stolen_passwords,
        "If a recipient entered their password, reset it and revoke their active sessions.",
    ),
    RecommendedAction(
        _sender_may_be_impersonated,
        "Confirm with the apparent sender through a contact you already know, not the details in this email.",
    ),
    RecommendedAction(_anything_not_checked, "Check the Not Checked items by hand before closing the ticket."),
    RecommendedAction(
        _clean_and_fully_checked,
        "Close with no action, and tell the reporter the email looks safe.",
    ),
)


def recommended_actions(report: TriageReport) -> list[str]:
    """Return the text of every Recommended Action that applies to the report, in table order."""
    chosen = []
    for action in RECOMMENDED_ACTIONS:
        if action.applies(report):
            chosen.append(action.says if isinstance(action.says, str) else action.says(report))
    return chosen
