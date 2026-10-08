"""Recommended Actions: sensible next steps for the analyst, chosen from a fixed list.

The tool only ever suggests these. Every action here is just text: no code
path blocks, searches, resets or emails anything. The analyst stays in control.

Choosing them is a pure function of the Triage Report, like the Incident Note.
The whole choice is the RECOMMENDED_ACTIONS table at the bottom: one row per
action, saying when it applies and what it says (ADR 0013).
"""

from collections.abc import Callable
from dataclasses import dataclass

from phishing_triage.core.observables import ObservableKind, describe_observable
from phishing_triage.core.report import TriageReport, Verdict
from phishing_triage.core.rules import (
    DISPLAY_NAME_IMPERSONATION,
    LOOKALIKE_DOMAIN,
    NEWLY_REGISTERED_DOMAIN,
    REPLY_TO_MISMATCH,
)
from phishing_triage.core.urls import defang_domain

# Findings that suggest a fake login page: a link pretending to be someone it isn't.
_CREDENTIAL_PHISHING_SIGNS = (LOOKALIKE_DOMAIN, DISPLAY_NAME_IMPERSONATION, NEWLY_REGISTERED_DOMAIN)

# Findings that suggest the email isn't really from who it says.
_IMPERSONATION_SIGNS = (REPLY_TO_MISMATCH, DISPLAY_NAME_IMPERSONATION)


@dataclass(frozen=True)
class RecommendedAction:
    """One row of the table: when the action applies, and what it says."""

    # Does this action apply to the report?
    applies: Callable[[TriageReport], bool]
    # The suggestion, worded for a human. It takes the report so the wording
    # can quote from it, such as the IOCs to block.
    says: Callable[[TriageReport], str]


# --- Small questions about the report ---


def _sender_domain_to_block(report: TriageReport) -> str:
    """The sender domain to block on its own, or "" if there isn't one.

    Only a malicious email's sender domain is blocked. If a Provider flagged
    the sender domain itself, it is already in the IOCs to block, so it isn't
    blocked a second time.
    """
    if report.verdict is not Verdict.MALICIOUS:
        return ""
    sender_domain = next((o for o in report.observables if o.kind is ObservableKind.SENDER_DOMAIN), None)
    if sender_domain is None or sender_domain in report.iocs():
        return ""
    return sender_domain.value


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


def _has_iocs(report: TriageReport) -> bool:
    return bool(report.iocs())


def _has_sender_domain_to_block(report: TriageReport) -> bool:
    return bool(_sender_domain_to_block(report))


def _not_clean_with_links(report: TriageReport) -> bool:
    return _not_clean(report) and _has(report, ObservableKind.URL)


def _not_clean_with_attachments(report: TriageReport) -> bool:
    return _not_clean(report) and _has(report, ObservableKind.SHA256)


def _may_have_stolen_passwords(report: TriageReport) -> bool:
    return _not_clean_with_links(report) and _fired(report, _CREDENTIAL_PHISHING_SIGNS)


def _sender_may_be_impersonated(report: TriageReport) -> bool:
    return _fired(report, _IMPERSONATION_SIGNS)


def _anything_not_checked(report: TriageReport) -> bool:
    """Was anything Not Checked, or the Verdict raised for missing evidence?"""
    return bool(report.not_checked or report.cap_reason)


# --- What each action says ---


def _fixed(text: str) -> Callable[[TriageReport], str]:
    """Wording that is the same whatever the report."""

    def says(report: TriageReport) -> str:
        return text

    return says


def _block_iocs(report: TriageReport) -> str:
    """The block action, with each IOC defanged on its own indented line."""
    lines = ["Block these malicious URLs, domains or attachment hashes:"]
    lines += [f"  - {describe_observable(o, report.attachments)}" for o in report.iocs()]
    return "\n".join(lines)


def _block_sender_domain(report: TriageReport) -> str:
    return f"Block the sender domain {defang_domain(_sender_domain_to_block(report))}."


# Every action that asks the analyst to do something, in the order they appear in the Incident Note.
_ACTIONS_TO_TAKE: tuple[RecommendedAction, ...] = (
    RecommendedAction(_has_iocs, _block_iocs),
    RecommendedAction(_has_sender_domain_to_block, _block_sender_domain),
    RecommendedAction(
        _not_clean,
        _fixed("Search all mailboxes for copies of this email (same sender or subject) and remove them."),
    ),
    RecommendedAction(
        _not_clean_with_links,
        _fixed("Check web proxy logs for anyone who visited the email's links."),
    ),
    RecommendedAction(_not_clean_with_attachments, _fixed("Check whether anyone opened the attachment.")),
    RecommendedAction(
        _may_have_stolen_passwords,
        _fixed("If a recipient entered their password, reset it and revoke their active sessions."),
    ),
    RecommendedAction(
        _sender_may_be_impersonated,
        _fixed(
            "Confirm with the apparent sender through a contact you already know,"
            " not the details in this email."
        ),
    ),
    RecommendedAction(
        _anything_not_checked,
        _fixed("Check the Not Checked items by hand before closing the ticket."),
    ),
)


def _nothing_else_to_do(report: TriageReport) -> bool:
    """Is the email clean, fully checked, and is there no other action to take?"""
    return (
        report.verdict is Verdict.CLEAN
        and not _anything_not_checked(report)
        and not any(action.applies(report) for action in _ACTIONS_TO_TAKE)
    )


# The fixed list, in the order the actions appear in the Incident Note.
# Closing comes last, and only when no other action applies.
RECOMMENDED_ACTIONS: tuple[RecommendedAction, ...] = _ACTIONS_TO_TAKE + (
    RecommendedAction(
        _nothing_else_to_do,
        _fixed("Close with no action, and tell the reporter the email looks safe."),
    ),
)


def recommended_actions(report: TriageReport) -> list[str]:
    """Return the text of every Recommended Action that applies to the report, in table order."""
    return [action.says(report) for action in RECOMMENDED_ACTIONS if action.applies(report)]
