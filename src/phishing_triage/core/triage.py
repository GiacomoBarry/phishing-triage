"""The core entry point: run one Triage on one email."""

import hashlib
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from importlib.metadata import version

from phishing_triage.core.attachments import extract_attachments
from phishing_triage.core.errors import UnparseableEmailError
from phishing_triage.core.findings import Finding, Rule, RuleInput
from phishing_triage.core.lookups import find_not_checked, run_lookups
from phishing_triage.core.observables import extract_observables
from phishing_triage.core.providers import Provider
from phishing_triage.core.report import TriageReport
from phishing_triage.core.rules import BUILT_IN_RULES
from phishing_triage.core.settings import Settings
from phishing_triage.core.verdict import cap_for_missing_evidence, score_and_verdict

TOOL_VERSION = version("phishing-triage")

# Headers that real emails carry. Input with none of them isn't treated as an email.
STANDARD_EMAIL_HEADERS = frozenset(
    {
        "from", "to", "cc", "subject", "date", "message-id",
        "received", "return-path", "reply-to", "sender", "mime-version",
    }
)


def triage(
    raw_email: bytes,
    settings: Settings,
    providers: Sequence[Provider],
    rules: Sequence[Rule] = BUILT_IN_RULES,
) -> TriageReport:
    """Run one Triage on the raw bytes of an email and return its Triage Report.

    `rules` defaults to the built-in red-flag rules. Tests can pass their own.
    Raises UnparseableEmailError if the bytes are not an email at all.
    """
    message = _parse(raw_email)
    warnings: list[str] = []

    from_address, display_name = _sender(message)
    if not from_address:
        warnings.append("The email has no From address.")

    attachments = extract_attachments(message)
    observables = extract_observables(message, attachments)
    lookups = run_lookups(observables, providers)
    rule_input = RuleInput(
        message=message, observables=observables, attachments=attachments, lookups=lookups
    )

    findings: list[Finding] = []
    for rule in rules:
        findings += rule(rule_input, settings)
    score, verdict_before_cap = score_and_verdict(findings, settings)
    not_checked = find_not_checked(observables, lookups)
    verdict, cap_reason = cap_for_missing_evidence(verdict_before_cap, not_checked)

    return TriageReport(
        report_id=str(uuid.uuid4()),
        analysed_at=datetime.now(UTC),
        tool_version=TOOL_VERSION,
        source_sha256=hashlib.sha256(raw_email).hexdigest(),
        from_address=from_address,
        display_name=display_name,
        subject=str(message.get("Subject", "")),
        observables=observables,
        attachments=attachments,
        lookups=lookups,
        not_checked=not_checked,
        findings=findings,
        score=score,
        verdict=verdict,
        verdict_before_cap=verdict_before_cap,
        cap_reason=cap_reason,
        warnings=warnings,
    )


def _parse(raw_email: bytes) -> EmailMessage:
    """Parse raw bytes into an email message, refusing anything that isn't one.

    Python's parser accepts almost any input, and treats any line like
    "Note: hello" as a header. So the test for "this is an email" is that at
    least one standard email header is present.
    """
    message = BytesParser(policy=policy.default).parsebytes(raw_email)
    found_headers = {name.lower() for name in message.keys()}
    if not found_headers & STANDARD_EMAIL_HEADERS:
        raise UnparseableEmailError("No standard email headers were found.")
    assert isinstance(message, EmailMessage)  # guaranteed by policy.default
    return message


def _sender(message: EmailMessage) -> tuple[str, str]:
    """Return the From address and display name, or empty strings if absent."""
    from_header = message.get("From")
    if from_header is None or not from_header.addresses:
        return "", ""
    sender = from_header.addresses[0]
    return sender.addr_spec, sender.display_name
