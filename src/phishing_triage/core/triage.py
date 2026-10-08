"""The core entry point: run one Triage on one email."""

import hashlib
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from importlib.metadata import version

from phishing_triage.core.attachments import extract_attachments
from phishing_triage.core.authentication import read_authentication_results
from phishing_triage.core.cache import LookupCache
from phishing_triage.core.clock import Clock, SystemClock
from phishing_triage.core.errors import NoAttachedEmailError, UnparseableEmailError
from phishing_triage.core.findings import Finding, Rule, RuleInput
from phishing_triage.core.lookups import Progress, find_not_checked, run_lookups
from phishing_triage.core.observables import extract_observables
from phishing_triage.core.providers import Provider
from phishing_triage.core.received import find_claimed_origin, read_received_chain
from phishing_triage.core.report import TriageReport
from phishing_triage.core.rules import BUILT_IN_RULES
from phishing_triage.core.settings import Settings
from phishing_triage.core.verdict import cap_for_missing_evidence, score_and_verdict
from phishing_triage.core.wrapper import find_attached_emails

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
    clock: Clock | None = None,
    on_progress: Callable[[Progress], None] | None = None,
    cache: LookupCache | None = None,
    inner: bool = False,
) -> TriageReport:
    """Run one Triage on the raw bytes of an email and return its Triage Report.

    `rules` defaults to the built-in red-flag rules, and `clock` to the real
    clock, used to wait out Providers' rate limits. Tests can pass their own.
    `on_progress`, if given, is called as lookups start and while waiting, so
    the caller can show progress; the core itself never prints. `cache`, if
    given, supplies fresh earlier answers and keeps new ones. `inner` triages
    the email attached inside a Wrapper Email instead of the email itself.
    Raises UnparseableEmailError if the bytes are not an email at all, and
    NoAttachedEmailError if `inner` is set but no email is attached.
    """
    clock = clock or SystemClock()
    now = datetime.fromtimestamp(clock.now(), UTC)
    raw_email, message, taken_from_wrapper_sha256, warnings = _choose_email(raw_email, inner)

    from_address, display_name = _sender(message)
    if not from_address:
        warnings.append("The email has no From address.")

    authentication = read_authentication_results(message)
    received_hops = read_received_chain(message)
    claimed_origin = find_claimed_origin(received_hops, settings.trusted_relays)

    attachments = extract_attachments(raw_email)
    observables = extract_observables(message, attachments, claimed_origin.ip if claimed_origin else "")
    lookups = run_lookups(
        observables,
        providers,
        settings.url_cap,
        clock,
        on_progress or (lambda event: None),
        cache,
        settings.decisive_engines,
    )
    rule_input = RuleInput(
        message=message,
        observables=observables,
        attachments=attachments,
        lookups=lookups,
        authentication=authentication,
        claimed_origin=claimed_origin,
        now=now,
    )

    findings: list[Finding] = []
    for rule in rules:
        findings += rule(rule_input, settings)
    score, verdict_before_cap = score_and_verdict(findings, settings)
    not_checked = find_not_checked(observables, lookups)
    verdict, cap_reason = cap_for_missing_evidence(verdict_before_cap, not_checked)

    return TriageReport(
        report_id=str(uuid.uuid4()),
        analysed_at=now,
        tool_version=TOOL_VERSION,
        source_sha256=hashlib.sha256(raw_email).hexdigest(),
        taken_from_wrapper_sha256=taken_from_wrapper_sha256,
        from_address=from_address,
        display_name=display_name,
        subject=str(message.get("Subject", "")),
        authentication=authentication,
        received_hops=received_hops,
        claimed_origin=claimed_origin,
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


def _choose_email(raw_email: bytes, inner: bool) -> tuple[bytes, EmailMessage, str, list[str]]:
    """Pick the email to triage: the one given, or (with `inner`) the email attached inside it.

    Returns the chosen email's bytes and parsed message, the SHA-256 of the
    Wrapper Email it was taken from ("" if none) and any warnings about the choice.
    """
    message = _parse(raw_email)
    attached_emails = find_attached_emails(raw_email)
    count = len(attached_emails)
    if not inner:
        if count == 0:
            return raw_email, message, "", []
        has_attached = "an email attached" if count == 1 else f"{count} emails attached"
        which = "the attached email" if count == 1 else "the first attached email"
        return raw_email, message, "", [
            f"This email has {has_attached}, so it may be a user's report (a Wrapper Email)"
            f" rather than the suspected phish itself. Use --inner to triage {which} instead."
        ]

    if count == 0:
        raise NoAttachedEmailError("There is no email attached to triage instead.")
    wrapper_sha256 = hashlib.sha256(raw_email).hexdigest()
    chosen = attached_emails[0]
    warnings = ["Triaged the email attached inside a Wrapper Email, not the Wrapper Email itself."]
    if count > 1:
        warnings.append(
            f"The Wrapper Email has {count} emails attached. Only the first was triaged;"
            " extract the others by hand to triage them."
        )
    chosen_message = _parse(chosen)
    if find_attached_emails(chosen):
        warnings.append(
            "The triaged email has an email attached too. --inner only looks one level deep,"
            " so extract that one by hand to triage it."
        )
    return chosen, chosen_message, wrapper_sha256, warnings


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
