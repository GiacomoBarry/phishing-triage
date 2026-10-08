"""The core entry point: run one Triage on one email."""

import hashlib
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from importlib.metadata import version

from phishing_triage.core.attachments import extract_attachments
from phishing_triage.core.authentication import read_authentication_results
from phishing_triage.core.cache import LookupCache
from phishing_triage.core.clock import Clock, SystemClock
from phishing_triage.core.errors import NoAttachedEmailError, UnparseableAttachedEmailError, UnparseableEmailError
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
    Raises UnparseableEmailError if the bytes are not an email at all (the
    UnparseableAttachedEmailError kind if it is the attached email that isn't),
    and NoAttachedEmailError if `inner` is set but no email is attached.
    """
    clock = clock or SystemClock()
    now = datetime.fromtimestamp(clock.now(), UTC)
    chosen = _choose_email(raw_email, inner)
    raw_email, message = chosen.raw, chosen.message
    warnings = _wrapper_warnings(chosen)

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
        taken_from_wrapper_sha256=chosen.wrapper_sha256,
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


@dataclass(frozen=True)
class _ChosenEmail:
    """The email a Triage is run on, and how it relates to any Wrapper Email."""

    raw: bytes
    message: EmailMessage
    # The SHA-256 of the Wrapper Email it was taken from, or "" if it is the email given.
    wrapper_sha256: str
    emails_in_wrapper: int  # How many emails that Wrapper Email had attached (0 if none was used).
    emails_attached: int  # How many emails are attached directly to the chosen email.


def _choose_email(raw_email: bytes, inner: bool) -> _ChosenEmail:
    """Pick the email to triage: the one given, or (with `inner`) the first email attached inside it."""
    message = _parse(raw_email)
    attached_emails = find_attached_emails(raw_email)
    if not inner:
        return _ChosenEmail(
            raw_email, message, wrapper_sha256="", emails_in_wrapper=0, emails_attached=len(attached_emails)
        )

    if not attached_emails:
        raise NoAttachedEmailError("The email has no email attached, so there is no attached email to triage.")
    chosen = attached_emails[0]
    try:
        chosen_message = _parse(chosen)
    except UnparseableEmailError as error:
        raise UnparseableAttachedEmailError(f"The attached email is not a parseable email. {error}") from error
    return _ChosenEmail(
        chosen,
        chosen_message,
        wrapper_sha256=hashlib.sha256(raw_email).hexdigest(),
        emails_in_wrapper=len(attached_emails),
        emails_attached=len(find_attached_emails(chosen)),
    )


def _wrapper_warnings(chosen: _ChosenEmail) -> list[str]:
    """Warn that the email may be a Wrapper Email, or say that it was taken from inside one.

    The wording names no command-line flag: the core doesn't know how it was
    called. The CLI adds its own hint about --inner (ADR 0014).
    """
    if not chosen.wrapper_sha256:
        if chosen.emails_attached == 0:
            return []
        count = chosen.emails_attached
        has_attached = "an email attached" if count == 1 else f"{count} emails attached"
        which = "the attached email" if count == 1 else "the first attached email"
        return [
            f"This email has {has_attached}, so it may be a user's report (a Wrapper Email)"
            f" rather than the suspected phish itself. If so, triage {which} instead."
        ]

    warnings = ["Triaged the email attached inside a Wrapper Email, not the Wrapper Email itself."]
    if chosen.emails_in_wrapper > 1:
        warnings.append(
            f"The Wrapper Email has {chosen.emails_in_wrapper} emails attached. Only the first was triaged;"
            " extract the others by hand to triage them."
        )
    if chosen.emails_attached:
        warnings.append(
            "The triaged email has an email attached too. Only emails attached directly to the"
            " Wrapper Email can be triaged, so extract that one by hand to triage it."
        )
    return warnings


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
