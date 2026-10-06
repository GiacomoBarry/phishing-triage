"""The built-in red-flag rules. Each one returns zero or more Findings."""

from email.message import EmailMessage

from phishing_triage.core.findings import Finding, Rule
from phishing_triage.core.settings import Settings

REPLY_TO_MISMATCH = "reply_to_mismatch"


def reply_to_mismatch(message: EmailMessage, settings: Settings) -> list[Finding]:
    """Find Reply-To addresses on a different domain from the From address.

    Replies to such an email go somewhere other than the apparent sender,
    a common trick in invoice and payroll fraud. Every Reply-To address is
    checked, because a reply goes to all of them.
    """
    from_domains = _domains(message, "From")
    if not from_domains:
        return []
    from_domain = from_domains[0]

    other_domains = [d for d in _domains(message, "Reply-To") if d != from_domain]
    if not other_domains:
        return []

    if len(other_domains) == 1:
        described = f"Reply-To domain {other_domains[0]} differs"
    else:
        described = f"Reply-To domains {', '.join(other_domains)} differ"
    return [
        Finding(
            rule_id=REPLY_TO_MISMATCH,
            points=settings.points[REPLY_TO_MISMATCH],
            decisive=False,
            evidence=f"{described} from From domain {from_domain}.",
        )
    ]


def _domains(message: EmailMessage, header_name: str) -> list[str]:
    """Return the lowercased domains of a header's addresses, without repeats."""
    header = message.get(header_name)
    if header is None:
        return []
    domains = [str(address.domain).lower() for address in header.addresses]
    return list(dict.fromkeys(domain for domain in domains if domain))


BUILT_IN_RULES: tuple[Rule, ...] = (reply_to_mismatch,)
