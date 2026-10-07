"""The built-in red-flag rules. Each one returns zero or more Findings."""

import re
from email.message import EmailMessage

from phishing_triage.core.attachments import (
    Attachment,
    display_filename,
    extension_of,
    has_hidden_characters,
    previous_extension_of,
)
from phishing_triage.core.findings import Finding, Rule, RuleInput
from phishing_triage.core.lookalike import imitated_domain, is_genuine
from phishing_triage.core.observables import LABELS, ObservableKind, defanged
from phishing_triage.core.providers import URLHAUS, Outcome
from phishing_triage.core.settings import Settings
from phishing_triage.core.urls import defang_url, host_of

REPLY_TO_MISMATCH = "reply_to_mismatch"
DISPLAY_NAME_IMPERSONATION = "display_name_impersonation"
LOOKALIKE_DOMAIN = "lookalike_domain"
URL_SHORTENER = "url_shortener"
RISKY_ATTACHMENT = "risky_attachment"
KNOWN_MALICIOUS = "known_malicious"
URLHAUS_DOMAIN_LISTED = "urlhaus_domain_listed"

# Extensions a "double extension" hides behind: the part the reader is meant
# to notice in a name like invoice.pdf.exe.
DECOY_EXTENSIONS = frozenset(
    {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
     "jpg", "jpeg", "png", "gif", "mp3", "mp4"}
)


def reply_to_mismatch(rule_input: RuleInput, settings: Settings) -> list[Finding]:
    """Find Reply-To addresses on a different domain from the From address.

    Replies to such an email go somewhere other than the apparent sender,
    a common trick in invoice and payroll fraud. Every Reply-To address is
    checked, because a reply goes to all of them.
    """
    message = rule_input.message
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


def display_name_impersonation(rule_input: RuleInput, settings: Settings) -> list[Finding]:
    """Find a display name claiming a Protected Brand, sent from a domain that isn't theirs.

    Most mail apps show the display name and hide the address, so
    "PayPal Service <alerts@random.example>" reads as PayPal. The brand must
    appear as a whole word, so "Applebee's" doesn't count as Apple. Only the
    first brand named gives a Finding, so one display name can't score twice.
    """
    display_name, domain = _sender_display_name_and_domain(rule_input.message)
    if not display_name or not domain:
        return []

    for brand, brand_domains in settings.brands.items():
        if _names_brand(display_name, brand) and not is_genuine(domain, brand_domains):
            return [
                Finding(
                    rule_id=DISPLAY_NAME_IMPERSONATION,
                    points=settings.points[DISPLAY_NAME_IMPERSONATION],
                    decisive=False,
                    evidence=(
                        f'Display name "{display_name}" names {brand}, but the'
                        f" sending domain {domain} is not one of {brand}'s domains"
                        f" ({', '.join(brand_domains)})."
                    ),
                )
            ]
    return []


def lookalike_domain(rule_input: RuleInput, settings: Settings) -> list[Finding]:
    """Find sender or link domains built to be mistaken for a Protected Domain.

    There is one Finding per Protected Domain imitated, so a phish sent from
    paypa1.com that also links to paypa1.com counts once, not twice.
    """
    # Where each domain was seen, e.g. {"paypa1.com": ["sender", "link"]}.
    places: dict[str, list[str]] = {}
    _, sender_domain = _sender_display_name_and_domain(rule_input.message)
    if sender_domain:
        places[sender_domain] = ["sender"]
    for link_domain in rule_input.values(ObservableKind.DOMAIN):
        places.setdefault(link_domain, []).append("link")

    # Evidence sentences for each imitated Protected Domain.
    sightings: dict[str, list[str]] = {}
    for domain, seen_as in places.items():
        lookalike = imitated_domain(domain, settings.protected_domains)
        if lookalike:
            where = " and ".join(seen_as).capitalize()
            sightings.setdefault(lookalike.imitated, []).append(
                f"{where} domain {domain} imitates Protected Domain"
                f" {lookalike.imitated}: it {lookalike.technique}."
            )

    return [
        Finding(
            rule_id=LOOKALIKE_DOMAIN,
            points=settings.points[LOOKALIKE_DOMAIN],
            decisive=False,
            evidence=" ".join(sentences),
        )
        for sentences in sightings.values()
    ]


def url_shortener(rule_input: RuleInput, settings: Settings) -> list[Finding]:
    """Find links through a URL shortener, which hide their real destination.

    The short links are never expanded (ADR 0001): using one is the red flag.
    """
    shortened = [
        url
        for url in rule_input.values(ObservableKind.URL)
        if _is_on(host_of(url), settings.shortener_domains)
    ]
    if not shortened:
        return []

    listed = ", ".join(defang_url(url) for url in shortened)
    if len(shortened) == 1:
        described = f"Shortened URL hides its real destination: {listed}."
    else:
        described = f"Shortened URLs hide their real destinations: {listed}."
    return [
        Finding(
            rule_id=URL_SHORTENER,
            points=settings.points[URL_SHORTENER],
            decisive=False,
            evidence=described,
        )
    ]


def risky_attachment(rule_input: RuleInput, settings: Settings) -> list[Finding]:
    """Find attachments that look dangerous from the outside.

    Risky extensions, double extensions, hidden characters in the name,
    archives and password-protected ZIPs (which mail filters can't scan
    inside). There is one Finding for the whole email, naming each file.
    """
    sentences = []
    for attachment in rule_input.attachments:
        reasons = _attachment_red_flags(attachment, settings.risky_extensions)
        if reasons:
            name = display_filename(attachment.filename)
            sentences.append(f'Attachment "{name}" {_join_with_and(reasons)}.')
    if not sentences:
        return []
    return [
        Finding(
            rule_id=RISKY_ATTACHMENT,
            points=settings.points[RISKY_ATTACHMENT],
            decisive=False,
            evidence=" ".join(sentences),
        )
    ]


def known_malicious(rule_input: RuleInput, settings: Settings) -> list[Finding]:
    """Turn every malicious Reputation Lookup into a Decisive Finding.

    A Provider confirming an Observable is malicious (a URL listed on
    URLhaus, for example) makes the Verdict malicious whatever the Score
    (ADR 0002). Decisive Findings carry no points.
    """
    return [
        Finding(
            rule_id=KNOWN_MALICIOUS,
            points=0,
            decisive=True,
            evidence=(
                f"{result.provider} reports {LABELS[result.observable.kind]}"
                f" {defanged(result.observable)} as malicious: {result.detail}."
            ),
        )
        for result in rule_input.lookups
        if result.outcome is Outcome.MALICIOUS
    ]


def urlhaus_domain_listed(rule_input: RuleInput, settings: Settings) -> list[Finding]:
    """Find link domains hosting URLs that URLhaus lists as malicious.

    Not decisive, because shared platforms such as github.com host listed
    URLs too: only a listed URL itself is decisive (ADR 0005). One Finding
    per domain.
    """
    return [
        Finding(
            rule_id=URLHAUS_DOMAIN_LISTED,
            points=settings.points[URLHAUS_DOMAIN_LISTED],
            decisive=False,
            evidence=f"URLhaus lists malicious URLs on domain {defanged(result.observable)}: {result.detail}.",
        )
        for result in rule_input.lookups
        if result.provider == URLHAUS
        and result.observable.kind is ObservableKind.DOMAIN
        and result.outcome is Outcome.SUSPICIOUS
    ]


def _attachment_red_flags(attachment: Attachment, risky_extensions: tuple[str, ...]) -> list[str]:
    """Each reason an attachment looks dangerous, worded to follow its name."""
    reasons = []
    extension = extension_of(attachment.filename)
    previous = previous_extension_of(attachment.filename)
    if has_hidden_characters(attachment.filename):
        reasons.append("has hidden characters that can disguise its real extension")
    if extension in risky_extensions:
        reasons.append(f"has a risky extension (.{extension})")
        if previous in DECOY_EXTENSIONS:
            reasons.append(f"has a double extension (.{previous}.{extension})")
    if attachment.password_protected:
        reasons.append("is a password-protected archive, so it can't be scanned")
    elif attachment.archive_type:
        reasons.append(f"is an archive ({attachment.archive_type})")
    return reasons


def _join_with_and(items: list[str]) -> str:
    """Join ["a", "b", "c"] as "a, b and c"."""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def _is_on(host: str, domains: tuple[str, ...]) -> bool:
    """Is `host` one of `domains`, or a subdomain of one?"""
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def _names_brand(display_name: str, brand: str) -> bool:
    """Does the display name contain the brand as a whole word, ignoring case?"""
    # \b is a word boundary, so "Apple" matches "Apple Support" and
    # "support@apple.com" but not "Applebee's".
    return re.search(rf"\b{re.escape(brand)}\b", display_name, re.IGNORECASE) is not None


def _sender_display_name_and_domain(message: EmailMessage) -> tuple[str, str]:
    """Return the first From address's display name and lowercased domain."""
    header = message.get("From")
    if header is None or not header.addresses:
        return "", ""
    sender = header.addresses[0]
    return sender.display_name, str(sender.domain).lower()


def _domains(message: EmailMessage, header_name: str) -> list[str]:
    """Return the lowercased domains of a header's addresses, without repeats."""
    header = message.get(header_name)
    if header is None:
        return []
    domains = [str(address.domain).lower() for address in header.addresses]
    return list(dict.fromkeys(domain for domain in domains if domain))


BUILT_IN_RULES: tuple[Rule, ...] = (
    reply_to_mismatch,
    display_name_impersonation,
    lookalike_domain,
    url_shortener,
    risky_attachment,
    known_malicious,
    urlhaus_domain_listed,
)
