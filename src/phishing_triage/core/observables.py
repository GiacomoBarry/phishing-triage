"""Observables: the artefacts pulled out of an email, with no judgement attached."""

import ipaddress
from dataclasses import dataclass
from email.message import EmailMessage
from enum import StrEnum

from phishing_triage.core.attachments import Attachment
from phishing_triage.core.urls import defang_domain, defang_url, find_urls, host_of


class ObservableKind(StrEnum):
    """What sort of artefact an Observable is. More kinds arrive in later tickets."""

    URL = "url"
    DOMAIN = "domain"  # A link's domain.
    SENDER_DOMAIN = "sender_domain"  # The From address's domain.
    SHA256 = "sha256"  # The SHA-256 hash of an attachment.
    CLAIMED_ORIGIN = "claimed_origin"  # The Claimed Origin's IP address.


@dataclass(frozen=True)
class Observable:
    """One artefact pulled from an email, such as a URL or a domain."""

    kind: ObservableKind
    value: str


def extract_observables(
    message: EmailMessage, attachments: list[Attachment], claimed_origin_ip: str
) -> list[Observable]:
    """Return the email's Observables without repeats: the Claimed Origin's IP
    (if there is one), the sender's domain, every URL, every link domain, then
    every attachment's SHA-256.

    The Claimed Origin is the only IP address that becomes an Observable: a
    URL whose host is an IP address gives no domain Observable either.
    """
    urls = find_urls(message)
    hosts = (host_of(url) for url in urls)
    domains = dict.fromkeys(host for host in hosts if host and not _is_ip_address(host))
    hashes = dict.fromkeys(attachment.sha256 for attachment in attachments)
    sender_domain = _sender_domain(message)
    return (
        ([Observable(ObservableKind.CLAIMED_ORIGIN, claimed_origin_ip)] if claimed_origin_ip else [])
        + ([Observable(ObservableKind.SENDER_DOMAIN, sender_domain)] if sender_domain else [])
        + [Observable(ObservableKind.URL, url) for url in urls]
        + [Observable(ObservableKind.DOMAIN, domain) for domain in domains]
        + [Observable(ObservableKind.SHA256, sha256) for sha256 in hashes]
    )


def _sender_domain(message: EmailMessage) -> str:
    """The first From address's domain, lowercased, or "" if there isn't one.

    An address at an IP address (user@[192.0.2.7]) has no domain to look up,
    just as a link to an IP address gives no domain Observable.
    """
    header = message.get("From")
    if header is None or not header.addresses:
        return ""
    domain = str(header.addresses[0].domain).lower().strip(".")
    if domain.startswith("[") or _is_ip_address(domain):
        return ""
    return domain


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


# How each kind of Observable is named for analysts.
LABELS = {
    ObservableKind.URL: "URL",
    ObservableKind.DOMAIN: "Domain",
    ObservableKind.SENDER_DOMAIN: "Sender domain",
    ObservableKind.SHA256: "SHA-256",
    ObservableKind.CLAIMED_ORIGIN: "Claimed Origin IP",
}


def defanged(observable: Observable) -> str:
    """The Observable's value made safe to display: URLs and domains can't be clicked.

    A hash or an IP address isn't clickable, so it is shown as it is.
    """
    if observable.kind is ObservableKind.URL:
        return defang_url(observable.value)
    if observable.kind in (ObservableKind.DOMAIN, ObservableKind.SENDER_DOMAIN):
        return defang_domain(observable.value)
    return observable.value
