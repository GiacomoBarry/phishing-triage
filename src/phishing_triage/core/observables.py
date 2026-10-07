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
    DOMAIN = "domain"
    SHA256 = "sha256"  # The SHA-256 hash of an attachment.


@dataclass(frozen=True)
class Observable:
    """One artefact pulled from an email, such as a URL or a domain."""

    kind: ObservableKind
    value: str


def extract_observables(message: EmailMessage, attachments: list[Attachment]) -> list[Observable]:
    """Return the email's Observables without repeats: every URL, every link domain,
    then every attachment's SHA-256.

    A URL whose host is an IP address gives no domain Observable.
    """
    urls = find_urls(message)
    hosts = (host_of(url) for url in urls)
    domains = dict.fromkeys(host for host in hosts if host and not _is_ip_address(host))
    hashes = dict.fromkeys(attachment.sha256 for attachment in attachments)
    return (
        [Observable(ObservableKind.URL, url) for url in urls]
        + [Observable(ObservableKind.DOMAIN, domain) for domain in domains]
        + [Observable(ObservableKind.SHA256, sha256) for sha256 in hashes]
    )


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
    ObservableKind.SHA256: "SHA-256",
}


def defanged(observable: Observable) -> str:
    """The Observable's value made safe to display: URLs and domains can't be clicked.

    A hash isn't clickable, so it is shown as it is.
    """
    if observable.kind is ObservableKind.URL:
        return defang_url(observable.value)
    if observable.kind is ObservableKind.DOMAIN:
        return defang_domain(observable.value)
    return observable.value
