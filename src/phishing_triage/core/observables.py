"""Observables: the artefacts pulled out of an email, with no judgement attached."""

import ipaddress
from dataclasses import dataclass
from email.message import EmailMessage
from enum import StrEnum

from phishing_triage.core.urls import find_urls, host_of


class ObservableKind(StrEnum):
    """What sort of artefact an Observable is. More kinds arrive in later tickets."""

    URL = "url"
    DOMAIN = "domain"


@dataclass(frozen=True)
class Observable:
    """One artefact pulled from an email, such as a URL or a domain."""

    kind: ObservableKind
    value: str


def extract_observables(message: EmailMessage) -> list[Observable]:
    """Return the email's Observables: every URL, then every link domain, without repeats.

    A URL whose host is an IP address gives no domain Observable.
    """
    urls = find_urls(message)
    hosts = (host_of(url) for url in urls)
    domains = dict.fromkeys(host for host in hosts if host and not _is_ip_address(host))
    return [Observable(ObservableKind.URL, url) for url in urls] + [
        Observable(ObservableKind.DOMAIN, domain) for domain in domains
    ]


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
