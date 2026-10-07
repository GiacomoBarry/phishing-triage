"""The RDAP Provider: when a domain was registered, asked of its registry.

RDAP (Registration Data Access Protocol) is how domain registries publish
registration details. Only the registry is asked; the domain itself is never
contacted (ADR 0001). RDAP gives facts, not reputation, so every answer's
outcome is Unknown, with the registration date in the evidence (ADR 0010).
"""

import json
from collections.abc import Set
from datetime import UTC, datetime
from typing import Any

from phishing_triage.core import RDAP, Lookup, Observable, ObservableKind, Outcome
from phishing_triage.providers.transport import Transport, TransportError

# IANA's list of which registry's RDAP service answers for each domain ending.
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
ACCEPT = {"Accept": "application/rdap+json"}

# Registries publish no common limit, so lookups are kept gentle.
LOOKUPS_PER_MINUTE = 30


class RdapProvider:
    """Looks up when domains were registered."""

    def __init__(self, transport: Transport) -> None:
        self._transport = transport
        # Each domain ending's RDAP service, fetched on first use.
        self._services: dict[str, str] | None = None

    @property
    def name(self) -> str:
        return RDAP

    @property
    def handles(self) -> Set[ObservableKind]:
        return {ObservableKind.DOMAIN, ObservableKind.SENDER_DOMAIN}

    @property
    def lookups_per_minute(self) -> int:
        return LOOKUPS_PER_MINUTE

    def lookup(self, observable: Observable) -> Lookup:
        try:
            services = self._load_services()
        except (TransportError, ValueError, KeyError, TypeError) as error:
            reason = f"could not reach the RDAP bootstrap list ({error})"
            return Lookup(Outcome.NOT_CHECKED, reason, stop_asking=True)
        try:
            # Registries want plain ASCII: non-Latin letters as punycode (xn--...).
            ascii_domain = observable.value.strip(".").lower().encode("idna").decode("ascii")
        except UnicodeError:
            return _unknown_age("the domain name can't be written in a form registries accept")
        ending = ascii_domain.rsplit(".", 1)[-1]
        base = services.get(ending)
        if base is None:
            return _unknown_age(f".{ending} has no RDAP service")

        # Registries only know registered domains, so trim subdomains one label
        # at a time (login.evil.co.uk, then evil.co.uk) until one is found.
        for name in _candidates(ascii_domain):
            try:
                response = self._transport.get(base + "domain/" + name, ACCEPT)
            except TransportError as error:
                reason = f"could not reach the registry ({error})"
                return Lookup(Outcome.NOT_CHECKED, reason, stop_asking=True)
            if response.status in (400, 404):
                continue
            if response.status == 429:
                return Lookup(Outcome.NOT_CHECKED, "rate limited by the registry", stop_asking=True)
            if response.status != 200:
                return Lookup(Outcome.NOT_CHECKED, f"the registry answered with HTTP {response.status}")
            return _interpret(response.body, name)
        return _unknown_age("not found at the registry")

    def _load_services(self) -> dict[str, str]:
        """Each domain ending's RDAP service, from IANA's list (fetched once)."""
        if self._services is None:
            response = self._transport.get(BOOTSTRAP_URL, {})
            bootstrap = json.loads(response.body)
            self._services = {
                ending.lower(): urls[0] if urls[0].endswith("/") else urls[0] + "/"
                for endings, urls in bootstrap["services"]
                for ending in endings
            }
        return self._services


def _interpret(body: bytes, rdap_domain: str) -> Lookup:
    """Turn a registry's answer into a Lookup carrying the registration date."""
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return Lookup(Outcome.NOT_CHECKED, "the registry sent an unreadable answer")

    date_text = _registration_event_date(data)
    if date_text is None:
        return _unknown_age("the registry doesn't publish a registration date", rdap_domain)
    try:
        registered = datetime.fromisoformat(date_text)
    except ValueError:
        return _unknown_age("the registry's registration date can't be read", rdap_domain)
    # A date with no time zone is taken as UTC, not this computer's local time.
    registered = registered.replace(tzinfo=UTC) if registered.tzinfo is None else registered.astimezone(UTC)
    return Lookup(
        Outcome.UNKNOWN,
        f"registered {registered:%Y-%m-%d}",
        {"registered": f"{registered:%Y-%m-%dT%H:%M:%SZ}", "rdap_domain": rdap_domain},
    )


def _registration_event_date(data: dict[str, Any]) -> str | None:
    """The date text of the "registration" event, if the registry publishes one."""
    for event in data.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            return str(event.get("eventDate"))
    return None


def _candidates(domain: str) -> list[str]:
    """The domain, then each shorter version down to two labels.

    login.evil.co.uk gives login.evil.co.uk, evil.co.uk and co.uk; the search
    stops at the first one the registry knows. A bare ending (uk) is never asked.
    """
    labels = domain.split(".")
    return [".".join(labels[start:]) for start in range(max(1, len(labels) - 1))]


def _unknown_age(reason: str, rdap_domain: str | None = None) -> Lookup:
    """Unknown age never counts as old (or young), but is shown with its reason."""
    return Lookup(Outcome.UNKNOWN, f"unknown age: {reason}", {"registered": None, "rdap_domain": rdap_domain})
