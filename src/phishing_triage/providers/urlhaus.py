"""The URLhaus Provider: abuse.ch's list of URLs used to spread malware.

Only the lookup endpoints are used; nothing is ever submitted (ADR 0001).
A listed URL is malicious. A listed domain is only suspicious, because shared
platforms host listed URLs too (ADR 0005). Not listed is Unknown, never clean.
"""

import json
from collections.abc import Set
from typing import Any

from phishing_triage.core import URLHAUS, Lookup, Observable, ObservableKind, Outcome
from phishing_triage.providers.transport import Transport, TransportError

API_ROOT = "https://urlhaus-api.abuse.ch/v1/"

# The lookup endpoint and form field for each kind of Observable.
LOOKUP_ENDPOINTS = {
    ObservableKind.URL: (API_ROOT + "url/", "url"),
    ObservableKind.DOMAIN: (API_ROOT + "host/", "host"),
}


class URLhausProvider:
    """Looks URLs and domains up on URLhaus."""

    def __init__(self, auth_key: str | None, transport: Transport) -> None:
        self._auth_key = auth_key
        self._transport = transport

    @property
    def name(self) -> str:
        return URLHAUS

    @property
    def handles(self) -> Set[ObservableKind]:
        return LOOKUP_ENDPOINTS.keys()

    def lookup(self, observable: Observable) -> Lookup:
        if not self._auth_key:
            return Lookup(Outcome.NOT_CHECKED, "no API key")

        endpoint, field = LOOKUP_ENDPOINTS[observable.kind]
        try:
            response = self._transport.post(
                endpoint, {field: observable.value}, {"Auth-Key": self._auth_key}
            )
        except TransportError as error:
            return Lookup(Outcome.NOT_CHECKED, f"could not reach URLhaus ({error})")

        if response.status in (401, 403):
            return Lookup(Outcome.NOT_CHECKED, "URLhaus rejected the API key")
        if response.status == 429:
            return Lookup(Outcome.NOT_CHECKED, "rate limited by URLhaus")
        if response.status != 200:
            return Lookup(Outcome.NOT_CHECKED, f"URLhaus answered with HTTP {response.status}")

        try:
            data = json.loads(response.body)
        except ValueError:
            data = None
        if not isinstance(data, dict):
            return Lookup(Outcome.NOT_CHECKED, "URLhaus sent an unreadable answer")
        return _interpret(observable.kind, data)


def _interpret(kind: ObservableKind, data: dict[str, Any]) -> Lookup:
    """Turn URLhaus's JSON answer into a Lookup."""
    status = data.get("query_status")
    if status == "no_results":
        return Lookup(Outcome.UNKNOWN, "not listed", {"query_status": status})
    if status != "ok":
        if "auth" in str(status):
            return Lookup(Outcome.NOT_CHECKED, "URLhaus rejected the API key")
        return Lookup(Outcome.NOT_CHECKED, f"URLhaus could not look it up ({status})")
    if kind is ObservableKind.URL:
        return _url_listing(data)
    return _domain_listing(data)


def _url_listing(data: dict[str, Any]) -> Lookup:
    threat = data.get("threat") or "malicious"
    url_status = data.get("url_status") or "unknown"
    detail = f"listed as {threat}, currently {url_status}"
    if data.get("date_added"):
        detail += f", added {data['date_added']}"
    evidence = {
        key: data.get(key)
        for key in ("urlhaus_reference", "url_status", "threat", "date_added", "tags")
    }
    return Lookup(Outcome.MALICIOUS, detail, evidence)


def _domain_listing(data: dict[str, Any]) -> Lookup:
    urls = data.get("urls") or []
    count = _whole_number(data.get("url_count"), default=len(urls))
    if count == 0:
        return Lookup(Outcome.UNKNOWN, "no URLs listed", {"query_status": "ok", "url_count": 0})
    online = sum(1 for url in urls if isinstance(url, dict) and url.get("url_status") == "online")
    noun = "URL" if count == 1 else "URLs"
    evidence = {
        "urlhaus_reference": data.get("urlhaus_reference"),
        "url_count": count,
        "online_url_count": online,
        "firstseen": data.get("firstseen"),
        "blacklists": data.get("blacklists"),
    }
    # The full URL list can run to thousands on a shared platform, so only counts are kept.
    return Lookup(Outcome.SUSPICIOUS, f"{count} malicious {noun} listed, {online} still online", evidence)


def _whole_number(value: Any, default: int) -> int:
    """URLhaus sends some counts as text ("12"), so accept either."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
