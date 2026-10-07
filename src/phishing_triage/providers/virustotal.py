"""The VirusTotal Provider: what dozens of antivirus and blocklist engines say.

Only the lookup endpoints (GET) are used. VirusTotal's POST endpoints submit
URLs and files for scanning, so they are never called (ADR 0001).
"""

import base64
import json
from collections.abc import Set
from datetime import UTC, datetime
from typing import Any

from phishing_triage.core import VIRUSTOTAL, Lookup, Observable, ObservableKind, Outcome
from phishing_triage.providers.transport import Transport, TransportError

API_ROOT = "https://www.virustotal.com/api/v3/"

# The lookup path for each kind of Observable. All are GET requests.
LOOKUP_PATHS = {
    ObservableKind.URL: "urls/",
    ObservableKind.DOMAIN: "domains/",
    ObservableKind.SHA256: "files/",
}

# Engine results that count as an answer (not a timeout or an unsupported file type).
ANSWERING_CATEGORIES = ("malicious", "suspicious", "harmless", "undetected")

# How many flagging engines to name in the evidence. The count is always kept.
MAX_ENGINES_NAMED = 10


# The free API allows 4 lookups a minute (and 500 a day).
LOOKUPS_PER_MINUTE = 4


class VirusTotalProvider:
    """Looks URLs, domains and attachment hashes up on VirusTotal."""

    def __init__(self, api_key: str | None, transport: Transport, decisive_engines: int) -> None:
        self._api_key = api_key
        self._transport = transport
        self._decisive_engines = decisive_engines

    @property
    def name(self) -> str:
        return VIRUSTOTAL

    @property
    def handles(self) -> Set[ObservableKind]:
        return LOOKUP_PATHS.keys()

    @property
    def lookups_per_minute(self) -> int:
        return LOOKUPS_PER_MINUTE

    def lookup(self, observable: Observable) -> Lookup:
        if not self._api_key:
            return Lookup(Outcome.NOT_CHECKED, "no API key", stop_asking=True)

        path = LOOKUP_PATHS[observable.kind] + _identifier(observable)
        try:
            response = self._transport.get(API_ROOT + path, {"x-apikey": self._api_key})
        except TransportError as error:
            return Lookup(Outcome.NOT_CHECKED, f"could not reach VirusTotal ({error})", stop_asking=True)

        if response.status == 404:
            return Lookup(Outcome.UNKNOWN, "never seen by VirusTotal")
        if response.status == 401:
            return Lookup(Outcome.NOT_CHECKED, "VirusTotal rejected the API key", stop_asking=True)
        if response.status == 429:
            return Lookup(Outcome.NOT_CHECKED, "rate limited by VirusTotal", stop_asking=True)
        data = _json_object(response.body)
        if response.status == 400:
            code = _error_code(data)
            return Lookup(Outcome.NOT_CHECKED, f"VirusTotal could not look it up ({code})")
        if response.status != 200:
            return Lookup(Outcome.NOT_CHECKED, f"VirusTotal answered with HTTP {response.status}")

        attributes = _attributes(data)
        stats = attributes.get("last_analysis_stats")
        if not isinstance(stats, dict):
            return Lookup(Outcome.NOT_CHECKED, "VirusTotal sent an unreadable answer")
        evidence = _evidence(data, attributes, stats)
        return self._interpret(observable.kind, stats, evidence)

    def _interpret(
        self, kind: ObservableKind, stats: dict[str, Any], evidence: dict[str, Any]
    ) -> Lookup:
        """Turn the engine counts into an outcome, using the decisive threshold."""
        malicious = stats["malicious"]
        answered = sum(stats.get(category, 0) for category in ANSWERING_CATEGORIES)
        if answered == 0:
            return Lookup(Outcome.UNKNOWN, "no engine gave an answer", evidence)
        detail = f"{malicious} of {answered} engines flag it as malicious"
        # A domain is never decisive: shared platforms (github.com, even
        # google.com) collect detections for what their users host (ADR 0007).
        if malicious >= self._decisive_engines and kind is not ObservableKind.DOMAIN:
            return Lookup(Outcome.MALICIOUS, detail, evidence)
        if malicious > 0:
            return Lookup(Outcome.SUSPICIOUS, detail, evidence)
        # Antivirus engines scan a file's bytes, so "undetected" is a real
        # verdict. For URLs and domains it only means "not on my blocklist",
        # so clean needs at least one engine saying "harmless" (ADR 0006).
        if kind is not ObservableKind.SHA256 and stats.get("harmless", 0) == 0:
            detail = f"no engine flags it, but none vouches for it either (0 of {answered} say harmless)"
            return Lookup(Outcome.UNKNOWN, detail, evidence)
        return Lookup(Outcome.CLEAN, detail, evidence)


def _evidence(
    data: dict[str, Any], attributes: dict[str, Any], stats: dict[str, Any]
) -> dict[str, Any]:
    """The useful parts of VirusTotal's answer, kept for the Triage Report.

    The full answer runs to tens of kilobytes (every engine's result, DNS
    records, WHOIS...), so only the counts and the first few engine names are kept.
    """
    results = attributes.get("last_analysis_results") or {}
    flagged_by = sorted(
        engine
        for engine, result in results.items()
        if isinstance(result, dict) and result.get("category") == "malicious"
    )
    analysed = attributes.get("last_analysis_date")
    item = data.get("data") or {}
    return {
        **{category: stats.get(category, 0) for category in ANSWERING_CATEGORIES},
        "flagged_by": flagged_by[:MAX_ENGINES_NAMED],
        "last_analysis": (
            datetime.fromtimestamp(analysed, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            if isinstance(analysed, int)
            else None
        ),
        "virustotal_link": f"https://www.virustotal.com/gui/{item.get('type')}/{item.get('id')}",
    }


def _json_object(body: bytes) -> dict[str, Any]:
    """The answer as a JSON object, or an empty one if it isn't JSON."""
    try:
        data = json.loads(body)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _attributes(data: dict[str, Any]) -> dict[str, Any]:
    """The `data.attributes` part of an answer, where VirusTotal keeps its findings."""
    attributes = (data.get("data") or {}).get("attributes")
    return attributes if isinstance(attributes, dict) else {}


def _error_code(data: dict[str, Any]) -> str:
    """VirusTotal's name for an error, such as "InvalidArgumentError"."""
    error = data.get("error")
    return str(error.get("code", "unknown error")) if isinstance(error, dict) else "unknown error"


def _identifier(observable: Observable) -> str:
    """How VirusTotal names an Observable in its lookup paths.

    A URL's name is the URL itself in base64url (letters, digits, - and _)
    without the = padding, so it fits safely in a path.
    """
    if observable.kind is ObservableKind.URL:
        return base64.urlsafe_b64encode(observable.value.encode()).decode().rstrip("=")
    return observable.value
