"""The AbuseIPDB Provider: how often an IP address has been reported for abuse.

Only the check endpoint (GET) is used. AbuseIPDB's report endpoint would
send it something, so it is never called (ADR 0001). The only thing ever
sent is the Claimed Origin's IP address.
"""

import json
from collections.abc import Set
from typing import Any
from urllib.parse import urlencode

from phishing_triage.core import ABUSEIPDB, Lookup, Observable, ObservableKind, Outcome
from phishing_triage.providers.transport import Transport, TransportError

API_ROOT = "https://api.abuseipdb.com/api/v2/"

# Only reports from this many recent days count towards the answer.
MAX_AGE_DAYS = 30


def check_url(ip: str) -> str:
    """The lookup URL for one IP address."""
    return API_ROOT + "check?" + urlencode({"ipAddress": ip, "maxAgeInDays": MAX_AGE_DAYS})


def request_headers(api_key: str) -> dict[str, str]:
    """The headers every request needs: the key, and asking for JSON."""
    return {"Key": api_key, "Accept": "application/json"}


class AbuseIPDBProvider:
    """Looks the Claimed Origin's IP address up on AbuseIPDB.

    AbuseIPDB answers for every IP, so there is no "not found": no recent
    reports is Unknown. Any non-zero Abuse Confidence is suspicious, with it kept
    in the evidence. Whether it is high enough for a Finding is up to the
    rule and its threshold setting, so changing the setting needs no fresh
    lookups (ADR 0012).
    """

    def __init__(self, api_key: str | None, transport: Transport) -> None:
        self._api_key = api_key
        self._transport = transport

    @property
    def name(self) -> str:
        return ABUSEIPDB

    @property
    def handles(self) -> Set[ObservableKind]:
        return frozenset({ObservableKind.CLAIMED_ORIGIN})

    @property
    def lookups_per_minute(self) -> None:
        # The free tier allows 1,000 checks a day, with no per-minute limit,
        # and each email has at most one Claimed Origin.
        return None

    def lookup(self, observable: Observable) -> Lookup:
        if not self._api_key:
            return Lookup(Outcome.NOT_CHECKED, "no API key", stop_asking=True)

        try:
            response = self._transport.get(check_url(observable.value), request_headers(self._api_key))
        except TransportError as error:
            return Lookup(Outcome.NOT_CHECKED, f"could not reach AbuseIPDB ({error})", stop_asking=True)

        if response.status == 401:
            return Lookup(Outcome.NOT_CHECKED, "AbuseIPDB rejected the API key", stop_asking=True)
        if response.status == 429:
            return Lookup(Outcome.NOT_CHECKED, "rate limited by AbuseIPDB", stop_asking=True)
        body = _json_object(response.body)
        if response.status == 422:
            return Lookup(Outcome.NOT_CHECKED, f"AbuseIPDB could not look it up ({_error_detail(body)})")
        if response.status != 200:
            return Lookup(Outcome.NOT_CHECKED, f"AbuseIPDB answered with HTTP {response.status}")

        data = body.get("data")
        if not isinstance(data, dict) or not isinstance(data.get("abuseConfidenceScore"), int):
            return Lookup(Outcome.NOT_CHECKED, "AbuseIPDB sent an unreadable answer")
        return _interpret(data, _evidence(data, observable.value))


def _interpret(data: dict[str, Any], evidence: dict[str, Any]) -> Lookup:
    """Turn AbuseIPDB's answer into an outcome."""
    abuse_confidence = data["abuseConfidenceScore"]
    reports = evidence["reports"]
    if data.get("isWhitelisted"):
        detail = f"on AbuseIPDB's allowlist of known-good addresses ({reports} reports ignored)"
        return Lookup(Outcome.CLEAN, detail, evidence)
    if reports == 0:
        return Lookup(Outcome.UNKNOWN, f"no reports on AbuseIPDB in the last {MAX_AGE_DAYS} days", evidence)
    detail = (
        f"abuse confidence {abuse_confidence}% from {reports} reports"
        f" by {evidence['reporters']} users in the last {MAX_AGE_DAYS} days"
    )
    # Old or disputed reports can leave an abuse confidence of 0: reported, but not
    # enough to judge either way.
    return Lookup(Outcome.SUSPICIOUS if abuse_confidence > 0 else Outcome.UNKNOWN, detail, evidence)


def _evidence(data: dict[str, Any], ip: str) -> dict[str, Any]:
    """The useful parts of AbuseIPDB's answer, kept for the Triage Report."""
    return {
        "abuse_confidence": data["abuseConfidenceScore"],
        "reports": data.get("totalReports", 0),
        "reporters": data.get("numDistinctUsers", 0),
        "last_reported": data.get("lastReportedAt"),
        "isp": data.get("isp"),
        "usage_type": data.get("usageType"),
        "country": data.get("countryCode"),
        "is_tor": data.get("isTor"),
        "abuseipdb_link": f"https://www.abuseipdb.com/check/{ip}",
    }


def _json_object(body: bytes) -> dict[str, Any]:
    """The answer as a JSON object, or an empty one if it isn't JSON."""
    try:
        data = json.loads(body)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _error_detail(body: dict[str, Any]) -> str:
    """AbuseIPDB's explanation of an error, from its "errors" list."""
    errors = body.get("errors")
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        return str(errors[0].get("detail", "unknown error"))
    return "unknown error"
