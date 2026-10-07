"""Tests for the AbuseIPDB Provider, using saved responses through a fake transport.

No test here touches the network: the fake transport hands back fixture
files from tests/fixtures/abuseipdb/, named <case>.<HTTP status>.json.
"""

from collections.abc import Mapping
from pathlib import Path

import pytest

from phishing_triage.core import Lookup, Observable, ObservableKind, Outcome
from phishing_triage.providers.abuseipdb import AbuseIPDBProvider
from phishing_triage.providers.transport import HttpResponse, TransportError

FIXTURES = Path(__file__).parent / "fixtures" / "abuseipdb"

ORIGIN = Observable(ObservableKind.CLAIMED_ORIGIN, "202.39.243.226")


class FakeTransport:
    """Returns one canned response (or raises) and records every request."""

    def __init__(self, response: HttpResponse | Exception) -> None:
        self.response = response
        self.requests: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str, headers: Mapping[str, str]) -> HttpResponse:
        self.requests.append((url, dict(headers)))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def post(self, url: str, form: Mapping[str, str], headers: Mapping[str, str]) -> HttpResponse:
        raise AssertionError("AbuseIPDB's POST endpoint reports an IP (ADR 0001)")


def saved(case: str) -> HttpResponse:
    """The saved response for a case, with the status taken from its filename."""
    (path,) = FIXTURES.glob(f"{case}.*.json")
    return HttpResponse(status=int(path.suffixes[0].lstrip(".")), body=path.read_bytes())


def look_up(response: HttpResponse | Exception, api_key: str | None = "test-key") -> Lookup:
    provider = AbuseIPDBProvider(api_key=api_key, transport=FakeTransport(response))
    return provider.lookup(ORIGIN)


def test_a_reported_ip_is_suspicious_with_its_score_and_reports() -> None:
    lookup = look_up(saved("high_confidence"))

    assert lookup.outcome is Outcome.SUSPICIOUS
    assert lookup.detail == "abuse confidence 100% from 2149 reports by 320 users in the last 30 days"
    assert lookup.evidence == {
        "abuse_confidence": 100,
        "reports": 2149,
        "reporters": 320,
        "last_reported": "2026-10-07T19:41:07+00:00",
        "isp": "Chunghwa Telecom Data Communication Business Group",
        "usage_type": "Fixed Line ISP",
        "country": "TW",
        "is_tor": False,
        "abuseipdb_link": "https://www.abuseipdb.com/check/202.39.243.226",
    }


def test_a_low_score_is_suspicious_too_the_threshold_is_for_the_rule() -> None:
    lookup = look_up(saved("low_confidence"))

    assert lookup.outcome is Outcome.SUSPICIOUS
    assert lookup.evidence["abuse_confidence"] == 34


def test_no_recent_reports_is_unknown_not_clean() -> None:
    lookup = look_up(saved("not_reported"))

    assert lookup.outcome is Outcome.UNKNOWN
    assert lookup.detail == "no reports on AbuseIPDB in the last 30 days"
    assert lookup.evidence["abuse_confidence"] == 0


def test_an_ip_on_abuseipdbs_allowlist_is_clean_despite_reports() -> None:
    lookup = look_up(saved("allowlisted"))

    assert lookup.outcome is Outcome.CLEAN
    assert lookup.detail == "on AbuseIPDB's allowlist of known-good addresses (51 reports ignored)"


def test_the_ip_is_only_ever_looked_up_with_a_get() -> None:
    transport = FakeTransport(saved("high_confidence"))

    AbuseIPDBProvider(api_key="test-key", transport=transport).lookup(ORIGIN)

    assert transport.requests == [
        (
            "https://api.abuseipdb.com/api/v2/check?ipAddress=202.39.243.226&maxAgeInDays=30",
            {"Key": "test-key", "Accept": "application/json"},
        )
    ]


def test_without_a_key_nothing_is_sent_and_it_stops_asking() -> None:
    transport = FakeTransport(AssertionError("nothing should be sent without an API key"))

    lookup = AbuseIPDBProvider(api_key=None, transport=transport).lookup(ORIGIN)

    assert lookup == Lookup(Outcome.NOT_CHECKED, "no API key", stop_asking=True)
    assert transport.requests == []


@pytest.mark.parametrize(
    ("response", "detail", "stop_asking"),
    [
        pytest.param(saved("bad_key"), "AbuseIPDB rejected the API key", True, id="bad key"),
        pytest.param(saved("rate_limited"), "rate limited by AbuseIPDB", True, id="rate limited"),
        pytest.param(
            saved("invalid_ip"),
            "AbuseIPDB could not look it up (The ip address must be a valid IPv4 or IPv6 address"
            " (e.g. 8.8.8.8 or 2001:4860:4860::8888).)",
            False,
            id="invalid IP",
        ),
        pytest.param(
            TransportError("timed out"), "could not reach AbuseIPDB (timed out)", True, id="unreachable"
        ),
        pytest.param(HttpResponse(500, b"<html>oops</html>"), "AbuseIPDB answered with HTTP 500", False, id="server error"),
        pytest.param(HttpResponse(200, b"not json"), "AbuseIPDB sent an unreadable answer", False, id="not JSON"),
    ],
)
def test_problems_are_not_checked_with_the_reason(
    response: HttpResponse | Exception, detail: str, stop_asking: bool
) -> None:
    lookup = look_up(response)

    assert lookup.outcome is Outcome.NOT_CHECKED
    assert lookup.detail == detail
    assert lookup.stop_asking is stop_asking


def test_it_handles_only_the_claimed_origin() -> None:
    provider = AbuseIPDBProvider(api_key="test-key", transport=FakeTransport(saved("not_reported")))

    assert set(provider.handles) == {ObservableKind.CLAIMED_ORIGIN}
    assert provider.name == "AbuseIPDB"


def test_reports_that_leave_a_score_of_zero_are_unknown() -> None:
    body = b'{"data": {"abuseConfidenceScore": 0, "totalReports": 3, "numDistinctUsers": 2, "isWhitelisted": false}}'

    lookup = look_up(HttpResponse(200, body))

    assert lookup.outcome is Outcome.UNKNOWN
    assert lookup.detail == "abuse confidence 0% from 3 reports by 2 users in the last 30 days"
