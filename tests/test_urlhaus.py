"""Tests for the URLhaus Provider, using saved responses through a fake transport.

No test here touches the network: the fake transport hands back fixture
files from tests/fixtures/urlhaus/, named <case>.<HTTP status>.json.
"""

from collections.abc import Mapping
from pathlib import Path

import pytest

from phishing_triage.core import Lookup, Observable, ObservableKind, Outcome
from phishing_triage.providers.transport import HttpResponse, TransportError
from phishing_triage.providers.urlhaus import LOOKUP_ENDPOINTS, URLhausProvider

FIXTURES = Path(__file__).parent / "fixtures" / "urlhaus"

# The URL and domain in the captured responses.
A_URL = Observable(
    ObservableKind.URL,
    "https://hardly-signatures-loc-surf.trycloudflare.com/download/WindowsUpdate.ps1",
)
A_DOMAIN = Observable(ObservableKind.DOMAIN, "hardly-signatures-loc-surf.trycloudflare.com")


class FakeTransport:
    """Returns one canned response (or raises) and records every request."""

    def __init__(self, response: HttpResponse | Exception) -> None:
        self.response = response
        self.requests: list[tuple[str, dict[str, str], dict[str, str]]] = []

    def post(self, url: str, form: Mapping[str, str], headers: Mapping[str, str]) -> HttpResponse:
        self.requests.append((url, dict(form), dict(headers)))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def get(self, url: str, headers: Mapping[str, str]) -> HttpResponse:
        raise AssertionError("URLhaus lookups are POSTs")


def saved(case: str) -> HttpResponse:
    """The saved response for a case, with the status taken from its filename."""
    (path,) = FIXTURES.glob(f"{case}.*.json")
    return HttpResponse(status=int(path.suffixes[0].lstrip(".")), body=path.read_bytes())


def look_up(observable: Observable, response: HttpResponse | Exception) -> Lookup:
    return URLhausProvider(auth_key="test-key", transport=FakeTransport(response)).lookup(observable)


def test_a_listed_url_is_malicious_with_the_threat_and_status() -> None:
    lookup = look_up(A_URL, saved("url_listed"))

    assert lookup.outcome is Outcome.MALICIOUS
    assert lookup.detail.startswith("listed as malware_download, currently ")
    assert lookup.evidence["urlhaus_reference"].startswith("https://urlhaus.abuse.ch/url/")


def test_a_listed_domain_is_only_suspicious_with_counts() -> None:
    lookup = look_up(A_DOMAIN, saved("host_listed"))

    assert lookup.outcome is Outcome.SUSPICIOUS
    assert "malicious URL" in lookup.detail and "still online" in lookup.detail
    assert lookup.evidence["url_count"] >= 1
    assert "urls" not in lookup.evidence  # The full list can be huge, so only counts are kept.


@pytest.mark.parametrize(
    ("observable", "case"),
    [(A_URL, "url_not_listed"), (A_DOMAIN, "host_not_listed")],
)
def test_not_listed_is_unknown_never_clean(observable: Observable, case: str) -> None:
    assert look_up(observable, saved(case)) == Lookup(
        Outcome.UNKNOWN, "not listed", {"query_status": "no_results"}
    )


@pytest.mark.parametrize(
    ("response", "reason", "stop_asking"),
    [
        pytest.param(saved("bad_key"), "URLhaus rejected the API key", True, id="bad key"),
        pytest.param(HttpResponse(429, b"Too Many Requests"), "rate limited by URLhaus", True, id="rate limited"),
        pytest.param(HttpResponse(500, b"oops"), "URLhaus answered with HTTP 500", False, id="server error"),
        pytest.param(
            HttpResponse(200, b"<html>maintenance</html>"), "URLhaus sent an unreadable answer", False,
            id="not JSON",
        ),
        pytest.param(
            HttpResponse(200, b'{"query_status": "invalid_url"}'),
            "URLhaus could not look it up (invalid_url)", False, id="refused query",
        ),
        pytest.param(TransportError("timed out"), "could not reach URLhaus (timed out)", True, id="timeout"),
    ],
)
def test_problems_are_not_checked_with_the_reason(
    response: HttpResponse | Exception, reason: str, stop_asking: bool
) -> None:
    # Problems that will affect every lookup also say to stop asking URLhaus for this Triage.
    assert look_up(A_URL, response) == Lookup(Outcome.NOT_CHECKED, reason, stop_asking=stop_asking)


def test_no_api_key_is_not_checked_without_asking_urlhaus() -> None:
    transport = FakeTransport(AssertionError("URLhaus should not be asked"))

    lookup = URLhausProvider(auth_key=None, transport=transport).lookup(A_URL)

    assert lookup == Lookup(Outcome.NOT_CHECKED, "no API key", stop_asking=True)
    assert transport.requests == []


def test_only_lookup_endpoints_are_used_with_the_key_in_a_header() -> None:
    transport = FakeTransport(saved("url_not_listed"))
    provider = URLhausProvider(auth_key="test-key", transport=transport)

    provider.lookup(A_URL)
    provider.lookup(A_DOMAIN)

    assert transport.requests == [
        ("https://urlhaus-api.abuse.ch/v1/url/", {"url": A_URL.value}, {"Auth-Key": "test-key"}),
        ("https://urlhaus-api.abuse.ch/v1/host/", {"host": A_DOMAIN.value}, {"Auth-Key": "test-key"}),
    ]
    # Safety (ADR 0001): every endpoint the Provider knows is a lookup, never a submission.
    assert all(endpoint.endswith(("/url/", "/host/")) for endpoint, _ in LOOKUP_ENDPOINTS.values())
