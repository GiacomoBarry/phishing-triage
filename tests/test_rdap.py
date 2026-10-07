"""Tests for the RDAP Provider, using saved responses through a fake transport.

No test here touches the network: the fake transport answers each URL with a
fixture file from tests/fixtures/rdap/, named <case>.<HTTP status>.json.
"""

from collections.abc import Mapping
from pathlib import Path

import pytest

from phishing_triage.core import Lookup, Observable, ObservableKind, Outcome
from phishing_triage.providers.rdap import RdapProvider
from phishing_triage.providers.transport import HttpResponse, TransportError

FIXTURES = Path(__file__).parent / "fixtures" / "rdap"

BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
PIR = "https://rdap.publicinterestregistry.org/rdap/domain/"
VERISIGN = "https://rdap.verisign.com/com/v1/domain/"
NOMINET = "https://rdap.nominet.uk/uk/domain/"


def saved(case: str) -> HttpResponse:
    """The saved response for a case, with the status taken from its filename."""
    (path,) = FIXTURES.glob(f"{case}.*.json")
    return HttpResponse(status=int(path.suffixes[0].lstrip(".")), body=path.read_bytes())


class FakeTransport:
    """Answers each URL from a table (anything else is a 404) and records every request."""

    def __init__(self, answers: Mapping[str, HttpResponse | Exception]) -> None:
        self.answers = {BOOTSTRAP: saved("bootstrap"), **answers}
        self.requests: list[str] = []

    def get(self, url: str, headers: Mapping[str, str]) -> HttpResponse:
        self.requests.append(url)
        answer = self.answers.get(url, HttpResponse(404, b""))
        if isinstance(answer, Exception):
            raise answer
        return answer

    def post(self, url: str, form: Mapping[str, str], headers: Mapping[str, str]) -> HttpResponse:
        raise AssertionError("RDAP lookups are GETs")


def domain(value: str) -> Observable:
    return Observable(ObservableKind.DOMAIN, value)


def look_up(observable: Observable, answers: Mapping[str, HttpResponse | Exception]) -> Lookup:
    return RdapProvider(FakeTransport(answers)).lookup(observable)


def test_a_registered_domain_gives_its_registration_date() -> None:
    lookup = look_up(domain("wicar.org"), {PIR + "wicar.org": saved("registered")})

    # RDAP gives facts, not reputation, so the outcome is Unknown (ADR 0010).
    assert lookup == Lookup(
        Outcome.UNKNOWN, "registered 2012-11-07", {"registered": "2012-11-07T04:14:52Z", "rdap_domain": "wicar.org"}
    )


def test_a_subdomain_is_trimmed_until_the_registry_knows_it() -> None:
    transport = FakeTransport(
        {PIR + "malware.wicar.org": saved("subdomain"), PIR + "wicar.org": saved("registered")}
    )

    lookup = RdapProvider(transport).lookup(domain("malware.wicar.org"))

    assert (lookup.detail, lookup.evidence["rdap_domain"]) == ("registered 2012-11-07", "wicar.org")
    assert transport.requests == [BOOTSTRAP, PIR + "malware.wicar.org", PIR + "wicar.org"]


def test_trimming_stops_at_the_registered_domain_of_a_co_uk() -> None:
    lookup = look_up(domain("www.bbc.co.uk"), {NOMINET + "bbc.co.uk": saved("registered_co_uk")})

    assert (lookup.detail, lookup.evidence["rdap_domain"]) == ("registered 1994-12-13", "bbc.co.uk")


@pytest.mark.parametrize(
    ("observable", "answers", "detail"),
    [
        pytest.param(
            domain("wicar.org"), {PIR + "wicar.org": saved("registered_no_date")},
            "unknown age: the registry doesn't publish a registration date", id="no date",
        ),
        pytest.param(
            domain("evil.de"), {}, "unknown age: .de has no RDAP service", id="no RDAP service",
        ),
        pytest.param(
            domain("never-registered-phishing-triage-fixture-4f9b9e.com"),
            {VERISIGN + "never-registered-phishing-triage-fixture-4f9b9e.com": saved("not_found")},
            "unknown age: not found at the registry", id="not registered",
        ),
    ],
)
def test_unknown_age_is_unknown_with_the_reason_and_no_date(
    observable: Observable, answers: Mapping[str, HttpResponse], detail: str
) -> None:
    lookup = look_up(observable, answers)

    assert (lookup.outcome, lookup.detail, lookup.evidence["registered"]) == (Outcome.UNKNOWN, detail, None)


@pytest.mark.parametrize(
    ("answers", "reason", "stop_asking"),
    [
        pytest.param(
            {BOOTSTRAP: TransportError("timed out")},
            "could not reach the RDAP bootstrap list (timed out)", True, id="bootstrap unreachable",
        ),
        pytest.param(
            {PIR + "wicar.org": TransportError("timed out")},
            "could not reach the registry (timed out)", True, id="registry unreachable",
        ),
        pytest.param({PIR + "wicar.org": HttpResponse(429, b"")}, "rate limited by the registry", True, id="rate limited"),
        pytest.param({PIR + "wicar.org": HttpResponse(500, b"oops")}, "the registry answered with HTTP 500", False, id="server error"),
        pytest.param(
            {PIR + "wicar.org": HttpResponse(200, b"<html>")}, "the registry sent an unreadable answer", False,
            id="not JSON",
        ),
    ],
)
def test_problems_are_not_checked_with_the_reason(
    answers: Mapping[str, HttpResponse | Exception], reason: str, stop_asking: bool
) -> None:
    assert look_up(domain("wicar.org"), answers) == Lookup(Outcome.NOT_CHECKED, reason, stop_asking=stop_asking)


def test_the_bootstrap_list_is_fetched_once() -> None:
    transport = FakeTransport({PIR + "wicar.org": saved("registered")})
    provider = RdapProvider(transport)

    provider.lookup(domain("wicar.org"))
    provider.lookup(domain("wicar.org"))

    assert transport.requests.count(BOOTSTRAP) == 1


def registration_on(date_text: str) -> HttpResponse:
    body = '{"events": [{"eventAction": "registration", "eventDate": "%s"}]}' % date_text
    return HttpResponse(200, body.encode())


def test_a_date_with_no_time_zone_is_read_as_utc() -> None:
    lookup = look_up(domain("wicar.org"), {PIR + "wicar.org": registration_on("2026-09-30T23:30:00")})

    assert lookup.evidence["registered"] == "2026-09-30T23:30:00Z"


def test_an_unreadable_registration_date_is_unknown_age() -> None:
    lookup = look_up(domain("wicar.org"), {PIR + "wicar.org": registration_on("soon")})

    assert (lookup.outcome, lookup.detail, lookup.evidence["registered"]) == (
        Outcome.UNKNOWN, "unknown age: the registry's registration date can't be read", None
    )


def test_a_domain_with_non_latin_letters_is_asked_about_in_punycode() -> None:
    # "pаypal.org" with a Cyrillic "а", as a lookalike would use.
    transport = FakeTransport({PIR + "xn--pypal-4ve.org": saved("registered")})

    lookup = RdapProvider(transport).lookup(domain("p\u0430ypal.org"))

    assert lookup.detail == "registered 2012-11-07"
    assert transport.requests[-1] == PIR + "xn--pypal-4ve.org"


def test_a_trailing_dot_is_ignored() -> None:
    lookup = look_up(domain("wicar.org."), {PIR + "wicar.org": saved("registered")})

    assert lookup.detail == "registered 2012-11-07"
