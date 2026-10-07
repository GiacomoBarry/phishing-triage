"""Tests for the VirusTotal Provider, using saved responses through a fake transport.

No test here touches the network: the fake transport hands back fixture
files from tests/fixtures/virustotal/, named <case>.<HTTP status>.json.
"""

from collections.abc import Mapping
from pathlib import Path

import pytest

from phishing_triage.core import Lookup, Observable, ObservableKind, Outcome
from phishing_triage.providers.transport import HttpResponse, TransportError
from phishing_triage.providers.virustotal import VirusTotalProvider

FIXTURES = Path(__file__).parent / "fixtures" / "virustotal"

EICAR = Observable(
    ObservableKind.SHA256, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
)


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
        raise AssertionError("VirusTotal POST endpoints submit things for scanning (ADR 0001)")


def saved(case: str) -> HttpResponse:
    """The saved response for a case, with the status taken from its filename."""
    (path,) = FIXTURES.glob(f"{case}.*.json")
    return HttpResponse(status=int(path.suffixes[0].lstrip(".")), body=path.read_bytes())


def look_up(
    observable: Observable, response: HttpResponse | Exception, decisive_engines: int = 3
) -> Lookup:
    provider = VirusTotalProvider(
        api_key="test-key", transport=FakeTransport(response), decisive_engines=decisive_engines
    )
    return provider.lookup(observable)


def test_a_hash_flagged_by_many_engines_is_malicious_with_the_count() -> None:
    lookup = look_up(EICAR, saved("file_detected"))

    assert lookup.outcome is Outcome.MALICIOUS
    assert lookup.detail == "66 of 68 engines flag it as malicious"


GOOGLE = Observable(ObservableKind.DOMAIN, "google.com")


@pytest.mark.parametrize(
    ("observable", "case", "decisive_engines", "detail"),
    [
        pytest.param(GOOGLE, "domain_low_detections", 3, "2 of 92 engines flag it as malicious", id="google.com"),
        pytest.param(EICAR, "file_detected", 67, "66 of 68 engines flag it as malicious", id="threshold raised"),
    ],
)
def test_detections_below_the_decisive_threshold_are_only_suspicious(
    observable: Observable, case: str, decisive_engines: int, detail: str
) -> None:
    lookup = look_up(observable, saved(case), decisive_engines=decisive_engines)

    assert lookup.outcome is Outcome.SUSPICIOUS
    assert lookup.detail == detail


WICAR_URL = Observable(ObservableKind.URL, "http://malware.wicar.org/data/eicar.com")
WICAR_DOMAIN = Observable(ObservableKind.DOMAIN, "malware.wicar.org")
EMPTY_FILE = Observable(
    ObservableKind.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
GOOGLE_URL = Observable(ObservableKind.URL, "https://www.google.com/")
NEW_DOMAIN = Observable(ObservableKind.DOMAIN, "never-registered-phishing-triage-fixture-4f9b9e.com")
NEVER_SEEN_HASH = Observable(ObservableKind.SHA256, "4f9b9ede2dd1a9348377f8a240ed48b695593d51238c9cdc2a86e830cd037d16")
NEVER_SEEN_URL = Observable(ObservableKind.URL, "https://example.com/phishing-triage-fixture-never-seen")


@pytest.mark.parametrize(
    ("observable", "case", "detail"),
    [
        pytest.param(WICAR_URL, "url_detected", "19 of 93 engines flag it as malicious", id="URL"),
    ],
)
def test_urls_flagged_by_many_engines_are_malicious(
    observable: Observable, case: str, detail: str
) -> None:
    lookup = look_up(observable, saved(case))

    assert (lookup.outcome, lookup.detail) == (Outcome.MALICIOUS, detail)


@pytest.mark.parametrize(
    ("observable", "case", "detail"),
    [
        pytest.param(EMPTY_FILE, "file_clean", "0 of 60 engines flag it as malicious", id="hash"),
        pytest.param(GOOGLE_URL, "url_clean", "0 of 93 engines flag it as malicious", id="URL"),
    ],
)
def test_no_detections_is_clean(observable: Observable, case: str, detail: str) -> None:
    lookup = look_up(observable, saved(case))

    assert (lookup.outcome, lookup.detail) == (Outcome.CLEAN, detail)


@pytest.mark.parametrize(
    ("observable", "case"),
    [
        pytest.param(NEVER_SEEN_HASH, "file_not_found", id="hash"),
        pytest.param(NEVER_SEEN_URL, "url_not_found", id="URL"),
    ],
)
def test_never_seen_is_unknown_never_clean(observable: Observable, case: str) -> None:
    assert look_up(observable, saved(case)) == Lookup(Outcome.UNKNOWN, "never seen by VirusTotal")


def test_a_domain_no_engine_vouches_for_is_unknown_not_clean() -> None:
    # Looking a new domain up makes VirusTotal create a record on the spot:
    # every blocklist says "undetected" and none says "harmless". That's no
    # evidence it is clean (ADR 0006).
    lookup = look_up(NEW_DOMAIN, saved("domain_just_created"))

    assert (lookup.outcome, lookup.detail) == (
        Outcome.UNKNOWN,
        "no engine flags it, but none vouches for it either (0 of 92 say harmless)",
    )


@pytest.mark.parametrize(
    ("observable", "response", "reason", "stop_asking"),
    [
        pytest.param(EICAR, saved("bad_key"), "VirusTotal rejected the API key", True, id="bad key"),
        pytest.param(EICAR, saved("rate_limited"), "rate limited by VirusTotal", True, id="rate limited"),
        pytest.param(
            Observable(ObservableKind.DOMAIN, "never-registered-phishing-triage-fixture.example"),
            saved("domain_invalid"),
            "VirusTotal could not look it up (InvalidArgumentError)",
            False,
            id="invalid domain",
        ),
        pytest.param(EICAR, HttpResponse(500, b"oops"), "VirusTotal answered with HTTP 500", False, id="server error"),
        pytest.param(
            EICAR, HttpResponse(200, b"<html>maintenance</html>"),
            "VirusTotal sent an unreadable answer", False, id="not JSON",
        ),
        pytest.param(
            EICAR, HttpResponse(200, b'{"data": {"attributes": {}}}'),
            "VirusTotal sent an unreadable answer", False, id="no engine results",
        ),
        pytest.param(
            EICAR, TransportError("timed out"), "could not reach VirusTotal (timed out)", True, id="timeout"
        ),
    ],
)
def test_problems_are_not_checked_with_the_reason(
    observable: Observable, response: HttpResponse | Exception, reason: str, stop_asking: bool
) -> None:
    # Problems that will affect every lookup also say to stop asking VirusTotal for this Triage.
    assert look_up(observable, response) == Lookup(Outcome.NOT_CHECKED, reason, stop_asking=stop_asking)


def test_no_api_key_is_not_checked_without_asking_virustotal() -> None:
    transport = FakeTransport(AssertionError("VirusTotal should not be asked"))

    lookup = VirusTotalProvider(api_key=None, transport=transport, decisive_engines=3).lookup(EICAR)

    assert lookup == Lookup(Outcome.NOT_CHECKED, "no API key", stop_asking=True)
    assert transport.requests == []


def test_evidence_keeps_the_counts_flagging_engines_date_and_a_link() -> None:
    lookup = look_up(GOOGLE, saved("domain_low_detections"))

    assert lookup.evidence == {
        "malicious": 2,
        "suspicious": 0,
        "harmless": 58,
        "undetected": 32,
        "flagged_by": ["0xSI_f33d", "Fortra"],
        "last_analysis": "2026-10-07T18:19:45Z",
        "virustotal_link": "https://www.virustotal.com/gui/domain/google.com",
    }


def test_evidence_names_at_most_ten_flagging_engines() -> None:
    lookup = look_up(EICAR, saved("file_detected"))

    assert lookup.evidence["malicious"] == 66
    assert lookup.evidence["flagged_by"][:5] == ["ALYac", "APEX", "AVG", "AhnLab-V3", "Alibaba"]
    assert len(lookup.evidence["flagged_by"]) == 10


def test_only_lookup_endpoints_are_used_with_the_key_in_a_header() -> None:
    transport = FakeTransport(saved("url_not_found"))
    provider = VirusTotalProvider(api_key="test-key", transport=transport, decisive_engines=3)

    for observable in (WICAR_URL, WICAR_DOMAIN, EICAR):
        provider.lookup(observable)

    # Safety (ADR 0001): only GETs, which read what VirusTotal already knows.
    # POST /urls and /files would submit for scanning; the fake fails any POST.
    assert transport.requests == [
        (
            "https://www.virustotal.com/api/v3/urls/aHR0cDovL21hbHdhcmUud2ljYXIub3JnL2RhdGEvZWljYXIuY29t",
            {"x-apikey": "test-key"},
        ),
        ("https://www.virustotal.com/api/v3/domains/malware.wicar.org", {"x-apikey": "test-key"}),
        (f"https://www.virustotal.com/api/v3/files/{EICAR.value}", {"x-apikey": "test-key"}),
    ]


@pytest.mark.parametrize("observable", [EICAR, WICAR_URL], ids=["hash", "URL"])
def test_no_engine_answering_is_unknown_not_clean(observable: Observable) -> None:
    # Every Engine timed out or couldn't handle the file type: no evidence either way.
    body = (
        b'{"data": {"type": "file", "id": "x", "attributes": {"last_analysis_stats":'
        b' {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0,'
        b' "timeout": 3, "type-unsupported": 70}}}}'
    )

    lookup = look_up(observable, HttpResponse(200, body))

    assert (lookup.outcome, lookup.detail) == (Outcome.UNKNOWN, "no engine gave an answer")


def test_a_domain_is_never_more_than_suspicious_however_many_engines_flag_it() -> None:
    # Shared platforms collect detections too, so a domain alone is never decisive (ADR 0007).
    lookup = look_up(WICAR_DOMAIN, saved("domain_detected"))

    assert (lookup.outcome, lookup.detail) == (Outcome.SUSPICIOUS, "16 of 92 engines flag it as malicious")
