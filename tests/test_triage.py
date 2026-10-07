"""Tests at Seam 1: the core entry point, `triage()`."""

import socket
import urllib.request
from dataclasses import replace
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from uuid import UUID

import pytest

from phishing_triage.config import load_settings
from phishing_triage.core import (
    Finding,
    Observable,
    ObservableKind,
    RuleInput,
    Settings,
    UnparseableEmailError,
    Verdict,
    incident_note,
    triage,
)

FIXTURES = Path(__file__).parent / "fixtures"
DEFAULT_SETTINGS = load_settings()


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_parseable_email_with_no_rules_gets_a_clean_verdict() -> None:
    report = triage(load("clean_newsletter.eml"), DEFAULT_SETTINGS, providers=[])

    assert report.from_address == "news@example.org"
    assert report.display_name == "Example Newsletter"
    assert report.subject == "Your October update"
    assert report.score == 0
    assert report.verdict is Verdict.CLEAN


def test_report_carries_metadata_for_later_phases() -> None:
    before = datetime.now(UTC)
    report = triage(load("clean_newsletter.eml"), DEFAULT_SETTINGS, providers=[])
    after = datetime.now(UTC)

    assert UUID(report.report_id).version == 4
    assert before <= report.analysed_at <= after
    assert report.tool_version == "0.1.0"
    assert report.format_version == 1
    # Worked out independently with `shasum -a 256` on the fixture file.
    assert report.source_sha256 == (
        "5594a9c27c3b5075500b07ed8e0806ee0bb4bb4e49cf4ac5b503f85c57925ecd"
    )
    assert report.warnings == []
    assert report.tags == []


def test_each_triage_gets_its_own_report_id() -> None:
    raw = load("clean_newsletter.eml")

    first = triage(raw, DEFAULT_SETTINGS, providers=[])
    second = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert first.report_id != second.report_id


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(b"", id="empty file"),
        pytest.param(b"\x89PNG\r\n\x1a\n\x00\x00binary", id="binary file"),
        pytest.param(b"Just some notes.\nNot an email.\n", id="plain text"),
        pytest.param(b"Note: just text\nMore text\n", id="text that looks like a header"),
    ],
)
def test_input_with_no_email_headers_is_refused(raw: bytes) -> None:
    with pytest.raises(UnparseableEmailError):
        triage(raw, DEFAULT_SETTINGS, providers=[])


def test_missing_from_header_is_a_warning_not_an_error() -> None:
    raw = b"Subject: Invoice attached\r\n\r\nPlease see attached.\r\n"

    report = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert report.from_address == ""
    assert report.display_name == ""
    assert report.subject == "Invoice attached"
    assert report.warnings == ["The email has no From address."]


def test_incident_note_opens_with_a_one_line_summary() -> None:
    report = triage(load("clean_newsletter.eml"), DEFAULT_SETTINGS, providers=[])

    note = incident_note(report)

    assert note.splitlines()[0] == (
        "Verdict: CLEAN | Score: 0/100 | Sender: news@example.org"
        " | Subject: Your October update"
    )


def test_reply_to_on_a_different_domain_gives_a_finding() -> None:
    report = triage(load("reply_to_mismatch.eml"), DEFAULT_SETTINGS, providers=[])

    assert report.findings == [
        Finding(
            rule_id="reply_to_mismatch",
            points=20,
            decisive=False,
            evidence=(
                "Reply-To domain attacker.example differs from"
                " From domain example.org."
            ),
        )
    ]
    assert report.score == 20
    assert report.verdict is Verdict.CLEAN


def email_with_headers(*headers: str) -> bytes:
    """A minimal email with the given header lines and a short body."""
    return ("\r\n".join(headers) + "\r\n\r\nHello.\r\n").encode()


@pytest.mark.parametrize(
    "reply_to_header",
    [
        pytest.param(None, id="no Reply-To"),
        pytest.param("Reply-To: billing@example.org", id="same domain"),
        pytest.param("Reply-To: billing@EXAMPLE.org", id="same domain, other case"),
    ],
)
def test_no_reply_to_finding_when_replies_go_to_the_sender_domain(
    reply_to_header: str | None,
) -> None:
    headers = ["From: Accounts <accounts@example.org>", "Subject: Invoice"]
    if reply_to_header:
        headers.append(reply_to_header)

    report = triage(email_with_headers(*headers), DEFAULT_SETTINGS, providers=[])

    assert report.findings == []
    assert report.score == 0


def settings_with_reply_to_points(points: int) -> Settings:
    return replace(DEFAULT_SETTINGS, points={**DEFAULT_SETTINGS.points, "reply_to_mismatch": points})


@pytest.mark.parametrize(
    ("score", "verdict"),
    [
        (29, Verdict.CLEAN),
        (30, Verdict.SUSPICIOUS),
        (59, Verdict.SUSPICIOUS),
        (60, Verdict.MALICIOUS),
    ],
)
def test_score_thresholds_set_the_verdict(score: int, verdict: Verdict) -> None:
    settings = settings_with_reply_to_points(score)

    report = triage(load("reply_to_mismatch.eml"), settings, providers=[])

    assert report.score == score
    assert report.verdict is verdict


def test_score_is_capped_at_100() -> None:
    settings = settings_with_reply_to_points(150)

    report = triage(load("reply_to_mismatch.eml"), settings, providers=[])

    assert report.score == 100
    assert report.verdict is Verdict.MALICIOUS


def always_decisive(rule_input: RuleInput, settings: Settings) -> list[Finding]:
    """A test-only rule standing in for, say, a URL listed on URLhaus."""
    return [
        Finding(
            rule_id="test_decisive",
            points=40,
            decisive=True,
            evidence="Test-only Decisive Finding.",
        )
    ]


def test_decisive_finding_makes_the_verdict_malicious_whatever_the_score() -> None:
    report = triage(
        load("clean_newsletter.eml"),
        DEFAULT_SETTINGS,
        providers=[],
        rules=[always_decisive],
    )

    assert report.verdict is Verdict.MALICIOUS
    # Decisive Findings decide the Verdict but add nothing to the Score.
    assert report.score == 0


def test_incident_note_lists_key_findings_with_evidence() -> None:
    report = triage(load("reply_to_mismatch.eml"), DEFAULT_SETTINGS, providers=[])

    note = incident_note(report)

    assert note == (
        "Verdict: CLEAN | Score: 20/100 | Sender: payroll@example.org"
        " | Subject: Update your bank details\n"
        "\n"
        "Key Findings:\n"
        "- Reply-To domain attacker.example differs from From domain"
        " example.org. (+20 points)\n"
        "\n"
        "Observables (defanged):\n"
        "- None.\n"
    )


def test_incident_note_marks_decisive_findings_and_says_when_there_are_none() -> None:
    decisive = triage(
        load("clean_newsletter.eml"),
        DEFAULT_SETTINGS,
        providers=[],
        rules=[always_decisive],
    )
    clean = triage(load("clean_newsletter.eml"), DEFAULT_SETTINGS, providers=[])

    assert "- Test-only Decisive Finding. (decisive)\n" in incident_note(decisive)
    assert "Key Findings:\n- None.\n" in incident_note(clean)


def test_any_reply_to_address_on_another_domain_gives_a_finding() -> None:
    raw = email_with_headers(
        "From: Accounts <accounts@example.org>",
        "Reply-To: billing@example.org, collections@attacker.example",
        "Subject: Overdue invoice",
    )

    report = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert [finding.evidence for finding in report.findings] == [
        "Reply-To domain attacker.example differs from From domain example.org."
    ]


def twenty_points(rule_input: RuleInput, settings: Settings) -> list[Finding]:
    """A test-only rule giving a low, non-decisive Score."""
    return [Finding("test_points", 20, decisive=False, evidence="Test-only Finding.")]


def test_decisive_finding_outweighs_a_low_score_from_other_findings() -> None:
    report = triage(
        load("clean_newsletter.eml"),
        DEFAULT_SETTINGS,
        providers=[],
        rules=[twenty_points, always_decisive],
    )

    assert report.score == 20
    assert report.verdict is Verdict.MALICIOUS


def test_reply_to_finding_names_every_other_domain_once() -> None:
    raw = email_with_headers(
        "From: accounts@example.org",
        "Reply-To: a@first.example, b@second.example, c@first.example",
        "Subject: Overdue invoice",
    )

    report = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert [finding.evidence for finding in report.findings] == [
        "Reply-To domains first.example, second.example differ"
        " from From domain example.org."
    ]


# --- Display-name impersonation and sender Lookalike Domains (ticket 04) ---


def findings_for_sender(from_header: str, settings: Settings = DEFAULT_SETTINGS) -> list[Finding]:
    """Triage a minimal email from the given sender and return its Findings."""
    raw = email_with_headers(f"From: {from_header}", "Subject: Account notice")
    return triage(raw, settings, providers=[]).findings


def rule_ids(findings: list[Finding]) -> list[str]:
    return [finding.rule_id for finding in findings]


@pytest.mark.parametrize(
    "from_header",
    [
        pytest.param("PayPal <service@paypal.com>", id="brand's own domain"),
        pytest.param("PayPal <service@PayPal.co.uk>", id="brand's other domain, other case"),
        pytest.param("PayPal Alerts <service@mail.paypal.com>", id="brand's subdomain"),
        pytest.param("HMRC <noreply@notify.hmrc.gov.uk>", id="government subdomain"),
        pytest.param("Royal Mail <tracking@royalmail.com>", id="two-word brand"),
    ],
)
def test_genuine_brand_senders_give_no_findings(from_header: str) -> None:
    assert findings_for_sender(from_header) == []


def test_display_name_naming_a_brand_from_another_domain_gives_a_finding() -> None:
    findings = findings_for_sender("PayPal Service <alerts@random-mailer.example>")

    assert findings == [
        Finding(
            rule_id="display_name_impersonation",
            points=25,
            decisive=False,
            evidence=(
                'Display name "PayPal Service" names PayPal, but the sending domain'
                " random-mailer.example is not one of PayPal's domains"
                " (paypal.com, paypal.co.uk)."
            ),
        )
    ]


@pytest.mark.parametrize(
    "from_header",
    [
        pytest.param("Royal Mail Delivery <parcel@tracking-update.example>", id="two-word brand"),
        pytest.param("microsoft account team <it@helpdesk.example>", id="lower case"),
        pytest.param('"service@paypal.com" <x@evil.example>', id="address as display name"),
        pytest.param("Google Security <google.security@gmail.com>", id="free webmail"),
    ],
)
def test_brand_in_display_name_is_matched_flexibly(from_header: str) -> None:
    assert rule_ids(findings_for_sender(from_header)) == ["display_name_impersonation"]


@pytest.mark.parametrize(
    "from_header",
    [
        pytest.param("Applebee's <offers@applebees.example>", id="brand inside a longer word"),
        pytest.param("Jo Bloggs <jo@example.org>", id="no brand"),
        pytest.param("<jo@example.org>", id="no display name"),
    ],
)
def test_no_impersonation_finding_without_a_whole_brand_name(from_header: str) -> None:
    assert findings_for_sender(from_header) == []


@pytest.mark.parametrize(
    ("sender_domain", "imitated", "technique"),
    [
        pytest.param("paypa1.com", "paypal.com", "swaps characters to look like paypal", id="digit for letter"),
        pytest.param("rnicrosoft.com", "microsoft.com", "swaps characters to look like microsoft", id="rn for m"),
        pytest.param("g00gle.co.uk", "google.com", "swaps characters to look like google", id="zeros for o"),
        pytest.param("paypall.com", "paypal.com", "is one letter off from paypal", id="letter added"),
        pytest.param("amazn.com", "amazon.com", "is one letter off from amazon", id="letter dropped"),
        pytest.param("micrasoft.com", "microsoft.com", "is one letter off from microsoft", id="letter changed"),
        pytest.param("paypla.com", "paypal.com", "is one letter off from paypal", id="letters swapped"),
        pytest.param("paypal-secure.xyz", "paypal.com", "adds words to the name paypal", id="extra word after"),
        pytest.param("secure-dhl.com", "dhl.com", "adds words to the name dhl", id="extra word before"),
        pytest.param("paypa1-secure.xyz", "paypal.com", "swaps characters to look like paypal", id="swap plus extra word"),
        pytest.param("paypal.com.evil.example", "paypal.com", "reuses the name paypal", id="brand as subdomain"),
        pytest.param("paypal.xyz", "paypal.com", "reuses the name paypal", id="different ending"),
        pytest.param(
            "xn--pypal-4ve.com", "paypal.com", "uses non-Latin letters (p\u0430ypal) to look like paypal",
            id="Cyrillic letter",
        ),
    ],
)
def test_sender_lookalike_domains_give_a_finding(
    sender_domain: str, imitated: str, technique: str
) -> None:
    findings = findings_for_sender(f"<alerts@{sender_domain}>")

    assert findings == [
        Finding(
            rule_id="lookalike_domain",
            points=30,
            decisive=False,
            evidence=f"Sender domain {sender_domain} imitates Protected Domain {imitated}: it {technique}.",
        )
    ]


@pytest.mark.parametrize(
    "sender_domain",
    [
        pytest.param("pineapple.example", id="brand inside a longer word"),
        pytest.param("dhs.gov", id="short brand one letter off"),
        pytest.param("example.org", id="unrelated"),
        pytest.param("paypalsecure.example", id="joined without a hyphen (known gap)"),
    ],
)
def test_near_misses_are_not_lookalikes(sender_domain: str) -> None:
    assert findings_for_sender(f"<alerts@{sender_domain}>") == []


def test_impersonation_and_lookalike_together_add_up_to_suspicious() -> None:
    raw = email_with_headers("From: PayPal <service@paypa1.com>", "Subject: Account notice")

    report = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert rule_ids(report.findings) == ["display_name_impersonation", "lookalike_domain"]
    assert report.score == 55
    assert report.verdict is Verdict.SUSPICIOUS


def test_analysts_own_brand_is_protected_once_added_to_settings() -> None:
    settings = replace(DEFAULT_SETTINGS, brands={"Acme": ("acme.co.uk",)})

    assert findings_for_sender("Acme IT <it@acme.co.uk>", settings) == []
    assert rule_ids(findings_for_sender("Acme IT <it@acrne.co.uk>", settings)) == [
        "display_name_impersonation",
        "lookalike_domain",
    ]


# --- URLs: extraction, offline decoding, shorteners and link Lookalikes (ticket 07) ---


def email_with_body(
    plain: str | None = None,
    html: str | None = None,
    from_header: str = "Alerts <alerts@example.org>",
    attachment: str | None = None,
) -> bytes:
    """An email with a plain-text body, an HTML body, or both, and an optional attachment."""
    message = EmailMessage()
    message["From"] = from_header
    message["Subject"] = "Account notice"
    if plain is not None:
        message.set_content(plain)
    if html is not None:
        if plain is None:
            message.set_content(html, subtype="html")
        else:
            message.add_alternative(html, subtype="html")
    if plain is None and html is None:
        message.set_content("Hello.")
    if attachment is not None:
        message.add_attachment(attachment, filename="notes.txt")
    return message.as_bytes()


def urls_in(raw: bytes) -> list[str]:
    report = triage(raw, DEFAULT_SETTINGS, providers=[])
    return [o.value for o in report.observables if o.kind is ObservableKind.URL]


def test_urls_and_their_domains_become_observables_without_repeats() -> None:
    raw = email_with_body(
        plain="Log in at https://Evil.EXAMPLE/login, or https://evil.example/login.\n"
        "Help: https://help.evil.example/faq"
    )

    report = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert report.observables == [
        Observable(ObservableKind.URL, "https://evil.example/login"),
        Observable(ObservableKind.URL, "https://help.evil.example/faq"),
        Observable(ObservableKind.DOMAIN, "evil.example"),
        Observable(ObservableKind.DOMAIN, "help.evil.example"),
    ]
    assert report.to_dict()["observables"][0] == {
        "kind": "url",
        "value": "https://evil.example/login",
    }


SAFELINK = (
    "https://eur01.safelinks.protection.outlook.com/"
    "?url=https%3A%2F%2Fevil.example%2Flogin&data=05%7C01&reserved=0"
)


@pytest.mark.parametrize(
    ("plain", "html", "expected"),
    [
        pytest.param("Go to hxxps://evil[.]example/login", None, "https://evil.example/login", id="hxxp and [.]"),
        pytest.param("Go to hXXp://evil(.)example", None, "http://evil.example", id="hXXp and (.)"),
        pytest.param("Go to hxxps[:]//evil[.]example/a", None, "https://evil.example/a", id="[:]"),
        pytest.param("Go to https://evil&#46;example/pay", None, "https://evil.example/pay", id="entity in text"),
        pytest.param(
            None, '<a href="https://evil&#46;example/pay">Pay now</a>', "https://evil.example/pay",
            id="entity in HTML link",
        ),
        pytest.param(f"Go to {SAFELINK}", None, "https://evil.example/login", id="SafeLinks"),
        pytest.param(
            "Go to https://www.google.com/url?q=https://evil.example/x&sa=D", None, "https://evil.example/x",
            id="Google redirect",
        ),
        pytest.param(
            "Go to https://eur01.safelinks.protection.outlook.com/?url="
            "https%3A%2F%2Fwww.google.com%2Furl%3Fq%3Dhttps%253A%252F%252Fevil.example%252Fx",
            None, "https://evil.example/x", id="wrapper inside a wrapper",
        ),
        pytest.param("Go to www.evil.example/login", None, "http://www.evil.example/login", id="www without scheme"),
    ],
)
def test_obfuscated_urls_are_decoded_offline(plain: str | None, html: str | None, expected: str) -> None:
    assert urls_in(email_with_body(plain=plain, html=html)) == [expected]


def test_html_link_targets_and_visible_text_are_both_searched() -> None:
    raw = email_with_body(
        html='<p>Hi,</p><a href="https://evil.example/login">https://www.paypal.com/account</a>'
        '<img src="https://tracker.example/pixel.gif">'
    )

    # The link target and the visible text differ: both are recorded.
    # Image addresses (mostly tracking pixels) are not.
    assert urls_in(raw) == ["https://evil.example/login", "https://www.paypal.com/account"]


def test_urls_in_attachments_are_not_read() -> None:
    raw = email_with_body(plain="See attached.", attachment="https://in-attachment.example/x")

    assert urls_in(raw) == []


def test_a_url_with_an_ip_address_host_gives_no_domain_observable() -> None:
    report = triage(email_with_body(plain="http://192.0.2.10/login"), DEFAULT_SETTINGS, providers=[])

    assert report.observables == [Observable(ObservableKind.URL, "http://192.0.2.10/login")]


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any attempt to open a network connection fail the test."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


@pytest.mark.usefixtures("no_network")
def test_url_handling_never_touches_the_network() -> None:
    # First prove the guard works: a real request is refused.
    with pytest.raises(AssertionError, match="network access attempted"):
        urllib.request.urlopen("http://example.com", timeout=1)

    raw = email_with_body(
        plain=f"https://bit.ly/abc {SAFELINK} hxxps://paypa1[.]com/login",
        html='<a href="https://www.google.com/url?q=https://evil.example/x">here</a>',
    )
    report = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert len(urls_in(raw)) == 4
    assert rule_ids(report.findings) == ["lookalike_domain", "url_shortener"]


def test_shortened_urls_give_one_finding_listing_them_defanged() -> None:
    raw = email_with_body(plain="https://bit.ly/abc and https://www.tinyurl.com/xyz and https://example.org")

    findings = triage(raw, DEFAULT_SETTINGS, providers=[]).findings

    assert findings == [
        Finding(
            rule_id="url_shortener",
            points=10,
            decisive=False,
            evidence=(
                "Shortened URLs hide their real destinations:"
                " hxxps://bit[.]ly/abc, hxxps://www[.]tinyurl[.]com/xyz."
            ),
        )
    ]


@pytest.mark.parametrize(
    "url",
    [
        pytest.param("https://notbit.ly/x", id="ends with a shortener's name"),
        pytest.param("https://bit.ly.evil.example/x", id="shortener as a subdomain"),
    ],
)
def test_near_miss_shortener_domains_give_no_finding(url: str) -> None:
    assert triage(email_with_body(plain=url), DEFAULT_SETTINGS, providers=[]).findings == []


def test_lookalike_link_domain_gives_a_finding() -> None:
    raw = email_with_body(plain="Verify at https://paypa1.com/login")

    findings = triage(raw, DEFAULT_SETTINGS, providers=[]).findings

    assert findings == [
        Finding(
            rule_id="lookalike_domain",
            points=30,
            decisive=False,
            evidence=(
                "Link domain paypa1.com imitates Protected Domain paypal.com:"
                " it swaps characters to look like paypal."
            ),
        )
    ]


def test_sender_and_link_imitating_the_same_brand_count_once() -> None:
    raw = email_with_body(
        plain="Verify at https://paypa1.com/login or https://paypal-verify.example/",
        from_header="Alerts <alerts@paypa1.com>",
    )

    report = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert [f.evidence for f in report.findings] == [
        "Sender and link domain paypa1.com imitates Protected Domain paypal.com:"
        " it swaps characters to look like paypal."
        " Link domain paypal-verify.example imitates Protected Domain paypal.com:"
        " it adds words to the name paypal."
    ]
    assert report.score == 30


def test_links_imitating_two_brands_give_two_findings() -> None:
    raw = email_with_body(plain="https://paypa1.com/a https://rnicrosoft.com/b")

    findings = triage(raw, DEFAULT_SETTINGS, providers=[]).findings

    assert rule_ids(findings) == ["lookalike_domain", "lookalike_domain"]


def test_genuine_brand_links_behind_safelinks_give_no_findings() -> None:
    raw = email_with_body(
        plain="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Faccount.microsoft.com%2F"
    )

    report = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert report.findings == []
    assert report.observables == [
        Observable(ObservableKind.URL, "https://account.microsoft.com/"),
        Observable(ObservableKind.DOMAIN, "account.microsoft.com"),
    ]


def test_incident_note_lists_observables_defanged_and_nothing_clickable() -> None:
    raw = email_with_body(plain="https://bit.ly/abc and http://evil.example/login.php")

    note = incident_note(triage(raw, DEFAULT_SETTINGS, providers=[]))

    assert note.endswith(
        "Observables (defanged):\n"
        "- URL: hxxps://bit[.]ly/abc\n"
        "- URL: hxxp://evil[.]example/login.php\n"
        "- Domain: bit[.]ly\n"
        "- Domain: evil[.]example\n"
    )
    assert "http" not in note
