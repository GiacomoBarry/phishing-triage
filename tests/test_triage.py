"""Tests at Seam 1: the core entry point, `triage()`."""

import builtins
import io
import os
import socket
import urllib.request
import zipfile
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from uuid import UUID

import pytest

from phishing_triage.config import load_settings
from phishing_triage.providers.transport import HttpResponse
from phishing_triage.providers.urlhaus import URLhausProvider
from phishing_triage.core import (
    URLHAUS,
    VIRUSTOTAL,
    Attachment,
    CachedLookup,
    Finding,
    Lookup,
    LookupStarted,
    NotChecked,
    Observable,
    ObservableKind,
    Outcome,
    Progress,
    ProviderStopped,
    RuleInput,
    Settings,
    TriageReport,
    UnparseableEmailError,
    Verdict,
    WaitingForRateLimit,
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
        "- Sender domain: example[.]org\n"
        "\n"
        "Not Checked:\n"
        "- Sender domain: example[.]org: no Provider looks this kind of Observable up yet\n"
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
    from_header: str | None = "Alerts <alerts@example.org>",
    attachment: str | None = None,
) -> bytes:
    """An email with a plain-text body, an HTML body, or both, and an optional attachment.

    `from_header=None` leaves the From header out, so the email has no Sender
    Domain: tests about link lookups use that to count only the links.
    """
    message = EmailMessage()
    if from_header is not None:
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
        Observable(ObservableKind.SENDER_DOMAIN, "example.org"),
        Observable(ObservableKind.URL, "https://evil.example/login"),
        Observable(ObservableKind.URL, "https://help.evil.example/faq"),
        Observable(ObservableKind.DOMAIN, "evil.example"),
        Observable(ObservableKind.DOMAIN, "help.evil.example"),
    ]
    assert report.to_dict()["observables"][1] == {
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

    assert report.observables == [
        Observable(ObservableKind.SENDER_DOMAIN, "example.org"),
        Observable(ObservableKind.URL, "http://192.0.2.10/login"),
    ]


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
        Observable(ObservableKind.SENDER_DOMAIN, "example.org"),
        Observable(ObservableKind.URL, "https://account.microsoft.com/"),
        Observable(ObservableKind.DOMAIN, "account.microsoft.com"),
    ]


def test_incident_note_lists_observables_defanged_and_nothing_clickable() -> None:
    raw = email_with_body(plain="https://bit.ly/abc and http://evil.example/login.php")

    note = incident_note(triage(raw, DEFAULT_SETTINGS, providers=[]))

    assert (
        "Observables (defanged):\n"
        "- Sender domain: example[.]org\n"
        "- URL: hxxps://bit[.]ly/abc\n"
        "- URL: hxxp://evil[.]example/login.php\n"
        "- Domain: bit[.]ly\n"
        "- Domain: evil[.]example\n"
    ) in note
    assert "http" not in note


# --- Attachments: hashes and attachment Findings (ticket 08) ---


def email_with_attachments(*attachments: tuple[str, bytes, str], inline: bool = False) -> bytes:
    """An email with a short body and the given (filename, content, declared type) attachments."""
    message = EmailMessage()
    message["From"] = "Accounts <accounts@example.org>"
    message["Subject"] = "Invoice"
    message.set_content("Please see attached.")
    for filename, content, content_type in attachments:
        maintype, subtype = content_type.split("/")
        message.add_attachment(
            content,
            maintype=maintype,
            subtype=subtype,
            filename=filename,
            disposition="inline" if inline else "attachment",
        )
    return message.as_bytes()


def attachment_evidence(raw: bytes) -> list[str]:
    report = triage(raw, DEFAULT_SETTINGS, providers=[])
    return [f.evidence for f in report.findings if f.rule_id == "risky_attachment"]


def a_zip(*, encrypted: bool = False) -> bytes:
    """A small ZIP, optionally marked as encrypted.

    Python can't write a really encrypted ZIP, but the tool only reads the
    "encrypted" flag, so setting that bit in both places it's stored is enough.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("invoice.exe", b"MZ not really a program")
    data = bytearray(buffer.getvalue())
    if encrypted:
        data[6] |= 0x1  # Flags in the file's local header.
        data[data.index(b"PK\x01\x02") + 8] |= 0x1  # Flags in the table of contents.
    return bytes(data)


def test_benign_attachment_is_recorded_with_correct_hashes_and_no_finding() -> None:
    report = triage(load("benign_attachment.eml"), DEFAULT_SETTINGS, providers=[])

    # Expected hashes worked out separately with shasum and md5, not with this code.
    sha256 = "56466756b631879f95cb959987c9d36c3581d1f12d37914d50e73f5d7d99ceff"
    assert report.attachments == [
        Attachment(
            filename="agenda.txt",
            content_type="text/plain",
            size=37,
            sha256=sha256,
            md5="21ef88c005f99434769f4cc4ca2de563",
            sha1="0302994af3ee7c69191e3897ebae59a306519baa",
            archive_type="",
            password_protected=False,
        )
    ]
    assert report.observables == [
        Observable(ObservableKind.SENDER_DOMAIN, "example.org"),
        Observable(ObservableKind.SHA256, sha256),
    ]
    assert report.findings == []
    assert f"- SHA-256: {sha256} (agenda.txt)" in incident_note(report)


@pytest.mark.parametrize(
    ("filename", "content", "content_type", "evidence"),
    [
        pytest.param(
            "setup.exe", b"MZ", "application/octet-stream",
            'Attachment "setup.exe" has a risky extension (.exe).', id="risky extension",
        ),
        pytest.param(
            "Invoice.PDF.exe", b"MZ", "application/pdf",
            'Attachment "Invoice.PDF.exe" has a risky extension (.exe) and has a double extension (.pdf.exe).',
            id="double extension",
        ),
        pytest.param(
            "invoice.pdf      .exe", b"MZ", "application/octet-stream",
            'Attachment "invoice.pdf      .exe" has a risky extension (.exe)'
            " and has a double extension (.pdf.exe).",
            id="double extension padded with spaces",
        ),
        pytest.param(
            "login.html", b"<form>", "text/html",
            'Attachment "login.html" has a risky extension (.html).', id="HTML page",
        ),
        pytest.param(
            "invoice\u202egpj.exe", b"MZ", "application/octet-stream",
            'Attachment "invoice\\u202egpj.exe" has hidden characters that can disguise its real'
            " extension and has a risky extension (.exe).",
            id="right-to-left override",
        ),
        pytest.param(
            "documents.zip", a_zip(), "application/zip",
            'Attachment "documents.zip" is an archive (zip).', id="zip archive",
        ),
        pytest.param(
            "statement.pdf", a_zip(), "application/pdf",
            'Attachment "statement.pdf" is an archive (zip).', id="zip disguised as a PDF",
        ),
        pytest.param(
            "backup.rar", b"not checked", "application/octet-stream",
            'Attachment "backup.rar" is an archive (rar).', id="archive by extension",
        ),
        pytest.param(
            "documents.zip", a_zip(encrypted=True), "application/zip",
            'Attachment "documents.zip" is a password-protected archive, so it can\'t be scanned.',
            id="password-protected zip",
        ),
    ],
)
def test_dangerous_looking_attachments_give_a_finding_naming_the_file_and_reason(
    filename: str, content: bytes, content_type: str, evidence: str
) -> None:
    raw = email_with_attachments((filename, content, content_type))

    assert attachment_evidence(raw) == [evidence]


@pytest.mark.parametrize(
    ("filename", "content", "content_type"),
    [
        pytest.param("report.docx", a_zip(), "application/octet-stream", id="Word file is a ZIP inside"),
        pytest.param("photo.jpg", b"\xff\xd8\xff", "image/jpeg", id="image"),
        pytest.param("notes.v2.txt", b"hello", "text/plain", id="harmless double extension"),
        pytest.param("exe", b"hello", "text/plain", id="name without an extension"),
    ],
)
def test_ordinary_attachments_give_no_finding(filename: str, content: bytes, content_type: str) -> None:
    assert attachment_evidence(email_with_attachments((filename, content, content_type))) == []


def test_several_dangerous_attachments_give_one_finding() -> None:
    raw = email_with_attachments(
        ("setup.exe", b"MZ", "application/octet-stream"),
        ("agenda.txt", b"hello", "text/plain"),
        ("archive.zip", a_zip(), "application/zip"),
    )

    report = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert attachment_evidence(raw) == [
        'Attachment "setup.exe" has a risky extension (.exe).'
        ' Attachment "archive.zip" is an archive (zip).'
    ]
    assert report.score == 25
    assert [a.filename for a in report.attachments] == ["setup.exe", "agenda.txt", "archive.zip"]


def test_an_exe_marked_inline_is_still_an_attachment() -> None:
    raw = email_with_attachments(("setup.exe", b"MZ", "application/octet-stream"), inline=True)

    assert attachment_evidence(raw) == ['Attachment "setup.exe" has a risky extension (.exe).']


def test_an_attached_email_is_hashed_whole_but_not_opened() -> None:
    inner = EmailMessage()
    inner["From"] = "PayPal <x@paypa1.com>"
    inner["Subject"] = "Inner"
    inner.set_content("https://inner-link.example/login")
    outer = EmailMessage()
    outer["From"] = "Jo <jo@example.org>"
    outer["Subject"] = "Fwd: suspicious"
    outer.set_content("Is this real?")
    outer.add_attachment(inner)

    report = triage(outer.as_bytes(), DEFAULT_SETTINGS, providers=[])

    assert [a.content_type for a in report.attachments] == ["message/rfc822"]
    assert report.attachments[0].size > 0
    # Nothing from inside the attached email is used (ticket 06 decides that).
    assert [o.kind for o in report.observables] == [ObservableKind.SENDER_DOMAIN, ObservableKind.SHA256]
    assert report.findings == []


def test_same_file_attached_twice_gives_one_hash_observable() -> None:
    raw = email_with_attachments(
        ("a.txt", b"same", "text/plain"), ("b.txt", b"same", "text/plain")
    )

    report = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert len(report.attachments) == 2
    assert [o.kind for o in report.observables] == [ObservableKind.SENDER_DOMAIN, ObservableKind.SHA256]
    assert "(a.txt, b.txt)" in incident_note(report)


def forbid_files_and_unpacking(monkeypatch: pytest.MonkeyPatch) -> None:
    """From now on in this test, opening a file or reading inside a ZIP fails it.

    A plain function rather than a fixture, so the test can build its ZIP first.
    """

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("file opened or archive unpacked")

    monkeypatch.setattr(builtins, "open", refuse)
    monkeypatch.setattr(io, "open", refuse)
    monkeypatch.setattr(os, "open", refuse)
    for method in ("open", "read", "extract", "extractall"):
        monkeypatch.setattr(zipfile.ZipFile, method, refuse)


def test_attachments_are_never_written_to_disk_or_unpacked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = email_with_attachments(
        ("setup.exe", b"MZ", "application/octet-stream"),
        ("documents.zip", a_zip(encrypted=True), "application/zip"),
    )
    forbid_files_and_unpacking(monkeypatch)

    report = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert report.attachments[1].password_protected


# --- Provider framework, URLhaus, and "clean requires evidence" (ticket 09) ---

ALL_KINDS = frozenset(ObservableKind)
# What a typical fake handles: everything but attachment hashes.
DOMAINS_AND_URLS = frozenset({ObservableKind.SENDER_DOMAIN, ObservableKind.DOMAIN, ObservableKind.URL})


class FakeProvider:
    """A Provider with canned answers that records what it was asked.

    It answers `default` unless `answers` has an entry for the value, and
    raises if `fail` is set. It has submit and scan methods that fail the
    test if ever called, standing in for the endpoints ADR 0001 forbids.
    """

    def __init__(
        self,
        name: str = "FakeIntel",
        handles: frozenset[ObservableKind] = DOMAINS_AND_URLS,
        default: Lookup = Lookup(Outcome.UNKNOWN, "not listed"),
        answers: dict[str, Lookup] | None = None,
        fail: bool = False,
        lookups_per_minute: int | None = None,
    ) -> None:
        self._name = name
        self._lookups_per_minute = lookups_per_minute
        self._handles = handles
        self.default = default
        self.answers = answers or {}
        self.fail = fail
        self.received: list[Observable] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def handles(self) -> frozenset[ObservableKind]:
        return self._handles

    @property
    def lookups_per_minute(self) -> int | None:
        return self._lookups_per_minute

    def lookup(self, observable: Observable) -> Lookup:
        self.received.append(observable)
        if self.fail:
            raise RuntimeError("service exploded")
        return self.answers.get(observable.value, self.default)

    def submit(self, *args: object) -> None:
        raise AssertionError("a Provider was asked to submit something (ADR 0001)")

    def scan(self, *args: object) -> None:
        raise AssertionError("a Provider was asked to scan something (ADR 0001)")


class UnusedTransport:
    """A transport for a Provider with no key, which must never send anything."""

    def post(self, url: str, form: Mapping[str, str], headers: Mapping[str, str]) -> HttpResponse:
        raise AssertionError("nothing should be sent without an API key")

    def get(self, url: str, headers: Mapping[str, str]) -> HttpResponse:
        raise AssertionError("nothing should be sent without an API key")


LINK_EMAIL = email_with_body(plain="Your invoice: https://evil.example/invoice", from_header=None)
LISTED = Lookup(Outcome.MALICIOUS, "listed as malware_download, currently online")


def test_a_malicious_lookup_is_a_decisive_finding() -> None:
    provider = FakeProvider(answers={"https://evil.example/invoice": LISTED})

    report = triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[provider])

    assert report.findings == [
        Finding(
            rule_id="known_malicious",
            points=0,
            decisive=True,
            evidence=(
                "FakeIntel reports URL hxxps://evil[.]example/invoice as malicious:"
                " listed as malware_download, currently online."
            ),
        )
    ]
    assert report.verdict is Verdict.MALICIOUS


def test_unknown_everywhere_can_still_be_clean() -> None:
    report = triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[FakeProvider()])

    assert report.verdict is Verdict.CLEAN
    assert report.not_checked == []
    assert report.cap_reason == ""
    assert [(r.provider, r.observable.value, r.outcome) for r in report.lookups] == [
        ("FakeIntel", "evil.example", Outcome.UNKNOWN),
        ("FakeIntel", "https://evil.example/invoice", Outcome.UNKNOWN),
    ]
    assert report.to_dict()["lookups"][1] == {
        "provider": "FakeIntel",
        "observable": {"kind": "url", "value": "https://evil.example/invoice"},
        "outcome": "unknown",
        "detail": "not listed",
        "evidence": {},
        "from_cache": False,
        "cached_at": None,
    }


def test_a_link_nobody_checked_raises_clean_to_suspicious() -> None:
    report = triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[])

    assert report.verdict_before_cap is Verdict.CLEAN
    assert report.verdict is Verdict.SUSPICIOUS
    assert report.cap_reason == (
        "Raised from clean to suspicious: 1 URL or attachment was Not Checked,"
        " so there isn't the evidence to call this email clean."
    )
    assert report.to_dict()["verdict_before_cap"] == "clean"


def test_missing_api_key_is_not_checked_and_the_run_continues() -> None:
    urlhaus = URLhausProvider(auth_key=None, transport=UnusedTransport())

    report = triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[urlhaus])

    assert report.not_checked == [
        NotChecked(Observable(ObservableKind.URL, "https://evil.example/invoice"), ["URLhaus: no API key"]),
        NotChecked(Observable(ObservableKind.DOMAIN, "evil.example"), ["URLhaus: no API key"]),
    ]
    assert report.verdict is Verdict.SUSPICIOUS


def test_a_failing_provider_is_not_checked_never_a_crash() -> None:
    report = triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[FakeProvider(fail=True)])

    assert report.not_checked[0].reasons == [
        "FakeIntel: the Provider failed (RuntimeError: service exploded)"
    ]
    assert report.verdict is Verdict.SUSPICIOUS


def test_one_provider_answering_is_enough_evidence() -> None:
    providers = [FakeProvider(name="Down", fail=True), FakeProvider(name="Up")]

    report = triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=providers)

    assert report.not_checked == []
    assert report.verdict is Verdict.CLEAN


def test_unchecked_domains_alone_dont_raise_the_verdict() -> None:
    urls_only = FakeProvider(handles=frozenset({ObservableKind.URL}))

    report = triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[urls_only])

    assert [n.observable.kind for n in report.not_checked] == [ObservableKind.DOMAIN]
    assert report.not_checked[0].reasons == ["no Provider looks this kind of Observable up yet"]
    assert report.verdict is Verdict.CLEAN


def test_an_attachment_nobody_checked_raises_clean_to_suspicious() -> None:
    report = triage(load("benign_attachment.eml"), DEFAULT_SETTINGS, providers=[FakeProvider()])

    assert report.findings == []
    assert report.verdict is Verdict.SUSPICIOUS
    assert [n.observable.kind for n in report.not_checked] == [ObservableKind.SHA256]


def test_the_cap_only_ever_raises_clean() -> None:
    raw = email_with_body(plain="https://paypa1.com/login https://rnicrosoft.com/x")  # 60 points

    report = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert report.verdict is report.verdict_before_cap is Verdict.MALICIOUS
    assert report.cap_reason == ""


def test_urlhaus_domain_listing_adds_points_but_is_not_decisive() -> None:
    urlhaus = FakeProvider(
        name=URLHAUS,
        answers={"evil.example": Lookup(Outcome.SUSPICIOUS, "3 malicious URLs listed, 1 still online")},
    )

    report = triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[urlhaus])

    assert report.findings == [
        Finding(
            rule_id="urlhaus_domain_listed",
            points=20,
            decisive=False,
            evidence=(
                "URLhaus lists malicious URLs on domain evil[.]example:"
                " 3 malicious URLs listed, 1 still online."
            ),
        )
    ]
    assert report.verdict is Verdict.CLEAN


def test_incident_note_lists_what_was_not_checked_and_why() -> None:
    raw = email_with_body(plain="https://evil.example/invoice", attachment="notes")
    urlhaus = URLhausProvider(auth_key=None, transport=UnusedTransport())

    note = incident_note(triage(raw, DEFAULT_SETTINGS, providers=[urlhaus]))

    not_checked = note.split("Not Checked:\n")[1]
    assert not_checked.startswith("Raised from clean to suspicious: 2 URLs or attachments were Not Checked")
    assert "- URL: hxxps://evil[.]example/invoice: URLhaus: no API key\n" in not_checked
    assert "- Domain: evil[.]example: URLhaus: no API key\n" in not_checked
    assert "(notes.txt): no Provider looks this kind of Observable up yet\n" in not_checked
    assert "http" not in note


def test_providers_never_receive_recipients_subject_or_body_text() -> None:
    message = EmailMessage()
    message["From"] = "Payroll <payroll@evil.example>"
    message["To"] = "Sam Victim <sam.victim@ourcompany.example>"
    message["Cc"] = "boss@ourcompany.example"
    message["Subject"] = "Confidential bonus letter"
    message.set_content("Dear Sam, your secret bonus is ready: https://evil.example/bonus")
    message.add_attachment("letter", filename="bonus.txt")
    spy = FakeProvider(handles=ALL_KINDS)

    report = triage(message.as_bytes(), DEFAULT_SETTINGS, providers=[spy])

    received = [o.value for o in spy.received]
    assert sorted(received) == sorted(o.value for o in report.observables)  # Only attacker-side Observables.
    for private in ("ourcompany", "victim", "Sam", "bonus letter", "Confidential", "secret", "Dear"):
        assert not any(private in value for value in received), private


def test_the_core_only_ever_asks_providers_to_look_up() -> None:
    accessed: list[str] = []

    class WatchedProvider(FakeProvider):
        def __getattribute__(self, attribute: str) -> object:
            if not attribute.startswith("_"):
                accessed.append(attribute)
            return super().__getattribute__(attribute)

    triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[WatchedProvider()])

    # The core may read the Provider's name, kinds and rate limit and call lookup. Nothing
    # else, so it can never submit or scan (ADR 0001). (The other names are the fake's own state.)
    assert set(accessed) - {"received", "fail", "answers", "default"} == {
        "name", "handles", "lookups_per_minute", "lookup",
    }


# --- VirusTotal (ticket 10) ---

VT_EMAIL = email_with_body(plain="Your invoice: https://evil.example/invoice", attachment="notes", from_header=None)
VT_CLEAN = Lookup(Outcome.CLEAN, "0 of 90 engines flag it as malicious")
VIRUSTOTAL_KINDS = [ObservableKind.URL, ObservableKind.DOMAIN, ObservableKind.SHA256]


def virustotal_answering(answers: dict[ObservableKind, Lookup]) -> FakeProvider:
    """A fake VirusTotal giving `answers` for the email's Observable of each kind, and clean otherwise."""
    observables = triage(VT_EMAIL, DEFAULT_SETTINGS, providers=[]).observables
    by_kind = {o.kind: o.value for o in observables}
    return FakeProvider(
        name=VIRUSTOTAL,
        handles=ALL_KINDS,
        default=VT_CLEAN,
        answers={by_kind[kind]: lookup for kind, lookup in answers.items()},
    )


@pytest.mark.parametrize(
    ("kind", "label"),
    [(ObservableKind.URL, "URL"), (ObservableKind.SHA256, "SHA-256")],
)
def test_virustotal_at_the_decisive_engine_count_is_decisive(kind: ObservableKind, label: str) -> None:
    virustotal = virustotal_answering({kind: Lookup(Outcome.MALICIOUS, "5 of 90 engines flag it as malicious")})

    report = triage(VT_EMAIL, DEFAULT_SETTINGS, providers=[virustotal])

    assert [(f.rule_id, f.decisive) for f in report.findings] == [("known_malicious", True)]
    assert report.findings[0].evidence.startswith(f"VirusTotal reports {label} ")
    assert report.verdict is Verdict.MALICIOUS


@pytest.mark.parametrize("kind", VIRUSTOTAL_KINDS)
def test_virustotal_low_detections_add_points_but_are_not_decisive(kind: ObservableKind) -> None:
    virustotal = virustotal_answering({kind: Lookup(Outcome.SUSPICIOUS, "2 of 90 engines flag it as malicious")})

    report = triage(VT_EMAIL, DEFAULT_SETTINGS, providers=[virustotal])

    assert [(f.rule_id, f.points, f.decisive) for f in report.findings] == [
        ("virustotal_low_detections", 15, False)
    ]
    assert report.verdict is Verdict.CLEAN


def test_virustotal_low_detection_finding_names_the_observable_defanged() -> None:
    virustotal = virustotal_answering(
        {ObservableKind.URL: Lookup(Outcome.SUSPICIOUS, "2 of 90 engines flag it as malicious")}
    )

    [finding] = triage(VT_EMAIL, DEFAULT_SETTINGS, providers=[virustotal]).findings

    assert finding.evidence == (
        "VirusTotal flags URL hxxps://evil[.]example/invoice: 2 of 90 engines flag it as malicious,"
        " fewer than the 3 needed to be decisive."
    )


def test_each_observable_with_low_detections_gives_its_own_finding() -> None:
    weak = Lookup(Outcome.SUSPICIOUS, "1 of 90 engines flag it as malicious")
    virustotal = virustotal_answering({ObservableKind.URL: weak, ObservableKind.DOMAIN: weak})

    report = triage(VT_EMAIL, DEFAULT_SETTINGS, providers=[virustotal])

    assert [f.rule_id for f in report.findings] == ["virustotal_low_detections"] * 2
    assert report.score == 30
    assert report.verdict is Verdict.SUSPICIOUS


@pytest.mark.parametrize("kind", VIRUSTOTAL_KINDS)
@pytest.mark.parametrize(
    "answer",
    [VT_CLEAN, Lookup(Outcome.UNKNOWN, "never seen by VirusTotal")],
    ids=["clean", "unknown"],
)
def test_virustotal_clean_or_unknown_gives_no_finding_and_counts_as_checked(
    kind: ObservableKind, answer: Lookup
) -> None:
    report = triage(VT_EMAIL, DEFAULT_SETTINGS, providers=[virustotal_answering({kind: answer})])

    assert report.findings == []
    assert report.not_checked == []
    assert report.verdict is Verdict.CLEAN


def test_an_attachment_virustotal_answered_for_can_be_clean() -> None:
    report = triage(load("benign_attachment.eml"), DEFAULT_SETTINGS, providers=[virustotal_answering({})])

    assert report.not_checked == []
    assert report.verdict is Verdict.CLEAN


def test_a_domain_many_virustotal_engines_flag_adds_points_but_is_never_decisive() -> None:
    virustotal = virustotal_answering(
        {ObservableKind.DOMAIN: Lookup(Outcome.SUSPICIOUS, "16 of 92 engines flag it as malicious")}
    )

    report = triage(VT_EMAIL, DEFAULT_SETTINGS, providers=[virustotal])

    assert report.findings == [
        Finding(
            rule_id="virustotal_low_detections",
            points=15,
            decisive=False,
            evidence=(
                "VirusTotal flags Domain evil[.]example: 16 of 92 engines flag it as malicious."
                " A domain is never decisive on its own, because shared platforms collect detections too."
            ),
        )
    ]
    assert report.verdict is Verdict.CLEAN


# --- Lookup orchestration (ticket 11) ---

TWO_LINKS_EMAIL = email_with_body(
    plain=(
        "Pay here: https://evil.example/pay and again https://evil.example/pay\n"
        "Or here: https://evil.example/alt\n"
    ),
    attachment="notes",
    from_header=None,
)


def test_each_observable_is_looked_up_once_with_domains_first() -> None:
    provider = FakeProvider(handles=ALL_KINDS)

    triage(TWO_LINKS_EMAIL, DEFAULT_SETTINGS, providers=[provider])

    assert [(o.kind, o.value) for o in provider.received[:3]] == [
        (ObservableKind.DOMAIN, "evil.example"),
        (ObservableKind.URL, "https://evil.example/pay"),
        (ObservableKind.URL, "https://evil.example/alt"),
    ]
    assert [o.kind for o in provider.received[3:]] == [ObservableKind.SHA256]


def test_urls_over_the_lookup_cap_are_not_checked_and_the_verdict_cannot_be_clean() -> None:
    raw = email_with_body(plain="https://a.example/1 https://b.example/2 https://c.example/3", from_header=None)
    urlhaus, virustotal = FakeProvider(name="URLhaus"), FakeProvider(name="VirusTotal")

    report = triage(raw, replace(DEFAULT_SETTINGS, url_cap=2), providers=[urlhaus, virustotal])

    asked = [o.value for o in urlhaus.received if o.kind is ObservableKind.URL]
    assert asked == ["https://a.example/1", "https://b.example/2"]
    assert report.not_checked == [
        NotChecked(
            Observable(ObservableKind.URL, "https://c.example/3"),
            ["URLhaus: over lookup cap", "VirusTotal: over lookup cap"],
        )
    ]
    assert report.verdict is Verdict.SUSPICIOUS


def test_the_default_url_cap_is_10() -> None:
    raw = email_with_body(plain=" ".join(f"https://evil.example/{n}" for n in range(11)))
    provider = FakeProvider()

    report = triage(raw, DEFAULT_SETTINGS, providers=[provider])

    assert sum(o.kind is ObservableKind.URL for o in provider.received) == 10
    assert [n.observable.value for n in report.not_checked] == ["https://evil.example/10"]


class FakeClock:
    """A clock that never really waits: sleeping just moves its time on, and is recorded."""

    def __init__(self) -> None:
        self.time = 1000.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.time

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.time += seconds


ONE_DOMAIN_TWO_URLS = email_with_body(plain="https://evil.example/pay https://evil.example/alt", from_header=None)


def test_each_provider_is_paced_to_its_own_rate_limit_by_waiting() -> None:
    # With a 10% safety margin: URLhaus one every 2.2s, VirusTotal one every 16.5s.
    urlhaus = FakeProvider(name="URLhaus", lookups_per_minute=30)
    virustotal = FakeProvider(name="VirusTotal", lookups_per_minute=4)
    clock = FakeClock()

    report = triage(ONE_DOMAIN_TWO_URLS, DEFAULT_SETTINGS, providers=[urlhaus, virustotal], clock=clock)

    # Domain: both at once. URL 1: URLhaus waits 2.2s, then VirusTotal 14.3s more
    # (16.5s after its first). URL 2: URLhaus's gap has long passed; VirusTotal waits 16.5s.
    assert clock.sleeps == pytest.approx([2.2, 14.3, 16.5])
    assert report.not_checked == []


def test_a_provider_without_a_rate_limit_never_waits() -> None:
    clock = FakeClock()

    triage(ONE_DOMAIN_TWO_URLS, DEFAULT_SETTINGS, providers=[FakeProvider()], clock=clock)

    assert clock.sleeps == []


def test_a_provider_that_cannot_answer_is_not_asked_or_waited_for_again() -> None:
    unreachable = Lookup(Outcome.NOT_CHECKED, "could not reach FakeIntel (timed out)", stop_asking=True)
    provider = FakeProvider(handles=ALL_KINDS, default=unreachable, lookups_per_minute=4)
    clock = FakeClock()

    report = triage(TWO_LINKS_EMAIL, DEFAULT_SETTINGS, providers=[provider], clock=clock)

    assert len(provider.received) == 1
    assert clock.sleeps == []
    assert [n.reasons for n in report.not_checked] == [
        ["FakeIntel: could not reach FakeIntel (timed out)"]
    ] * 4


def test_progress_is_reported_for_each_lookup_and_each_wait() -> None:
    events: list[Progress] = []
    provider = FakeProvider(lookups_per_minute=4)

    triage(
        ONE_DOMAIN_TWO_URLS, DEFAULT_SETTINGS, providers=[provider],
        clock=FakeClock(), on_progress=events.append,
    )

    domain = Observable(ObservableKind.DOMAIN, "evil.example")
    url_1 = Observable(ObservableKind.URL, "https://evil.example/pay")
    url_2 = Observable(ObservableKind.URL, "https://evil.example/alt")
    # 4 a minute plus the 10% margin is one every 16.5 seconds.
    assert [type(event).__name__ for event in events] == [
        "LookupStarted", "WaitingForRateLimit", "LookupStarted", "WaitingForRateLimit", "LookupStarted",
    ]
    assert [e for e in events if isinstance(e, LookupStarted)] == [
        LookupStarted(number=1, total=3, provider="FakeIntel", observable=domain),
        LookupStarted(number=2, total=3, provider="FakeIntel", observable=url_1),
        LookupStarted(number=3, total=3, provider="FakeIntel", observable=url_2),
    ]
    waits = [(e.provider, e.seconds) for e in events if isinstance(e, WaitingForRateLimit)]
    assert [provider for provider, _ in waits] == ["FakeIntel", "FakeIntel"]
    assert [seconds for _, seconds in waits] == pytest.approx([16.5, 16.5])


def test_a_crashing_provider_is_not_asked_or_waited_for_again() -> None:
    provider = FakeProvider(handles=ALL_KINDS, fail=True, lookups_per_minute=4)
    clock = FakeClock()

    report = triage(TWO_LINKS_EMAIL, DEFAULT_SETTINGS, providers=[provider], clock=clock)

    assert len(provider.received) == 1
    assert clock.sleeps == []
    assert len(report.not_checked) == 4


def test_progress_says_when_a_provider_will_not_be_asked_again() -> None:
    events: list[Progress] = []
    provider = FakeProvider(default=Lookup(Outcome.NOT_CHECKED, "no API key", stop_asking=True))

    triage(ONE_DOMAIN_TWO_URLS, DEFAULT_SETTINGS, providers=[provider], on_progress=events.append)

    assert events == [
        LookupStarted(number=1, total=3, provider="FakeIntel", observable=Observable(ObservableKind.DOMAIN, "evil.example")),
        ProviderStopped(provider="FakeIntel", reason="no API key"),
    ]


# --- Reputation cache (ticket 14) ---


class MemoryCache:
    """A cache kept in a dict, standing in for the CLI's JSON file."""

    def __init__(self) -> None:
        self.entries: dict[str, CachedLookup] = {}

    def get(self, key: str) -> CachedLookup | None:
        return self.entries.get(key)

    def put(self, key: str, entry: CachedLookup) -> None:
        self.entries[key] = entry


def test_a_second_triage_uses_cached_answers_without_asking_or_waiting() -> None:
    cache, clock = MemoryCache(), FakeClock()
    first = FakeProvider(answers={"https://evil.example/invoice": LISTED}, lookups_per_minute=4)
    triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[first], clock=clock, cache=cache)
    clock.sleeps.clear()

    second = FakeProvider(lookups_per_minute=4)
    report = triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[second], clock=clock, cache=cache)

    assert second.received == []
    assert clock.sleeps == []
    assert [(r.observable.value, r.outcome, r.from_cache) for r in report.lookups] == [
        ("evil.example", Outcome.UNKNOWN, True),
        ("https://evil.example/invoice", Outcome.MALICIOUS, True),
    ]
    assert report.verdict is Verdict.MALICIOUS


DAY = 24 * 60 * 60


def asked_again_after(answer: Lookup, seconds: float, settings: Settings = DEFAULT_SETTINGS) -> bool:
    """Cache `answer` for LINK_EMAIL's Observables, wait `seconds`, triage again: was the Provider asked?"""
    cache, clock = MemoryCache(), FakeClock()
    triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[FakeProvider(default=answer)], clock=clock, cache=cache)
    clock.time += seconds
    second = FakeProvider(default=answer)
    triage(LINK_EMAIL, settings, providers=[second], clock=clock, cache=cache)
    return len(second.received) > 0


@pytest.mark.parametrize(
    ("answer", "lifetime"),
    [
        pytest.param(LISTED, 7 * DAY, id="malicious: 7 days"),
        pytest.param(Lookup(Outcome.SUSPICIOUS, "2 of 90 engines flag it as malicious"), DAY, id="suspicious: 24 hours"),
        pytest.param(Lookup(Outcome.CLEAN, "0 of 90 engines flag it as malicious"), DAY, id="clean: 24 hours"),
        pytest.param(Lookup(Outcome.UNKNOWN, "not listed"), DAY, id="unknown: 24 hours"),
    ],
)
def test_cached_answers_are_used_until_they_expire(answer: Lookup, lifetime: int) -> None:
    assert not asked_again_after(answer, lifetime - 1)
    assert asked_again_after(answer, lifetime)


def test_not_checked_is_never_cached() -> None:
    cache = MemoryCache()

    triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[FakeProvider(fail=True)], cache=cache)

    assert cache.entries == {}
    assert asked_again_after(Lookup(Outcome.NOT_CHECKED, "VirusTotal answered with HTTP 500"), 0)


def test_changing_the_decisive_engine_count_ignores_old_cached_answers() -> None:
    stricter = replace(DEFAULT_SETTINGS, decisive_engines=5)

    assert asked_again_after(LISTED, 0, settings=stricter)


def test_the_report_says_when_a_cached_answer_was_fetched() -> None:
    cache, clock = MemoryCache(), FakeClock()
    clock.time = 1791397185.0  # 2026-10-07 18:19:45 UTC
    triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[FakeProvider()], clock=clock, cache=cache)
    clock.time += 3 * 60 * 60

    report = triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[FakeProvider()], clock=clock, cache=cache)

    assert [r.cached_at for r in report.lookups] == ["2026-10-07T18:19:45Z"] * 2


def test_progress_marks_answers_taken_from_the_cache() -> None:
    cache = MemoryCache()
    triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[FakeProvider()], cache=cache)
    events: list[Progress] = []

    triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[FakeProvider()], cache=cache, on_progress=events.append)

    assert events == [
        LookupStarted(1, 2, "FakeIntel", Observable(ObservableKind.DOMAIN, "evil.example"), from_cache=True),
        LookupStarted(2, 2, "FakeIntel", Observable(ObservableKind.URL, "https://evil.example/invoice"), from_cache=True),
    ]


def test_a_cached_answer_from_the_future_is_not_trusted() -> None:
    # Stored while the computer's clock was a day fast: it could outlive its lifetime.
    cache, clock = MemoryCache(), FakeClock()
    clock.time += DAY
    triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[FakeProvider()], clock=clock, cache=cache)
    clock.time -= DAY
    second = FakeProvider()

    triage(LINK_EMAIL, DEFAULT_SETTINGS, providers=[second], clock=clock, cache=cache)

    assert len(second.received) == 2


# --- RDAP: newly registered domains (ticket 13) ---

OCT_7_2026 = 1791331200.0  # 2026-10-07 00:00:00 UTC


def registered_on(date: str) -> Lookup:
    """What the RDAP Provider says about a domain registered on `date`."""
    return Lookup(Outcome.UNKNOWN, f"registered {date}", {"registered": f"{date}T00:00:00Z"})


def rdap_answering(answers: dict[str, Lookup]) -> FakeProvider:
    return FakeProvider(
        name="RDAP",
        handles=frozenset({ObservableKind.DOMAIN, ObservableKind.SENDER_DOMAIN}),
        default=registered_on("2001-01-01"),
        answers=answers,
    )


def triage_on_oct_7(raw: bytes, *providers: FakeProvider, settings: Settings = DEFAULT_SETTINGS) -> TriageReport:
    """Triage `raw` with the clock set to 2026-10-07 00:00 UTC."""
    clock = FakeClock()
    clock.time = OCT_7_2026
    return triage(raw, settings, providers=list(providers), clock=clock)


def test_a_newly_registered_link_domain_gives_a_finding() -> None:
    report = triage_on_oct_7(LINK_EMAIL, rdap_answering({"evil.example": registered_on("2026-09-30")}))

    assert report.findings == [
        Finding(
            rule_id="newly_registered_domain",
            points=20,
            decisive=False,
            evidence="Link domain evil[.]example was registered on 2026-09-30, 7 days ago (under 30 days).",
        )
    ]


@pytest.mark.parametrize(
    ("registered", "fires"),
    [
        pytest.param("2026-09-08", True, id="29 days old"),
        pytest.param("2026-09-07", False, id="exactly 30 days old"),
        pytest.param("1997-09-15", False, id="decades old"),
    ],
)
def test_only_domains_younger_than_the_limit_give_a_finding(registered: str, fires: bool) -> None:
    report = triage_on_oct_7(LINK_EMAIL, rdap_answering({"evil.example": registered_on(registered)}))

    assert [f.rule_id for f in report.findings] == (["newly_registered_domain"] if fires else [])


def test_unknown_age_never_gives_a_finding_but_is_in_the_report() -> None:
    unknown = Lookup(Outcome.UNKNOWN, "unknown age: .de has no RDAP service", {"registered": None})

    report = triage_on_oct_7(LINK_EMAIL, rdap_answering({"evil.example": unknown}))

    assert report.findings == []
    assert [(r.observable.value, r.detail) for r in report.lookups if r.observable.value == "evil.example"] == [
        ("evil.example", "unknown age: .de has no RDAP service")
    ]


def test_a_newly_registered_sender_domain_gives_a_finding_saying_so() -> None:
    raw = email_with_body(plain="Hello.", from_header="Billing <billing@fresh.example>")

    report = triage_on_oct_7(raw, rdap_answering({"fresh.example": registered_on("2026-10-06")}))

    assert [f.evidence for f in report.findings] == [
        "Sender domain fresh[.]example was registered on 2026-10-06, 1 day ago (under 30 days)."
    ]


def test_a_new_domain_used_as_sender_and_link_gives_one_finding() -> None:
    raw = email_with_body(plain="https://fresh.example/pay", from_header="Billing <billing@fresh.example>")

    report = triage_on_oct_7(raw, rdap_answering({"fresh.example": registered_on("2026-10-01")}))

    assert [f.evidence for f in report.findings] == [
        "Sender and link domain fresh[.]example was registered on 2026-10-01, 6 days ago (under 30 days)."
    ]


def test_the_new_domain_limit_is_a_setting() -> None:
    provider = rdap_answering({"evil.example": registered_on("2026-08-08")})  # 60 days before 7 October

    report = triage_on_oct_7(LINK_EMAIL, provider, settings=replace(DEFAULT_SETTINGS, new_domain_days=90))

    assert [f.evidence for f in report.findings] == [
        "Link domain evil[.]example was registered on 2026-08-08, 60 days ago (under 90 days)."
    ]


def test_a_registration_date_in_the_future_gives_no_finding() -> None:
    report = triage_on_oct_7(LINK_EMAIL, rdap_answering({"evil.example": registered_on("2026-10-10")}))

    assert report.findings == []


def test_a_sender_address_at_an_ip_address_gives_no_sender_domain() -> None:
    raw = email_with_body(plain="Hello.", from_header="someone@[192.0.2.7]")

    report = triage(raw, DEFAULT_SETTINGS, providers=[])

    assert [o.kind for o in report.observables] == []
