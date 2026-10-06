"""Tests at Seam 1: the core entry point, `triage()`."""

from dataclasses import replace
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from uuid import UUID

import pytest

from phishing_triage.config import load_settings
from phishing_triage.core import (
    Finding,
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
    return replace(DEFAULT_SETTINGS, points={"reply_to_mismatch": points})


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


def always_decisive(message: EmailMessage, settings: Settings) -> list[Finding]:
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


def twenty_points(message: EmailMessage, settings: Settings) -> list[Finding]:
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
