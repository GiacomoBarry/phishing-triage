"""Tests at Seam 1: the core entry point, `triage()`."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from phishing_triage.core import (
    Settings,
    UnparseableEmailError,
    Verdict,
    incident_note,
    triage,
)

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_parseable_email_with_no_rules_gets_a_clean_verdict() -> None:
    report = triage(load("clean_newsletter.eml"), Settings(), providers=[])

    assert report.from_address == "news@example.org"
    assert report.display_name == "Example Newsletter"
    assert report.subject == "Your October update"
    assert report.score == 0
    assert report.verdict is Verdict.CLEAN


def test_report_carries_metadata_for_later_phases() -> None:
    before = datetime.now(UTC)
    report = triage(load("clean_newsletter.eml"), Settings(), providers=[])
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

    first = triage(raw, Settings(), providers=[])
    second = triage(raw, Settings(), providers=[])

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
        triage(raw, Settings(), providers=[])


def test_missing_from_header_is_a_warning_not_an_error() -> None:
    raw = b"Subject: Invoice attached\r\n\r\nPlease see attached.\r\n"

    report = triage(raw, Settings(), providers=[])

    assert report.from_address == ""
    assert report.display_name == ""
    assert report.subject == "Invoice attached"
    assert report.warnings == ["The email has no From address."]


def test_incident_note_opens_with_a_one_line_summary() -> None:
    report = triage(load("clean_newsletter.eml"), Settings(), providers=[])

    note = incident_note(report)

    assert note.splitlines()[0] == (
        "Verdict: CLEAN | Score: 0/100 | Sender: news@example.org"
        " | Subject: Your October update"
    )
