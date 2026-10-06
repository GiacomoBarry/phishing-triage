"""Tests at Seam 2: the CLI.

These check only what the CLI adds on top of the core: exit codes, output
modes, the saved Triage Report and error handling. Rule logic is tested at
the core seam, not here.
"""

import json
from pathlib import Path

import pytest

from phishing_triage.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN_EMAIL = str(FIXTURES / "clean_newsletter.eml")
REPLY_TO_EMAIL = str(FIXTURES / "reply_to_mismatch.eml")


def write_settings(tmp_path: Path, reply_to_points: int) -> str:
    """Write an edited settings file, as an analyst tuning the tool would."""
    path = tmp_path / "my-settings.toml"
    path.write_text(
        "[verdict]\n"
        "suspicious_from = 30\n"
        "malicious_from = 60\n"
        "[points]\n"
        f"reply_to_mismatch = {reply_to_points}\n"
    )
    return str(path)


@pytest.fixture(autouse=True)
def work_in_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run each test from an empty folder so saved reports land somewhere disposable."""
    monkeypatch.chdir(tmp_path)


def saved_reports(tmp_path: Path) -> list[Path]:
    return sorted((tmp_path / "reports").glob("*.json"))


def test_clean_email_prints_readable_view_and_exits_0(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main([CLEAN_EMAIL])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Example Newsletter <news@example.org>" in out
    assert "Your October update" in out
    assert "CLEAN" in out
    assert (
        "Verdict: CLEAN | Score: 0/100 | Sender: news@example.org"
        " | Subject: Your October update"
    ) in out


def test_triage_report_is_saved_as_json_named_by_report_id(tmp_path: Path) -> None:
    main([CLEAN_EMAIL])

    [report_file] = saved_reports(tmp_path)
    saved = json.loads(report_file.read_text())
    assert report_file.name == f"{saved['report_id']}.json"
    assert saved["format_version"] == 1
    assert saved["verdict"] == "clean"
    assert saved["from_address"] == "news@example.org"


def test_json_option_prints_the_saved_triage_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main([CLEAN_EMAIL, "--json"])

    printed = json.loads(capsys.readouterr().out)
    [report_file] = saved_reports(tmp_path)
    assert exit_code == 0
    assert printed == json.loads(report_file.read_text())


def test_unreadable_file_exits_3_with_a_clear_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["does-not-exist.eml"])

    assert exit_code == 3
    assert "could not read does-not-exist.eml" in capsys.readouterr().err
    assert saved_reports(tmp_path) == []


def test_unparseable_email_exits_4_with_a_clear_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    not_an_email = tmp_path / "notes.eml"
    not_an_email.write_text("Just some notes.\nNot an email.\n")

    exit_code = main([str(not_an_email)])

    assert exit_code == 4
    assert "is not a parseable email" in capsys.readouterr().err
    assert saved_reports(tmp_path) == []


def test_bad_usage_exits_5_not_2_which_means_malicious() -> None:
    with pytest.raises(SystemExit) as exit_info:
        main([])

    assert exit_info.value.code == 5


def test_failing_to_save_the_report_is_an_error_not_a_verdict(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "reports").write_text("a file where the folder should be")

    exit_code = main([CLEAN_EMAIL, "--json"])

    captured = capsys.readouterr()
    assert exit_code == 6
    assert "could not save the Triage Report" in captured.err
    assert json.loads(captured.out)["verdict"] == "clean"


def test_readable_view_shows_findings_with_evidence(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main([REPLY_TO_EMAIL])

    # Only that Findings are shown: their wording is tested at the core seam.
    out = capsys.readouterr().out
    assert "Findings:\n  - Reply-To domain" in out
    assert "Key Findings:\n- Reply-To domain" in out


@pytest.mark.parametrize(
    ("reply_to_points", "exit_code"),
    [
        pytest.param(30, 1, id="suspicious exits 1"),
        pytest.param(60, 2, id="malicious exits 2"),
    ],
)
def test_settings_option_loads_an_edited_settings_file(
    tmp_path: Path, reply_to_points: int, exit_code: int
) -> None:
    settings_path = write_settings(tmp_path, reply_to_points)

    assert main([REPLY_TO_EMAIL, "--settings", settings_path]) == exit_code


VALID_SETTINGS = (
    "[verdict]\nsuspicious_from = 30\nmalicious_from = 60\n"
    "[points]\nreply_to_mismatch = 20\n"
)


@pytest.mark.parametrize(
    ("settings_text", "expected_error"),
    [
        pytest.param(None, "could not be read", id="missing file"),
        pytest.param("[points\n", "not valid TOML", id="invalid TOML"),
        pytest.param(
            VALID_SETTINGS.replace("reply_to_mismatch = 20\n", ""),
            "missing points.reply_to_mismatch",
            id="missing key",
        ),
        pytest.param(
            VALID_SETTINGS + "reply_to_mismach = 5\n",
            "unknown setting points.reply_to_mismach",
            id="misspelt key",
        ),
        pytest.param(
            VALID_SETTINGS.replace("= 20", '= "twenty"'),
            "points.reply_to_mismatch must be a whole number",
            id="not a number",
        ),
        pytest.param(
            VALID_SETTINGS.replace("suspicious_from = 30", "suspicious_from = 70"),
            "suspicious_from must be lower than verdict.malicious_from",
            id="thresholds out of order",
        ),
        pytest.param(
            VALID_SETTINGS.replace("= 20", "= -5"),
            "points.reply_to_mismatch must not be negative",
            id="negative points",
        ),
        pytest.param(
            VALID_SETTINGS.replace("suspicious_from = 30", "suspicious_from = 0"),
            "verdict.suspicious_from must be at least 1",
            id="nothing could be clean",
        ),
    ],
)
def test_broken_settings_file_exits_7_with_a_clear_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    settings_text: str | None,
    expected_error: str,
) -> None:
    settings_path = tmp_path / "broken.toml"
    if settings_text is not None:
        settings_path.write_text(settings_text)

    exit_code = main([CLEAN_EMAIL, "--settings", str(settings_path)])

    err = capsys.readouterr().err
    assert exit_code == 7
    assert "Error: settings file" in err
    assert expected_error in err
    assert saved_reports(tmp_path) == []
