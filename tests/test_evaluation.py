"""Tests at the evaluation command's seam: `phishing_triage.evaluation.main`.

The command runs the core over a samples folder (phish/ and ham/ subfolders)
with no Providers, and prints how many of each got each Verdict. The fixture
folder holds hand-made emails whose Verdicts were worked out by hand:

    phish/  delivery_shortener (malicious), paypal_lookalike (malicious),
            payroll_reply_to (suspicious), invoice_link (clean: a missed phish),
            not_an_email (unparseable)
    ham/    monthly_update (clean), meeting_link (clean, but has a URL that
            would be Not Checked), mailing_list_reply_to (suspicious: a false positive)
"""

import socket
from pathlib import Path

import pytest

from phishing_triage.core import Finding, Lookup, Observable, ObservableKind, Outcome, RuleInput, Settings
from phishing_triage.evaluation import main

SAMPLES = Path(__file__).parent / "fixtures" / "evaluation"


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Evaluation is offline: any attempt to use the network fails the test."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def row(output: str, label: str) -> list[str]:
    """The words of the counts table's row for `label` (phish or ham)."""
    for line in output.splitlines():
        words = line.split()
        if words[:1] == [label] and all(word.isdigit() for word in words[1:]):
            return words
    raise AssertionError(f"no {label} row in:\n{output}")


def test_prints_verdict_counts_for_phish_and_for_ham(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([str(SAMPLES)])

    output = capsys.readouterr().out
    assert exit_code == 0
    header = next(line.split() for line in output.splitlines() if line.split()[:1] == ["Label"])
    assert header == ["Label", "clean", "suspicious", "malicious", "unparseable", "error", "total"]
    assert row(output, "phish") == ["phish", "1", "1", "2", "1", "0", "5"]
    assert row(output, "ham") == ["ham", "2", "1", "0", "0", "0", "3"]


def test_prints_false_positive_and_missed_phish_rates(capsys: pytest.CaptureFixture[str]) -> None:
    # Unparseable samples have no Verdict, so they are left out of both rates.
    main([str(SAMPLES)])

    output = capsys.readouterr().out
    assert "False-positive rate (ham not clean): 33.3% (1 of 3 ham)" in output
    assert "Missed-phish rate (phish clean): 25.0% (1 of 4 phish)" in output


def listed(output: str, sample: str) -> str:
    """The --list line for one sample, found by its file name."""
    lines = [line for line in output.splitlines() if f"/{sample} " in line or line.endswith(f"/{sample}")]
    assert len(lines) == 1, f"expected one line for {sample} in:\n{output}"
    return lines[0]


def test_list_shows_each_samples_verdict_score_and_findings(capsys: pytest.CaptureFixture[str]) -> None:
    main([str(SAMPLES), "--list"])

    output = capsys.readouterr().out
    false_positive = listed(output, "ham/mailing_list_reply_to.eml")
    assert false_positive.split()[:3] == ["ham", "suspicious", "40"]
    assert "dmarc_fail" in false_positive and "reply_to_mismatch" in false_positive
    assert listed(output, "phish/invoice_link.eml").split()[:3] == ["phish", "clean", "0"]
    # The counts are still printed after the list.
    assert row(output, "ham") == ["ham", "2", "1", "0", "0", "0", "3"]


def test_list_shows_why_a_sample_was_unparseable(capsys: pytest.CaptureFixture[str]) -> None:
    main([str(SAMPLES), "--list"])

    line = listed(capsys.readouterr().out, "phish/not_an_email.eml")
    assert line.split()[:2] == ["phish", "unparseable"]
    assert "No standard email headers were found." in line


def test_without_list_no_sample_is_listed(capsys: pytest.CaptureFixture[str]) -> None:
    main([str(SAMPLES)])

    assert "invoice_link.eml" not in capsys.readouterr().out


def test_counts_the_verdict_from_before_the_clean_requires_evidence_cap(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # With no Providers, meeting_link's URL is Not Checked, so a normal Triage
    # would raise it from clean to suspicious. The rules alone call it clean.
    main([str(SAMPLES), "--list"])

    assert listed(capsys.readouterr().out, "ham/meeting_link.eml").split()[:2] == ["ham", "clean"]


def test_a_missing_samples_folder_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([str(tmp_path / "nowhere")])

    assert exit_code == 3
    assert "nowhere" in capsys.readouterr().err


def test_a_missing_label_folder_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "phish").mkdir()

    exit_code = main([str(tmp_path)])

    assert exit_code == 3
    assert "ham" in capsys.readouterr().err


def test_bad_usage_exits_with_the_clis_usage_error_code(capsys: pytest.CaptureFixture[str]) -> None:
    # argparse would exit with 2, which from the main CLI means "malicious".
    # Both commands use 5 for bad usage, so a script can't confuse the two.
    with pytest.raises(SystemExit) as exit_info:
        main([str(SAMPLES), "--no-such-option"])

    assert exit_info.value.code == 5
    assert "--no-such-option" in capsys.readouterr().err


def edited_settings(tmp_path: Path, old: str, new: str) -> str:
    """A copy of the shipped settings with one line changed, as the maintainer tuning weights would make."""
    shipped = (Path(__file__).parent.parent / "src" / "phishing_triage" / "settings.toml").read_text()
    assert old in shipped
    path = tmp_path / "tuned.toml"
    path.write_text(shipped.replace(old, new))
    return str(path)


def test_uses_an_edited_settings_file_to_tune_the_weights(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Without Reply-To mismatch points, the mailing list (DMARC fail, 20) is clean,
    # but so is the payroll phish (SPF fail, 10).
    settings = edited_settings(tmp_path, "reply_to_mismatch = 20", "reply_to_mismatch = 0")

    main([str(SAMPLES), "--settings", settings])

    output = capsys.readouterr().out
    assert row(output, "ham") == ["ham", "3", "0", "0", "0", "0", "3"]
    assert row(output, "phish") == ["phish", "2", "0", "2", "1", "0", "5"]


def test_an_invalid_settings_file_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    settings = edited_settings(tmp_path, "reply_to_mismatch = 20", 'reply_to_mismatch = "lots"')

    exit_code = main([str(SAMPLES), "--settings", settings])

    assert exit_code == 7
    assert "reply_to_mismatch" in capsys.readouterr().err


def samples_folder(tmp_path: Path) -> Path:
    """A fresh samples folder holding one phish and one ham from the fixtures."""
    for label, name in (("phish", "payroll_reply_to.eml"), ("ham", "monthly_update.eml")):
        (tmp_path / label).mkdir(parents=True)
        (tmp_path / label / name).write_bytes((SAMPLES / label / name).read_bytes())
    return tmp_path


def test_an_unreadable_sample_is_counted_as_an_error_and_skipped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A file that can't be read says nothing about the email in it, so it isn't unparseable.
    samples = samples_folder(tmp_path)
    locked = samples / "ham" / "locked.eml"
    locked.write_bytes((SAMPLES / "ham" / "monthly_update.eml").read_bytes())
    locked.chmod(0)

    exit_code = main([str(samples), "--list"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert row(output, "ham") == ["ham", "1", "0", "0", "0", "1", "2"]
    line = listed(output, "ham/locked.eml")
    assert line.split()[:2] == ["ham", "error"]
    assert "could not be read" in line


def test_a_sample_the_core_fails_on_is_counted_as_an_error_and_skipped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Real datasets hold odd emails. One that trips up the core mustn't stop a run
    # over thousands, but it is counted apart from unparseable samples, so a bug
    # in a rule can't hide among emails that simply aren't emails.
    def broken_rule(rule_input: RuleInput, settings: Settings) -> list[Finding]:
        if "bank details" in str(rule_input.message["Subject"]):
            raise ValueError("odd header")
        return []

    exit_code = main([str(samples_folder(tmp_path)), "--list"], rules=[broken_rule])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert row(output, "phish") == ["phish", "0", "0", "0", "0", "1", "1"]
    assert row(output, "ham") == ["ham", "1", "0", "0", "0", "0", "1"]
    line = listed(output, "phish/payroll_reply_to.eml")
    assert line.split()[:2] == ["phish", "error"]
    assert "the core failed (ValueError: odd header)" in line
    # Like unparseable samples, errors have no Verdict, so they are left out of the rates.
    assert "Missed-phish rate (phish clean): no phish samples were triaged" in output


def test_hidden_files_such_as_ds_store_are_not_samples(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    samples = samples_folder(tmp_path)
    (samples / "ham" / ".DS_Store").write_bytes(b"\x00\x00\x00\x01Bud1")

    main([str(samples)])

    assert row(capsys.readouterr().out, "ham") == ["ham", "1", "0", "0", "0", "0", "1"]


def test_says_it_is_offline_and_counts_verdicts_before_the_cap(capsys: pytest.CaptureFixture[str]) -> None:
    main([str(SAMPLES)])

    output = capsys.readouterr().out
    assert "no Providers" in output
    assert "before the clean-requires-evidence cap" in output


def test_says_how_many_samples_it_is_triaging_on_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    # A run over the real datasets takes minutes, so it says up front how big the job is.
    main([str(SAMPLES)])

    assert "Triaging 8 samples" in capsys.readouterr().err


def test_evaluates_the_samples_folder_in_the_current_folder_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    samples_folder(tmp_path / "samples")
    monkeypatch.chdir(tmp_path)

    exit_code = main([])

    assert exit_code == 0
    assert row(capsys.readouterr().out, "phish") == ["phish", "0", "1", "0", "0", "0", "1"]


# Live evaluation: the same command with --live asks Providers. These tests
# pass fake Providers only, and the network stays blocked (see no_network).


class ListsEveryURL:
    """A fake Provider that reports every URL as malicious."""

    name = "FakeIntel"
    handles = frozenset({ObservableKind.URL})
    lookups_per_minute = None

    def __init__(self) -> None:
        self.asked: list[Observable] = []

    def lookup(self, observable: Observable) -> Lookup:
        self.asked.append(observable)
        return Lookup(Outcome.MALICIOUS, "listed for testing")


@pytest.fixture
def in_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Work in an empty folder, so the live evaluation's cache file lands somewhere disposable."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_live_mode_asks_the_providers_so_lookups_change_the_verdicts(
    in_tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Offline, invoice_link is a missed phish and meeting_link is clean. A
    # Provider listing their URLs makes both malicious.
    exit_code = main([str(SAMPLES), "--live"], providers=[ListsEveryURL()])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert row(output, "phish") == ["phish", "0", "1", "3", "1", "0", "5"]
    assert row(output, "ham") == ["ham", "1", "1", "1", "0", "0", "3"]
    assert "Live evaluation" in output


class KnowsNothingButURLs:
    """A fake Provider that looks up every kind of Observable except URLs, and knows none of them."""

    name = "FakeIntel"
    handles = frozenset(ObservableKind) - {ObservableKind.URL}
    lookups_per_minute = None

    def lookup(self, observable: Observable) -> Lookup:
        return Lookup(Outcome.UNKNOWN, "not listed")


def test_live_mode_counts_the_final_verdict_after_the_cap(
    in_tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Nobody looks meeting_link's URL up, so it is Not Checked, and the cap
    # raises the ham from clean to suspicious, as an analyst would see it.
    main([str(SAMPLES), "--live", "--list"], providers=[KnowsNothingButURLs()])

    output = capsys.readouterr().out
    assert listed(output, "ham/meeting_link.eml").split()[:2] == ["ham", "suspicious"]
    assert row(output, "ham") == ["ham", "1", "2", "0", "0", "0", "3"]
    assert "after the clean-requires-evidence cap" in output


def test_live_mode_says_how_many_observables_were_not_checked(
    in_tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Every other Observable got an answer (Unknown), so only the four URLs
    # (three in phish, one in ham) were Not Checked.
    main([str(SAMPLES), "--live"], providers=[KnowsNothingButURLs()])

    assert "Observables Not Checked: 4 (3 in phish, 1 in ham)" in capsys.readouterr().out
