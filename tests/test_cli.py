"""Tests at Seam 2: the CLI.

These check only what the CLI adds on top of the core: exit codes, output
modes, the saved Triage Report and error handling. Rule logic is tested at
the core seam, not here.
"""

import json
import socket
from pathlib import Path

import pytest

from phishing_triage.cli import main
from phishing_triage.core import Lookup, Observable, ObservableKind, Outcome

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN_EMAIL = str(FIXTURES / "clean_newsletter.eml")
REPLY_TO_EMAIL = str(FIXTURES / "reply_to_mismatch.eml")


# A complete, valid settings file, as an analyst's edited copy might look.
VALID_SETTINGS = (
    "[verdict]\nsuspicious_from = 30\nmalicious_from = 60\n"
    "[points]\nreply_to_mismatch = 20\n"
    "display_name_impersonation = 25\nlookalike_domain = 30\nurl_shortener = 10\n"
    "urgency_language = 10\nrisky_attachment = 25\nurlhaus_domain_listed = 20\nvirustotal_low_detections = 15\n"
    "newly_registered_domain = 20\ndmarc_fail = 20\nspf_fail = 10\ndkim_fail = 10\n"
    "abuseipdb_high_confidence = 15\n"
    '[brands]\n"PayPal" = ["paypal.com"]\n'
    '[shorteners]\ndomains = ["bit.ly"]\n'
    '[urgency]\nphrases = ["final notice"]\n'
    '[attachments]\nrisky_extensions = ["exe", ".js"]\n'
    "[virustotal]\ndecisive_engines = 3\n"
    "[lookups]\nurl_cap = 10\n"
    "[rdap]\nnew_domain_days = 30\n"
    '[received]\ntrusted_relays = ["MX.Example.com."]\n'
    "[abuseipdb]\nconfidence_threshold = 75\n"
)


def write_settings(tmp_path: Path, reply_to_points: int) -> str:
    """Write an edited settings file, as an analyst tuning the tool would."""
    path = tmp_path / "my-settings.toml"
    path.write_text(
        VALID_SETTINGS.replace("reply_to_mismatch = 20", f"reply_to_mismatch = {reply_to_points}")
    )
    return str(path)


@pytest.fixture(autouse=True)
def work_in_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run each test from an empty folder so saved reports land somewhere disposable.

    The empty folder also has no .env, and API keys are removed from the
    environment, so the real Providers answer Not Checked ("no API key").
    The network is blocked too, so a test can never make a real lookup.
    """
    monkeypatch.chdir(tmp_path)
    for name in ("URLHAUS_AUTH_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


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
            VALID_SETTINGS.replace("[brands]", "reply_to_mismach = 5\n[brands]"),
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
        pytest.param(
            VALID_SETTINGS.split("[brands]")[0],
            "missing section [brands]",
            id="missing brands section",
        ),
        pytest.param(
            VALID_SETTINGS.replace('["paypal.com"]', '"paypal.com"'),
            'brands."PayPal" must be a list of one or more domains',
            id="brand domains not a list",
        ),
        pytest.param(
            VALID_SETTINGS.replace('["paypal.com"]', "[]"),
            'brands."PayPal" must be a list of one or more domains',
            id="brand with no domains",
        ),
        pytest.param(
            VALID_SETTINGS.replace('["paypal.com"]', '["support@paypal.com"]'),
            'brands."PayPal" must be a list of one or more domains',
            id="email address instead of a domain",
        ),
        pytest.param(
            VALID_SETTINGS.replace('domains = ["bit.ly"]', 'domains = "bit.ly"'),
            'shorteners.domains must be a list of domains, like ["example.com"]',
            id="shortener domains not a list",
        ),
        pytest.param(
            VALID_SETTINGS.replace('domains = ["bit.ly"]', 'domains = ["bitly"]'),
            "shorteners.domains must be a list of domains",
            id="shortener without a dot",
        ),
        pytest.param(
            VALID_SETTINGS.replace('phrases = ["final notice"]', 'phrases = "final notice"'),
            'urgency.phrases must be a list of phrases, like ["verify your account"]',
            id="phrases not a list",
        ),
        pytest.param(
            VALID_SETTINGS.replace('phrases = ["final notice"]', 'phrases = ["final notice", "  "]'),
            "urgency.phrases must be a list of phrases",
            id="blank phrase",
        ),
        pytest.param(
            VALID_SETTINGS.replace('["exe", ".js"]', '["exe", "pdf.exe"]'),
            'attachments.risky_extensions must be a list of file extensions, like ["exe"]',
            id="extension with a dot inside",
        ),
        pytest.param(
            VALID_SETTINGS.replace('["exe", ".js"]', '["exe", 7]'),
            "attachments.risky_extensions must be a list of file extensions",
            id="extension not text",
        ),
        pytest.param(
            VALID_SETTINGS.replace("decisive_engines = 3", "decisive_engines = 0"),
            "virustotal.decisive_engines must be at least 1",
            id="every lookup would be decisive",
        ),
        pytest.param(
            VALID_SETTINGS.split("[virustotal]")[0],
            "missing section [virustotal]",
            id="missing virustotal section",
        ),
        pytest.param(
            VALID_SETTINGS.replace("url_cap = 10", "url_cap = -1"),
            "lookups.url_cap must not be negative",
            id="negative url cap",
        ),
        pytest.param(
            VALID_SETTINGS.replace('["MX.Example.com."]', '"mx.example.com"'),
            'received.trusted_relays must be a list of mail server names, like ["mx.example.com"]',
            id="trusted relays not a list",
        ),
        pytest.param(
            VALID_SETTINGS.replace("confidence_threshold = 75", "confidence_threshold = 101"),
            "abuseipdb.confidence_threshold must be from 1 to 100 (a percentage)",
            id="threshold over 100%",
        ),
        pytest.param(
            VALID_SETTINGS.replace("confidence_threshold = 75", "confidence_threshold = 0"),
            "abuseipdb.confidence_threshold must be from 1 to 100",
            id="every reported IP would count",
        ),
        pytest.param(
            VALID_SETTINGS.split("[received]")[0],
            "missing section [received]",
            id="missing received section",
        ),
        pytest.param(
            VALID_SETTINGS.replace("new_domain_days = 30", "new_domain_days = -1"),
            "rdap.new_domain_days must not be negative",
            id="negative new-domain limit",
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


def test_readable_view_has_no_clickable_urls_but_json_keeps_them(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    email_path = tmp_path / "links.eml"
    email_path.write_text(
        "From: alerts@example.org\nSubject: Links\n\nhttps://bit.ly/abc https://paypa1.com/login\n"
    )

    main([str(email_path)])
    readable = capsys.readouterr().out
    main([str(email_path), "--json"])
    report = json.loads(capsys.readouterr().out)

    assert "http" not in readable
    assert "hxxps://paypa1[.]com/login" in readable
    assert {"kind": "url", "value": "https://paypa1.com/login"} in report["observables"]


def test_readable_view_lists_attachments_with_all_three_hashes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main([str(FIXTURES / "benign_attachment.eml")])

    out = capsys.readouterr().out
    assert "  - agenda.txt (text/plain, 37 bytes)" in out
    assert "SHA-256: 56466756b631879f95cb959987c9d36c3581d1f12d37914d50e73f5d7d99ceff" in out
    assert "MD5:     21ef88c005f99434769f4cc4ca2de563" in out
    assert "SHA-1:   0302994af3ee7c69191e3897ebae59a306519baa" in out


class ListsEverything:
    """A fake Provider that reports every URL as malicious."""

    name = "FakeIntel"
    handles = frozenset({ObservableKind.URL})
    lookups_per_minute = None

    def lookup(self, observable: Observable) -> Lookup:
        return Lookup(Outcome.MALICIOUS, "listed for testing")


def test_fake_providers_can_be_passed_in_and_drive_the_exit_code(tmp_path: Path) -> None:
    email_path = tmp_path / "link.eml"
    email_path.write_text("From: a@example.org\nSubject: Hi\n\nhttps://evil.example/x\n")

    assert main([str(email_path)], providers=[ListsEverything()]) == 2


def test_without_api_keys_links_are_not_checked_so_the_email_cannot_be_clean(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    email_path = tmp_path / "link.eml"
    email_path.write_text("From: a@example.org\nSubject: Hi\n\nhttps://evil.example/x\n")

    exit_code = main([str(email_path)])

    out = capsys.readouterr().out
    assert exit_code == 1
    assert "Capped:   Raised from clean to suspicious" in out
    assert "URLhaus: URL hxxps://evil[.]example/x -> not checked (no API key)" in out
    assert "VirusTotal: URL hxxps://evil[.]example/x -> not checked (no API key)" in out
    # RDAP needs no key, but the tests block the network, so it couldn't be reached.
    assert "RDAP: Domain evil[.]example -> not checked" in out


class QuickFakeProvider:
    """A fake Provider allowing 60,000 lookups a minute, so it waits only about 1ms between them."""

    name = "FakeIntel"
    handles = frozenset({ObservableKind.URL, ObservableKind.DOMAIN})
    lookups_per_minute = 60_000

    def lookup(self, observable: Observable) -> Lookup:
        return Lookup(Outcome.UNKNOWN, "not listed")


def test_progress_goes_to_stderr_defanged_and_json_output_stays_clean(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    email_path = tmp_path / "link.eml"
    email_path.write_text("From: a@example.org\nSubject: Hi\n\nhttps://evil.example/x\n")

    main([str(email_path), "--json"], providers=[QuickFakeProvider()])

    captured = capsys.readouterr()
    assert json.loads(captured.out)["verdict"] == "clean"
    assert "Looking up 1 of 2: FakeIntel, Domain evil[.]example\n" in captured.err
    assert "for FakeIntel's rate limit...\n" in captured.err
    assert "Looking up 2 of 2: FakeIntel, URL hxxps://evil[.]example/x\n" in captured.err
    assert "evil.example" not in captured.err


class CountingProvider:
    """A fake Provider giving one answer for everything, counting how often it's asked."""

    name = "FakeIntel"
    handles = frozenset({ObservableKind.URL, ObservableKind.DOMAIN})
    lookups_per_minute = None

    def __init__(self, answer: Lookup) -> None:
        self.answer = answer
        self.asked = 0

    def lookup(self, observable: Observable) -> Lookup:
        self.asked += 1
        return self.answer


UNKNOWN = Lookup(Outcome.UNKNOWN, "not listed")
MALICIOUS = Lookup(Outcome.MALICIOUS, "listed for testing")


def link_email(tmp_path: Path) -> str:
    email_path = tmp_path / "link.eml"
    email_path.write_text("From: a@example.org\nSubject: Hi\n\nhttps://evil.example/x\n")
    return str(email_path)


def test_a_second_run_answers_from_the_cache(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    email = link_email(tmp_path)
    main([email], providers=[CountingProvider(MALICIOUS)])
    capsys.readouterr()
    second = CountingProvider(UNKNOWN)

    exit_code = main([email], providers=[second])

    assert second.asked == 0
    assert exit_code == 2  # The cached malicious answer, not the new Provider's.
    out = capsys.readouterr().out
    assert "FakeIntel: URL hxxps://evil[.]example/x -> malicious (listed for testing) (cached, fetched " in out
    assert (tmp_path / ".cache" / "lookups.json").exists()


def test_no_cache_asks_again_and_keeps_the_fresh_answer(tmp_path: Path) -> None:
    email = link_email(tmp_path)
    main([email], providers=[CountingProvider(UNKNOWN)])
    fresh = CountingProvider(MALICIOUS)

    assert main([email, "--no-cache"], providers=[fresh]) == 2
    assert fresh.asked == 2

    later = CountingProvider(UNKNOWN)
    assert main([email], providers=[later]) == 2  # The fresh answer was stored.
    assert later.asked == 0


def test_a_damaged_cache_file_is_ignored(tmp_path: Path) -> None:
    (tmp_path / ".cache").mkdir()
    (tmp_path / ".cache" / "lookups.json").write_text("{not json")
    provider = CountingProvider(UNKNOWN)

    assert main([link_email(tmp_path)], providers=[provider]) == 0
    assert provider.asked == 2


def test_a_damaged_time_in_the_cache_is_ignored(tmp_path: Path) -> None:
    email = link_email(tmp_path)
    main([email], providers=[CountingProvider(UNKNOWN)])
    cache_file = tmp_path / ".cache" / "lookups.json"
    cache_file.write_text(cache_file.read_text().replace('"stored_at": ', '"stored_at": 1e20, "x": '))
    provider = CountingProvider(UNKNOWN)

    assert main([email], providers=[provider]) == 0
    assert provider.asked == 2


def test_a_cache_that_cannot_be_written_still_gives_a_verdict(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / ".cache").write_text("a file where the folder should be")

    assert main([link_email(tmp_path)], providers=[CountingProvider(MALICIOUS)]) == 2
    assert "Warning: could not save the cache" in capsys.readouterr().err


def test_evidence_comes_back_unchanged_from_the_cache(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    email = link_email(tmp_path)
    evidence = {"malicious": 5, "flagged_by": ["EngineA", "EngineB"], "last_analysis": None}
    main([email, "--json"], providers=[CountingProvider(Lookup(Outcome.MALICIOUS, "5 of 90", evidence))])
    capsys.readouterr()

    main([email, "--json"], providers=[CountingProvider(UNKNOWN)])

    lookups = json.loads(capsys.readouterr().out)["lookups"]
    assert [(lookup["from_cache"], lookup["evidence"]) for lookup in lookups] == [(True, evidence)] * 2


ROUTED_EMAIL = (
    "Received: from mail.evil.example (mail.evil.example [45.33.32.156])"
    " by mx.example.com; Mon, 05 Oct 2026 10:00:02 +0000\n"
    "Received: from laptop (laptop [192.168.1.20]) by mail.evil.example\n"
    "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.org; dkim=fail\n"
    "From: a@example.org\nSubject: Hi\n\nHello.\n"
)


def test_readable_view_shows_authentication_the_received_chain_and_an_unverified_claimed_origin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    email_path = tmp_path / "routed.eml"
    email_path.write_text(ROUTED_EMAIL)

    main([str(email_path)])

    out = capsys.readouterr().out
    assert (
        "Authentication (recorded by mx.example.com):\n"
        "  SPF:   pass\n"
        "  DKIM:  fail\n"
        "  DMARC: not recorded\n"
    ) in out
    assert (
        "Received chain (earliest first):\n"
        "  1. from laptop [192.168.1.20] by mail.evil.example\n"
        "  2. from mail.evil.example [45.33.32.156] by mx.example.com"
        " at Mon, 05 Oct 2026 10:00:02 +0000\n"
        "Claimed Origin: 45.33.32.156, recorded by mx.example.com"
        " (unverified: the sender could have forged it, as no Trusted Relay recorded it)\n"
    ) in out


def test_readable_view_labels_a_claimed_origin_recorded_by_a_trusted_relay(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    email_path = tmp_path / "routed.eml"
    email_path.write_text(ROUTED_EMAIL)
    settings_path = tmp_path / "trusting.toml"
    settings_path.write_text(VALID_SETTINGS)  # Trusts "MX.Example.com.", written untidily.

    main([str(email_path), "--settings", str(settings_path)])

    out = capsys.readouterr().out
    assert "Claimed Origin: 45.33.32.156, recorded by Trusted Relay mx.example.com\n" in out


def test_json_report_carries_authentication_hops_and_claimed_origin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    email_path = tmp_path / "routed.eml"
    email_path.write_text(ROUTED_EMAIL)

    main([str(email_path), "--json"])

    report = json.loads(capsys.readouterr().out)
    assert report["authentication"]["dkim"] == {"result": "fail", "recorded": "dkim=fail"}
    assert [hop["from_ip"] for hop in report["received_hops"]] == ["192.168.1.20", "45.33.32.156"]
    assert report["claimed_origin"] == {"ip": "45.33.32.156", "recorded_by": "mx.example.com", "verified": False}


def test_readable_view_says_when_nothing_was_recorded(capsys: pytest.CaptureFixture[str]) -> None:
    main([CLEAN_EMAIL])

    out = capsys.readouterr().out
    assert "Authentication (no Authentication-Results header):\n  SPF:   not recorded\n" in out
    assert "Received chain (earliest first):\n  - None.\nClaimed Origin: none found\n" in out


def test_without_an_abuseipdb_key_the_claimed_origin_is_not_checked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    email_path = tmp_path / "routed.eml"
    email_path.write_text(ROUTED_EMAIL)

    exit_code = main([str(email_path)])

    out = capsys.readouterr().out
    assert "AbuseIPDB: Claimed Origin IP 45.33.32.156 -> not checked (no API key)" in out
    assert exit_code == 0  # An unchecked Claimed Origin alone can't stop a clean Verdict.
