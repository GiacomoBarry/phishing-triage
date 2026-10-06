"""The command-line interface: a thin wrapper around the core.

The CLI does everything the core deliberately doesn't: it reads the file,
prints results, saves the Triage Report and turns the Verdict into an
exit code that scripts can react to.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from enum import IntEnum
from pathlib import Path
from typing import NoReturn

from phishing_triage.core import (
    Settings,
    TriageReport,
    UnparseableEmailError,
    Verdict,
    incident_note,
    triage,
)

REPORTS_DIR = Path("reports")


class ExitCode(IntEnum):
    """What the process exit code means. 3 and above are errors."""

    CLEAN = 0
    SUSPICIOUS = 1
    MALICIOUS = 2
    UNREADABLE_FILE = 3
    UNPARSEABLE_EMAIL = 4
    USAGE_ERROR = 5
    REPORT_NOT_SAVED = 6


VERDICT_EXIT_CODES = {
    Verdict.CLEAN: ExitCode.CLEAN,
    Verdict.SUSPICIOUS: ExitCode.SUSPICIOUS,
    Verdict.MALICIOUS: ExitCode.MALICIOUS,
}


class _ArgumentParser(argparse.ArgumentParser):
    """argparse exits with 2 on bad usage, which here would mean "malicious"."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(ExitCode.USAGE_ERROR, f"{self.prog}: error: {message}\n")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the exit code."""
    args = _parse_args(argv)
    email_path = Path(args.email)

    try:
        raw_email = email_path.read_bytes()
    except OSError as error:
        _print_error(f"could not read {email_path}: {error.strerror}")
        return ExitCode.UNREADABLE_FILE

    try:
        report = triage(raw_email, Settings(), providers=[])
    except UnparseableEmailError as error:
        _print_error(f"{email_path} is not a parseable email. {error}")
        return ExitCode.UNPARSEABLE_EMAIL

    # Print before saving, so the analyst still sees the Verdict if saving fails.
    report_json = json.dumps(report.to_dict(), indent=2)
    if args.json:
        print(report_json)
    else:
        print(_readable_view(report))

    try:
        saved_path = _save_report(report, report_json)
    except OSError as error:
        _print_error(f"could not save the Triage Report: {error}")
        return ExitCode.REPORT_NOT_SAVED
    print(f"Triage Report saved to {saved_path}", file=sys.stderr)

    return VERDICT_EXIT_CODES[report.verdict]


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = _ArgumentParser(
        prog="phishing-triage",
        description="Triage one reported email (.eml) using reputation lookups only.",
        epilog="Exit codes: 0 clean, 1 suspicious, 2 malicious, 3+ error.",
    )
    parser.add_argument("email", help="path to the .eml file to triage")
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the Triage Report as JSON instead of the readable view",
    )
    return parser.parse_args(argv)


def _save_report(report: TriageReport, report_json: str) -> Path:
    REPORTS_DIR.mkdir(exist_ok=True)
    path = REPORTS_DIR / f"{report.report_id}.json"
    path.write_text(report_json + "\n", encoding="utf-8")
    return path


def _readable_view(report: TriageReport) -> str:
    sender = report.from_address or "(no From address)"
    if report.display_name:
        sender = f"{report.display_name} <{report.from_address}>"

    lines = [
        f"Verdict:  {report.verdict.upper()}",
        f"Score:    {report.score}/100",
        f"From:     {sender}",
        f"Subject:  {report.subject or '(no subject)'}",
    ]
    lines += [f"Warning:  {warning}" for warning in report.warnings]
    lines += ["", "Incident Note", "-------------", incident_note(report)]
    return "\n".join(lines)


def _print_error(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)
