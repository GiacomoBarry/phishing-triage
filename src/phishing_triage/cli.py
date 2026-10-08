"""The command-line interface: a thin wrapper around the core.

The CLI does everything the core deliberately doesn't: it reads the file,
prints results, saves the Triage Report and turns the Verdict into an
exit code that scripts can react to.
"""

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from dotenv import load_dotenv

from phishing_triage.cache_file import JsonFileCache, WriteOnlyCache
from phishing_triage.command_line import ArgumentParser, ExitCode, print_error
from phishing_triage.config import SettingsError, load_settings
from phishing_triage.core import (
    LABELS,
    LookupStarted,
    NoAttachedEmailError,
    Progress,
    ProviderStopped,
    Provider,
    Settings,
    TriageReport,
    UnparseableAttachedEmailError,
    UnparseableEmailError,
    Verdict,
    defanged,
    describe_finding,
    display_filename,
    incident_note,
    triage,
)
from phishing_triage.providers import build_providers

REPORTS_DIR = Path("reports")

VERDICT_EXIT_CODES = {
    Verdict.CLEAN: ExitCode.CLEAN,
    Verdict.SUSPICIOUS: ExitCode.SUSPICIOUS,
    Verdict.MALICIOUS: ExitCode.MALICIOUS,
}


def main(argv: Sequence[str] | None = None, providers: Sequence[Provider] | None = None) -> int:
    """Run the CLI and return the exit code.

    `providers` defaults to the real ones, with API keys from the environment
    or a .env file in the current folder. Tests pass fakes instead.
    """
    args = _parse_args(argv)
    email_path = Path(args.email)

    try:
        settings = load_settings(args.settings)
    except SettingsError as error:
        print_error(str(error))
        return ExitCode.INVALID_SETTINGS

    try:
        raw_email = email_path.read_bytes()
    except OSError as error:
        print_error(f"could not read {email_path}: {error.strerror}")
        return ExitCode.UNREADABLE_FILE

    try:
        if providers is None:
            providers = _real_providers(settings)
        cache = JsonFileCache()
        report = triage(
            raw_email,
            settings,
            providers,
            on_progress=_show_progress,
            cache=WriteOnlyCache(cache) if args.no_cache else cache,
            inner=args.inner,
        )
        if cache.save_error:
            print(f"Warning: could not save the cache ({cache.save_error})", file=sys.stderr)
    except UnparseableAttachedEmailError as error:
        # The Wrapper Email itself is fine: it is the email inside it that isn't.
        print_error(f"{email_path}: {error}")
        return ExitCode.UNPARSEABLE_EMAIL
    except UnparseableEmailError as error:
        print_error(f"{email_path} is not a parseable email. {error}")
        return ExitCode.UNPARSEABLE_EMAIL
    except NoAttachedEmailError as error:
        print_error(f"{email_path}: {error} Leave out --inner to triage the email itself.")
        return ExitCode.NO_ATTACHED_EMAIL

    # Print before saving, so the analyst still sees the Verdict if saving fails.
    report_json = json.dumps(report.to_dict(), indent=2)
    if args.json:
        print(report_json)
    else:
        print(_readable_view(report))

    try:
        saved_path = _save_report(report, report_json)
    except OSError as error:
        print_error(f"could not save the Triage Report: {error}")
        return ExitCode.REPORT_NOT_SAVED
    print(f"Triage Report saved to {saved_path}", file=sys.stderr)

    return VERDICT_EXIT_CODES[report.verdict]


def _show_progress(event: Progress) -> None:
    """Show lookup progress on stderr, so it never mixes with --json output."""
    if isinstance(event, LookupStarted):
        observable = f"{LABELS[event.observable.kind]} {defanged(event.observable)}"
        message = f"Looking up {event.number} of {event.total}: {event.provider}, {observable}"
        if event.from_cache:
            message += " (cached)"
    elif isinstance(event, ProviderStopped):
        message = f"Not asking {event.provider} again: {event.reason}"
    else:
        message = f"Waiting {event.seconds:.0f}s for {event.provider}'s rate limit..."
    print(message, file=sys.stderr, flush=True)


def _real_providers(settings: Settings) -> list[Provider]:
    """Build the real Providers, reading API keys from .env (if present) and the environment.

    Keys already set in the environment win over the .env file.
    """
    load_dotenv(Path(".env"))
    return build_providers(os.environ, settings)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = ArgumentParser(
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
    parser.add_argument(
        "--inner",
        action="store_true",
        help="triage the email attached inside a Wrapper Email (a user's report of a phish) instead of the Wrapper Email itself",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="look everything up afresh instead of using cached answers (fresh ones are still cached)",
    )
    parser.add_argument(
        "--settings",
        type=Path,
        metavar="PATH",
        help="use an edited settings file instead of the defaults",
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
    if report.cap_reason:
        lines.append(f"Capped:   {report.cap_reason}")
    lines += [f"Warning:  {warning}" for warning in report.warnings]
    lines += _inner_hint(report)
    lines += ["", *_authentication_lines(report), "", *_received_lines(report)]
    lines += ["", "Attachments:"]
    for attachment in report.attachments:
        lines += [
            f"  - {display_filename(attachment.filename)}"
            f" ({attachment.content_type}, {attachment.size:,} bytes)",
            f"      SHA-256: {attachment.sha256}",
            f"      MD5:     {attachment.md5}",
            f"      SHA-1:   {attachment.sha1}",
        ]
    if not report.attachments:
        lines.append("  - None.")
    lines += ["", "Reputation Lookups:"]
    lines += [
        f"  - {result.provider}: {LABELS[result.observable.kind]} {defanged(result.observable)}"
        f" -> {result.outcome.replace('_', ' ')}"
        + (f" ({result.detail})" if result.detail else "")
        + (f" (cached, fetched {result.cached_at})" if result.from_cache else "")
        for result in report.lookups
    ]
    if not report.lookups:
        lines.append("  - None made.")
    lines += ["", "Findings:"]
    lines += [f"  - {describe_finding(finding)}" for finding in report.findings]
    if not report.findings:
        lines.append("  - None.")
    lines += ["", "Incident Note", "-------------", incident_note(report)]
    return "\n".join(lines)


def _inner_hint(report: TriageReport) -> list[str]:
    """Suggest --inner when the email given has an email attached.

    The core's warning names no flag, so the hint is added here. Once --inner
    has been used it isn't repeated: --inner only looks one level deep.
    """
    if report.taken_from_wrapper_sha256 or not report.attached_emails():
        return []
    which = "the attached email" if len(report.attached_emails()) == 1 else "the first attached email"
    return [f"Hint:     Use --inner to triage {which} instead."]


def _authentication_lines(report: TriageReport) -> list[str]:
    """SPF, DKIM and DMARC as recorded, and which server recorded them."""
    authentication = report.authentication
    if not authentication.header_found:
        heading = "Authentication (no Authentication-Results header):"
    else:
        heading = f"Authentication (recorded by {authentication.recorded_by or 'an unnamed server'}):"
    return [
        heading,
        f"  SPF:   {authentication.spf.result}",
        f"  DKIM:  {authentication.dkim.result}",
        f"  DMARC: {authentication.dmarc.result}",
    ]


def _received_lines(report: TriageReport) -> list[str]:
    """The Received chain hop by hop, then the Claimed Origin and how far to trust it."""
    lines = ["Received chain (earliest first):"]
    for number, hop in enumerate(report.received_hops, start=1):
        line = f"  {number}. from {hop.from_name or '(not recorded)'}"
        if hop.from_ip:
            line += f" [{hop.from_ip}]"
        line += f" by {hop.by_host or '(not recorded)'}"
        if hop.received_at:
            line += f" at {hop.received_at}"
        lines.append(line)
    if not report.received_hops:
        lines.append("  - None.")

    origin = report.claimed_origin
    if origin is None:
        lines.append("Claimed Origin: none found")
    elif origin.verified:
        lines.append(f"Claimed Origin: {origin.ip}, recorded by Trusted Relay {origin.recorded_by}")
    else:
        lines.append(
            f"Claimed Origin: {origin.ip}, recorded by {origin.recorded_by}"
            " (unverified: the sender could have forged it, as no Trusted Relay recorded it)"
        )
    return lines
