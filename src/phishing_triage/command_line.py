"""What the two commands (`phishing-triage` and `phishing-triage-evaluate`) share.

Keeping the exit codes in one place means the two commands can never give
the same number different meanings. Progress messages are shared too, so a
wait for a rate limit reads the same in both.
"""

import argparse
import sys
from enum import IntEnum
from typing import NoReturn

from phishing_triage.core import LABELS, LookupStarted, Progress, ProviderStopped, defanged


class ExitCode(IntEnum):
    """What the process exit code means. 3 and above are errors."""

    CLEAN = 0
    SUSPICIOUS = 1
    MALICIOUS = 2
    UNREADABLE_FILE = 3
    UNPARSEABLE_EMAIL = 4
    USAGE_ERROR = 5
    REPORT_NOT_SAVED = 6
    INVALID_SETTINGS = 7
    NO_ATTACHED_EMAIL = 8

    # Other names for the same numbers, for the evaluation, which gives no Verdict.
    OK = 0
    MISSING_FOLDER = 3  # Like an unreadable file: there is nothing to read


class ArgumentParser(argparse.ArgumentParser):
    """argparse exits with 2 on bad usage, which here would mean "malicious"."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(ExitCode.USAGE_ERROR, f"{self.prog}: error: {message}\n")


def print_error(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)


def show_progress(event: Progress) -> None:
    """Show lookup progress on stderr, so it never mixes with the results (or --json output)."""
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
