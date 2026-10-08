"""Offline evaluation: run the rules over a folder of labelled samples.

    phishing-triage-evaluate [samples] [--list] [--settings PATH]

The samples folder has a phish/ and a ham/ subfolder (scripts/download_datasets.py
fills them). Every file in each is triaged with no Providers, so nothing
touches the network, and the command prints how many phish and how many ham
emails got each Verdict, to catch false positives early (ADR 0015).

Like the CLI, this lives outside the core: it reads files and prints.
"""

import argparse
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from phishing_triage.command_line import ArgumentParser, ExitCode, print_error
from phishing_triage.config import SettingsError, load_settings
from phishing_triage.core import Rule, Settings, UnparseableEmailError, Verdict, triage
from phishing_triage.core.rules import BUILT_IN_RULES

SAMPLES_DIR = Path("samples")  # Ignored by git: raw samples hold real people's addresses
SAMPLE_LABELS = ("phish", "ham")


class Failure(StrEnum):
    """Why a sample got no Verdict."""

    UNPARSEABLE = "unparseable"  # The file isn't an email
    ERROR = "error"  # The file couldn't be read, or the core failed on it: something to fix


COLUMNS: list[Verdict | Failure] = [*Verdict, *Failure]


@dataclass(frozen=True)
class SampleResult:
    """What one sample got: a Verdict, or a Failure. Exactly one of the two is set."""

    label: str  # "phish" or "ham"
    path: Path
    verdict: Verdict | None  # The Verdict before the cap, or None if the sample failed
    failure: Failure | None  # Why there is no Verdict, or None if there is one
    score: int | None  # None if the sample failed
    # The rule IDs of the Findings, or why the sample failed.
    detail: str

    @property
    def outcome(self) -> Verdict | Failure:
        """The counts table's column for this sample."""
        if self.verdict is not None:
            return self.verdict
        assert self.failure is not None, "a SampleResult has a Verdict or a Failure"
        return self.failure


def main(argv: Sequence[str] | None = None, rules: Sequence[Rule] = BUILT_IN_RULES) -> int:
    """Run the evaluation command and return the exit code.

    `rules` defaults to the built-in red-flag rules. Tests pass their own.
    """
    args = _parse_args(argv)
    for label in SAMPLE_LABELS:
        folder = args.samples / label
        if not folder.is_dir():
            print_error(f"{folder} is not a folder. The samples folder needs a phish/ and a ham/ subfolder.")
            return ExitCode.MISSING_FOLDER
    try:
        settings = load_settings(args.settings)
    except SettingsError as error:
        print_error(str(error))
        return ExitCode.INVALID_SETTINGS

    samples = [(label, path) for label in SAMPLE_LABELS for path in _samples(args.samples / label)]
    # On stderr, so it never mixes with the results. A full run takes minutes.
    print(f"Triaging {len(samples)} samples offline...", file=sys.stderr, flush=True)
    results = [_evaluate_sample(label, path, settings, rules) for label, path in samples]

    print(f"Offline evaluation of {args.samples}: rules only, no Providers.")
    print("Verdicts are counted before the clean-requires-evidence cap.")
    print()
    if args.list:
        print("\n".join(_listing_line(result) for result in results))
        print()
    print(_counts_table(results))
    print()
    print(_rate_line("False-positive rate (ham not clean)", results, "ham", lambda v: v != Verdict.CLEAN))
    print(_rate_line("Missed-phish rate (phish clean)", results, "phish", lambda v: v == Verdict.CLEAN))
    return ExitCode.OK


def _evaluate_sample(label: str, path: Path, settings: Settings, rules: Sequence[Rule]) -> SampleResult:
    """Triage one sample with no Providers, keeping the Verdict from before the cap.

    With no Providers every URL and attachment is Not Checked, so the
    clean-requires-evidence cap would raise every clean Verdict to
    suspicious. The Verdict before the cap is what the rules alone decided.

    A sample that can't be triaged is counted as unparseable (not an email) or
    as an error (unreadable, or the core failed on it), with the reason, so one
    odd email can't stop a run over thousands. Errors get their own column so a
    bug in a rule can't hide among files that simply aren't emails.
    """
    try:
        raw_email = path.read_bytes()
    except OSError as error:
        return _failed(label, path, Failure.ERROR, f"could not be read: {error.strerror}")
    try:
        report = triage(raw_email, settings, providers=[], rules=rules)
    except UnparseableEmailError as error:
        return _failed(label, path, Failure.UNPARSEABLE, str(error))
    # Deliberately broad: real datasets hold emails odd enough to trip up the
    # parser or a rule. The listing shows the failure so the bug can be fixed.
    except Exception as error:
        return _failed(label, path, Failure.ERROR, f"the core failed ({type(error).__name__}: {error})")
    rule_ids = ", ".join(finding.rule_id for finding in report.findings)
    return SampleResult(label, path, report.verdict_before_cap, None, report.score, rule_ids)


def _failed(label: str, path: Path, failure: Failure, reason: str) -> SampleResult:
    return SampleResult(label, path, verdict=None, failure=failure, score=None, detail=reason)


def _listing_line(result: SampleResult) -> str:
    """One sample's label, Verdict, Score, path and Findings (or why it failed)."""
    score = "-" if result.score is None else str(result.score)
    line = f"{result.label:<6}{result.outcome:<12}{score:>4}  {result.path}"
    return f"{line}  ({result.detail})" if result.detail else line


def _samples(folder: Path) -> list[Path]:
    """Every file in `folder` and its subfolders, in a stable order.

    Hidden files (a name starting with ".", such as macOS's .DS_Store) are
    not samples. Dataset emails often have no .eml ending, so any other file counts.
    """
    return sorted(
        path
        for path in folder.rglob("*")
        if path.is_file() and not any(part.startswith(".") for part in path.relative_to(folder).parts)
    )


def _counts_table(results: list[SampleResult]) -> str:
    """How many samples of each label got each outcome."""
    lines = [_table_line("Label", [*COLUMNS, "total"])]
    for label in SAMPLE_LABELS:
        outcomes = [r.outcome for r in results if r.label == label]
        counts = [str(outcomes.count(column)) for column in COLUMNS]
        lines.append(_table_line(label, [*counts, str(len(outcomes))]))
    return "\n".join(lines)


def _rate_line(
    name: str, results: list[SampleResult], label: str, is_mistake: Callable[[Verdict], bool]
) -> str:
    """One rate: the share of a label's triaged samples that got the wrong sort of Verdict.

    Unparseable and error samples have no Verdict, so they count towards neither side.
    """
    verdicts = [r.verdict for r in results if r.label == label and r.verdict is not None]
    mistakes = sum(1 for verdict in verdicts if is_mistake(verdict))
    if not verdicts:
        return f"{name}: no {label} samples were triaged"
    return f"{name}: {mistakes / len(verdicts):.1%} ({mistakes} of {len(verdicts)} {label})"


def _table_line(row_name: str, cells: Sequence[str]) -> str:
    """One row of the counts table: its name left-aligned, then each cell right-aligned."""
    return f"{row_name:<6}" + "".join(f"{cell:>13}" for cell in cells)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = ArgumentParser(
        prog="phishing-triage-evaluate",
        description="Count the Verdicts the rules give a folder of phish and ham samples, offline.",
    )
    parser.add_argument(
        "samples",
        type=Path,
        nargs="?",
        default=SAMPLES_DIR,
        help=f"folder holding phish/ and ham/ subfolders (default: {SAMPLES_DIR})",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="also list every sample with its Verdict, Score and Findings, to investigate mistakes",
    )
    parser.add_argument(
        "--settings",
        type=Path,
        metavar="PATH",
        help="use an edited settings file instead of the defaults, to tune the weights",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
