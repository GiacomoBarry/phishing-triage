"""Evaluation: run the triage over a folder of labelled samples and count the Verdicts.

    phishing-triage-evaluate [samples] [--list] [--live] [--sample N] [--seed N] [--settings PATH]

The samples folder has a phish/ and a ham/ subfolder (scripts/download_datasets.py
fills them). By default every file in each is triaged with no Providers, so
nothing touches the network, and the command prints how many phish and how
many ham emails got each Verdict, to catch false positives early (ADR 0015).

With --live, a small reproducible sample is triaged with the real Providers
instead, keeping to their rate limits across the whole run and using the
reputation cache. It warns how many lookups it will make first, counts the
final Verdicts and the Not Checked Observables, and prints the offline counts
for the same sample to compare (ADR 0016).

Like the CLI, this lives outside the core: it reads files and prints.
"""

import argparse
import os
import random
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from dotenv import load_dotenv

from phishing_triage.cache_file import JsonFileCache
from phishing_triage.command_line import ArgumentParser, ExitCode, print_error
from phishing_triage.config import SettingsError, load_settings
from phishing_triage.core import (
    SAFETY_MARGIN,
    Clock,
    LookupCache,
    Observable,
    ObservableKind,
    Provider,
    Rule,
    Settings,
    SystemClock,
    UnparseableEmailError,
    Verdict,
    triage,
)
from phishing_triage.core.rules import BUILT_IN_RULES
from phishing_triage.providers import build_providers
from phishing_triage.run_wide_pacing import RunWidePacing

SAMPLES_DIR = Path("samples")  # Ignored by git: raw samples hold real people's addresses
SAMPLE_LABELS = ("phish", "ham")

# A live run asks real Providers on free tiers, so by default it takes a small
# sample of each label. The seed makes the pick the same every time (ADR 0016).
LIVE_SAMPLE_SIZE = 20
DEFAULT_SEED = 1


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
    # The Verdict (before the cap offline, final live), or None if the sample failed.
    verdict: Verdict | None
    failure: Failure | None  # Why there is no Verdict, or None if there is one
    score: int | None  # None if the sample failed
    # The rule IDs of the Findings, or why the sample failed.
    detail: str
    # How many of its Observables were Not Checked. Only meaningful live:
    # offline, nothing is checked.
    not_checked: int = 0
    # What was pulled out of the email, in email order, to estimate the lookups a live run makes.
    observables: tuple[Observable, ...] = ()

    @property
    def outcome(self) -> Verdict | Failure:
        """The counts table's column for this sample."""
        if self.verdict is not None:
            return self.verdict
        assert self.failure is not None, "a SampleResult has a Verdict or a Failure"
        return self.failure


def main(
    argv: Sequence[str] | None = None,
    rules: Sequence[Rule] = BUILT_IN_RULES,
    providers: Sequence[Provider] | None = None,
    clock: Clock | None = None,
) -> int:
    """Run the evaluation command and return the exit code.

    `rules` defaults to the built-in red-flag rules. With --live, `providers`
    defaults to the real ones, with API keys from the environment or a .env
    file in the current folder, and `clock` to the real clock, used to wait
    out rate limits. Tests pass their own rules, fake Providers and a fake clock.
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

    sample_size = args.sample or (LIVE_SAMPLE_SIZE if args.live else None)
    samples = [
        (label, path)
        for label in SAMPLE_LABELS
        for path in _pick(_samples(args.samples / label), sample_size, args.seed)
    ]
    # On stderr, so it never mixes with the results. A full run takes minutes.
    print(f"Triaging {len(samples)} samples offline...", file=sys.stderr, flush=True)
    offline_results = [_evaluate_sample(label, path, settings, rules) for label, path in samples]
    if not args.live:
        print(f"Offline evaluation of {args.samples}: rules only, no Providers.")
        print("Verdicts are counted before the clean-requires-evidence cap.")
        print()
        _print_results(offline_results, args.list)
        return ExitCode.OK

    # Live, the offline pass has found each sample's Observables, so the
    # warning can say how many lookups there will be before any is made.
    if providers is None:
        providers = _real_providers(settings)
    print(_lookup_estimate(offline_results, providers, settings.url_cap), file=sys.stderr, flush=True)
    print(f"Triaging {len(samples)} samples with live lookups...", file=sys.stderr, flush=True)
    clock = clock or SystemClock()
    cache = JsonFileCache()  # The CLI's cache: answers it has are used, new ones kept.
    live = _LiveLookups([RunWidePacing(provider, clock) for provider in providers], clock, cache)
    live_results = [_evaluate_sample(label, path, settings, rules, live) for label, path in samples]
    if cache.save_error:
        print(f"Warning: could not save the cache ({cache.save_error})", file=sys.stderr)

    print(f"Live evaluation of {args.samples}: rules plus Reputation Lookups.")
    print("Verdicts are the final ones, after the clean-requires-evidence cap.")
    print()
    _print_results(live_results, args.list)
    print(_not_checked_line(live_results))
    print()
    print("For comparison, offline on the same samples (rules only, Verdicts before the cap):")
    print()
    _print_results(offline_results, show_list=False)
    return ExitCode.OK


def _print_results(results: list[SampleResult], show_list: bool) -> None:
    """The --list lines (if asked for), the counts table and the two rates."""
    if show_list:
        print("\n".join(_listing_line(result) for result in results))
        print()
    print(_counts_table(results))
    print()
    print(_rate_line("False-positive rate (ham not clean)", results, "ham", lambda v: v != Verdict.CLEAN))
    print(_rate_line("Missed-phish rate (phish clean)", results, "phish", lambda v: v == Verdict.CLEAN))


@dataclass(frozen=True)
class _LiveLookups:
    """What a live run triages each sample with: the paced Providers, the clock they wait on, and the cache."""

    providers: list[Provider]
    clock: Clock
    cache: LookupCache


def _evaluate_sample(
    label: str,
    path: Path,
    settings: Settings,
    rules: Sequence[Rule],
    live: _LiveLookups | None = None,
) -> SampleResult:
    """Triage one sample, offline (no `live`) or live, and keep its Verdict.

    Offline, every URL and attachment is Not Checked, so the
    clean-requires-evidence cap would raise every clean Verdict to
    suspicious. So the Verdict kept is the one from before the cap: what the
    rules alone decided. Live, it is the final Verdict, as an analyst would see it.

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
        if live is None:
            report = triage(raw_email, settings, providers=[], rules=rules)
        else:
            report = triage(raw_email, settings, live.providers, rules=rules, clock=live.clock, cache=live.cache)
    except UnparseableEmailError as error:
        return _failed(label, path, Failure.UNPARSEABLE, str(error))
    # Deliberately broad: real datasets hold emails odd enough to trip up the
    # parser or a rule. The listing shows the failure so the bug can be fixed.
    except Exception as error:
        return _failed(label, path, Failure.ERROR, f"the core failed ({type(error).__name__}: {error})")
    rule_ids = ", ".join(finding.rule_id for finding in report.findings)
    verdict = report.verdict_before_cap if live is None else report.verdict
    return SampleResult(
        label, path, verdict, None, report.score, rule_ids, len(report.not_checked), tuple(report.observables)
    )


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


def _lookup_estimate(results: list[SampleResult], providers: Sequence[Provider], url_cap: int) -> str:
    """A warning of the most Reputation Lookups a live run will make, for each Provider.

    It's the most because a fresh cached answer is used instead of asking,
    and a Provider that stops answering isn't asked again.
    """
    counts = {provider.name: 0 for provider in providers}
    for result in results:
        urls = [o for o in result.observables if o.kind is ObservableKind.URL]
        to_look_up = [o for o in result.observables if o.kind is not ObservableKind.URL] + urls[:url_cap]
        for provider in providers:
            counts[provider.name] += sum(1 for o in to_look_up if o.kind in provider.handles)
    lines = [f"Up to {sum(counts.values())} Reputation Lookups (fewer if answers are cached):"]
    rates = {provider.name: provider.lookups_per_minute for provider in providers}
    lines += [f"  {name}: up to {count}{_how_long(count, rates[name])}" for name, count in counts.items()]
    return "\n".join(lines)


def _how_long(lookups: int, lookups_per_minute: int | None) -> str:
    """The shortest time a rate limit lets `lookups` lookups take, or "" if it has no limit.

    The first lookup needs no wait; each later one waits a gap, with the
    core's safety margin.
    """
    if not lookups_per_minute or lookups < 2:
        return ""
    seconds = (lookups - 1) * 60 / lookups_per_minute * SAFETY_MARGIN
    duration = f"{seconds:.0f} seconds" if seconds < 120 else f"{seconds / 60:.0f} minutes"
    return f" (at most {lookups_per_minute} a minute, so at least {duration})"


def _pick(paths: list[Path], size: int | None, seed: int) -> list[Path]:
    """`size` of `paths` picked at random, the same ones every time for the same seed, or all of them.

    Each label gets its own random generator, so the phish picked don't
    depend on how many ham there are. The pick is kept in path order.
    """
    if size is None or size >= len(paths):
        return paths
    return sorted(random.Random(seed).sample(paths, size))


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


def _not_checked_line(results: list[SampleResult]) -> str:
    """How many Observables no Provider answered for, in all and for each label."""
    per_label = {label: sum(r.not_checked for r in results if r.label == label) for label in SAMPLE_LABELS}
    in_each = ", ".join(f"{count} in {label}" for label, count in per_label.items())
    return f"Observables Not Checked: {sum(per_label.values())} ({in_each})"


def _table_line(row_name: str, cells: Sequence[str]) -> str:
    """One row of the counts table: its name left-aligned, then each cell right-aligned."""
    return f"{row_name:<6}" + "".join(f"{cell:>13}" for cell in cells)


def _real_providers(settings: Settings) -> list[Provider]:
    """Build the real Providers, reading API keys from .env (if present) and the environment.

    Keys already set in the environment win over the .env file.
    """
    load_dotenv(Path(".env"))
    return build_providers(os.environ, settings)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = ArgumentParser(
        prog="phishing-triage-evaluate",
        description="Count the Verdicts given to a folder of phish and ham samples: offline by default, or with --live lookups.",
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
        "--live",
        action="store_true",
        help="ask the real Providers (API keys from .env), over a small sample, and count the final Verdicts",
    )
    parser.add_argument(
        "--sample",
        type=_positive_whole_number,
        metavar="N",
        help=f"evaluate N phish and N ham picked at random (default: every sample offline, {LIVE_SAMPLE_SIZE} live)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help=f"pick a different random sample; the same seed always picks the same samples (default: {DEFAULT_SEED})",
    )
    parser.add_argument(
        "--settings",
        type=Path,
        metavar="PATH",
        help="use an edited settings file instead of the defaults, to tune the weights",
    )
    return parser.parse_args(argv)


def _positive_whole_number(text: str) -> int:
    """Read a sample size, refusing anything below 1 (argparse reports the error as bad usage)."""
    try:
        number = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
    if number < 1:
        raise argparse.ArgumentTypeError(f"{number} is not 1 or more")
    return number


if __name__ == "__main__":
    sys.exit(main())
