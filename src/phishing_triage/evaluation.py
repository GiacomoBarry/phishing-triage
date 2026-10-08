"""Evaluation: run the triage over a folder of labelled samples and count the Verdicts.

    phishing-triage-evaluate [samples] [--list] [--live] [--sample N] [--seed N] [--settings PATH]

The samples folder has a phish/ and a ham/ subfolder (scripts/download_datasets.py
fills them). By default every file in each is triaged with no Providers, so
nothing touches the network, and the command prints how many phish and how
many ham emails got each Verdict, to catch false positives early (ADR 0015).

With --live, a small reproducible sample is triaged with the real Providers
instead, keeping to their rate limits across the whole run and using the
reputation cache. It warns which Providers have no API key and how many
lookups it will make first, counts the final Verdicts and the Not Checked
Observables, then, to compare like-for-like, the live and the offline
Verdicts from before the cap for the same sample (ADR 0016).

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


from phishing_triage.cache_file import JsonFileCache
from phishing_triage.command_line import ArgumentParser, ExitCode, print_error, show_progress
from phishing_triage.config import SettingsError, load_settings
from phishing_triage.core import (
    SAFETY_MARGIN,
    Clock,
    Observable,
    Provider,
    Rule,
    SystemClock,
    TriageReport,
    UnparseableEmailError,
    Verdict,
    over_lookup_cap,
    triage,
)
from phishing_triage.core.rules import BUILT_IN_RULES
from phishing_triage.providers import missing_api_keys, real_providers
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
class Triaged:
    """What the core made of one sample."""

    verdict: Verdict  # The final Verdict, after the clean-requires-evidence cap
    verdict_before_cap: Verdict  # What the rules and Score alone decided
    score: int
    rule_ids: str  # The rule IDs of the Findings, comma-separated
    not_checked: int  # How many of its Observables no Provider answered for
    # What was pulled out of the email, in email order, to estimate the lookups a live run makes.
    observables: tuple[Observable, ...]


@dataclass(frozen=True)
class Failed:
    """Why one sample got no Verdict."""

    failure: Failure
    reason: str


@dataclass(frozen=True)
class SampleResult:
    """One sample and what it got: either Triaged, or Failed."""

    label: str  # "phish" or "ham"
    path: Path
    outcome: Triaged | Failed

    def column(self, before_cap: bool) -> Verdict | Failure:
        """The counts table's column for this sample: its Verdict (from before the cap, or final), or its Failure."""
        if isinstance(self.outcome, Failed):
            return self.outcome.failure
        return self.outcome.verdict_before_cap if before_cap else self.outcome.verdict


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
    # Live, this first pass only finds each sample's Observables for the
    # estimate (and gives the offline counts to compare with).
    if args.live:
        first_pass = f"Reading {len(samples)} samples to estimate the lookups (no lookups yet)..."
    else:
        first_pass = f"Triaging {len(samples)} samples offline..."
    print(first_pass, file=sys.stderr, flush=True)

    def triage_offline(raw_email: bytes) -> TriageReport:
        return triage(raw_email, settings, providers=[], rules=rules)

    offline_results = [_evaluate_sample(label, path, triage_offline) for label, path in samples]
    if not args.live:
        print(f"Offline evaluation of {args.samples}: rules only, no Providers.")
        print("Verdicts are counted before the clean-requires-evidence cap.")
        print()
        _print_results(offline_results, args.list, before_cap=True)
        return ExitCode.OK

    # Live, the offline pass has found each sample's Observables, so the
    # warning can say how many lookups there will be before any is made.
    if providers is None:
        providers = real_providers(settings)  # Also reads .env into the environment
        # A Provider with no key answers Not Checked, which would quietly make the
        # run look worse. Only the names are printed, never a key.
        for provider, variable in missing_api_keys(os.environ).items():
            print(
                f"Warning: {provider} has no API key ({variable}), so its lookups will be Not Checked.",
                file=sys.stderr,
            )
    print(_lookup_estimate(offline_results, providers, settings.url_cap), file=sys.stderr, flush=True)
    print(f"Triaging {len(samples)} samples with live lookups...", file=sys.stderr, flush=True)
    live_clock = clock or SystemClock()
    paced = [RunWidePacing(provider, live_clock, show_progress) for provider in providers]
    cache = JsonFileCache()  # The CLI's cache: answers it has are used, new ones kept.

    def triage_live(raw_email: bytes) -> TriageReport:
        return triage(raw_email, settings, paced, rules=rules, clock=live_clock, cache=cache)

    live_results = [_evaluate_sample(label, path, triage_live) for label, path in samples]
    if cache.save_error:
        print(f"Warning: could not save the cache ({cache.save_error})", file=sys.stderr)

    print(f"Live evaluation of {args.samples}: rules plus Reputation Lookups.")
    print("Verdicts are the final ones, after the clean-requires-evidence cap, as an analyst sees them.")
    print()
    _print_results(live_results, args.list, before_cap=False)
    print(_not_checked_line(live_results))
    print()
    # Offline, every link and attachment is Not Checked, so the offline counts
    # are from before the cap. Comparing them with the final live counts would
    # blame the lookups for what the cap did, so the live counts from before
    # the cap are shown alongside them.
    print("To compare like-for-like with the rules alone, the Verdicts before the cap:")
    print()
    print("Live, before the cap (rules plus Reputation Lookups):")
    print()
    _print_results(live_results, show_list=False, before_cap=True)
    print()
    print("Offline, before the cap (rules only, no Providers):")
    print()
    _print_results(offline_results, show_list=False, before_cap=True)
    return ExitCode.OK


def _print_results(results: list[SampleResult], show_list: bool, before_cap: bool) -> None:
    """The --list lines (if asked for), the counts table and the two rates.

    `before_cap` says which Verdict to count: the one from before the
    clean-requires-evidence cap, or the final one.
    """
    if show_list:
        print("\n".join(_listing_line(result, before_cap) for result in results))
        print()
    print(_counts_table(results, before_cap))
    print()
    print(_rate_line("False-positive rate (ham not clean)", results, "ham", before_cap, lambda v: v != Verdict.CLEAN))
    print(_rate_line("Missed-phish rate (phish clean)", results, "phish", before_cap, lambda v: v == Verdict.CLEAN))


def _evaluate_sample(label: str, path: Path, run_triage: Callable[[bytes], TriageReport]) -> SampleResult:
    """Triage one sample with `run_triage` (offline or live), and keep both its Verdicts.

    Both the final Verdict and the one from before the cap are kept: offline,
    every URL and attachment is Not Checked, so the clean-requires-evidence
    cap would raise every clean Verdict to suspicious, and only the Verdict
    from before the cap says what the rules decided.

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
        report = run_triage(raw_email)
    except UnparseableEmailError as error:
        return _failed(label, path, Failure.UNPARSEABLE, str(error))
    # Deliberately broad: real datasets hold emails odd enough to trip up the
    # parser or a rule. The listing shows the failure so the bug can be fixed.
    except Exception as error:
        return _failed(label, path, Failure.ERROR, f"the core failed ({type(error).__name__}: {error})")
    triaged = Triaged(
        verdict=report.verdict,
        verdict_before_cap=report.verdict_before_cap,
        score=report.score,
        rule_ids=", ".join(finding.rule_id for finding in report.findings),
        not_checked=len(report.not_checked),
        observables=tuple(report.observables),
    )
    return SampleResult(label, path, triaged)


def _failed(label: str, path: Path, failure: Failure, reason: str) -> SampleResult:
    return SampleResult(label, path, Failed(failure, reason))


def _listing_line(result: SampleResult, before_cap: bool) -> str:
    """One sample's label, Verdict, Score, path and Findings (or why it failed)."""
    if isinstance(result.outcome, Failed):
        score, detail = "-", result.outcome.reason
    else:
        score, detail = str(result.outcome.score), result.outcome.rule_ids
    line = f"{result.label:<6}{result.column(before_cap):<12}{score:>4}  {result.path}"
    return f"{line}  ({detail})" if detail else line


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
        if isinstance(result.outcome, Failed):
            continue
        observables = result.outcome.observables
        over_cap = over_lookup_cap(observables, url_cap)
        to_look_up = [o for o in observables if o not in over_cap]
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


def _counts_table(results: list[SampleResult], before_cap: bool) -> str:
    """How many samples of each label got each outcome."""
    lines = [_table_line("Label", [*COLUMNS, "total"])]
    for label in SAMPLE_LABELS:
        outcomes = [r.column(before_cap) for r in results if r.label == label]
        counts = [str(outcomes.count(column)) for column in COLUMNS]
        lines.append(_table_line(label, [*counts, str(len(outcomes))]))
    return "\n".join(lines)


def _rate_line(
    name: str,
    results: list[SampleResult],
    label: str,
    before_cap: bool,
    is_mistake: Callable[[Verdict], bool],
) -> str:
    """One rate: the share of a label's triaged samples that got the wrong sort of Verdict.

    Unparseable and error samples have no Verdict, so they count towards neither side.
    """
    columns = [r.column(before_cap) for r in results if r.label == label]
    verdicts = [column for column in columns if isinstance(column, Verdict)]
    mistakes = sum(1 for verdict in verdicts if is_mistake(verdict))
    if not verdicts:
        return f"{name}: no {label} samples were triaged"
    return f"{name}: {mistakes / len(verdicts):.1%} ({mistakes} of {len(verdicts)} {label})"


def _not_checked_line(results: list[SampleResult]) -> str:
    """How many Observables no Provider answered for, in all and for each label."""
    per_label = {
        label: sum(r.outcome.not_checked for r in results if r.label == label and isinstance(r.outcome, Triaged))
        for label in SAMPLE_LABELS
    }
    in_each = ", ".join(f"{count} in {label}" for label, count in per_label.items())
    return f"Observables Not Checked: {sum(per_label.values())} ({in_each})"


def _table_line(row_name: str, cells: Sequence[str]) -> str:
    """One row of the counts table: its name left-aligned, then each cell right-aligned."""
    return f"{row_name:<6}" + "".join(f"{cell:>13}" for cell in cells)


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
