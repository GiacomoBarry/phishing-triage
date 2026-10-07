"""Running Reputation Lookups, and working out what was Not Checked.

A Provider failing, for any reason, never stops a Triage: its lookup becomes
Not Checked with the reason, so the gap is visible instead of hidden.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from phishing_triage.core.observables import Observable, ObservableKind
from phishing_triage.core.providers import Lookup, Outcome, Provider

# The reason given when no Provider handles an Observable's kind at all.
NO_PROVIDER = "no Provider looks this kind of Observable up yet"

# A clean Verdict needs these kinds checked. A link or an attachment nobody
# checked could be the payload. Domains add context but aren't required.
KINDS_NEEDING_EVIDENCE = frozenset({ObservableKind.URL, ObservableKind.SHA256})


@dataclass(frozen=True)
class LookupResult:
    """One Provider's answer about one Observable, as recorded in the Triage Report."""

    provider: str
    observable: Observable
    outcome: Outcome
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NotChecked:
    """An Observable no Provider actually answered for, and why."""

    observable: Observable
    reasons: list[str]


def run_lookups(
    observables: Sequence[Observable], providers: Sequence[Provider]
) -> list[LookupResult]:
    """Ask every Provider about every Observable of a kind it handles."""
    results = []
    for observable in observables:
        for provider in providers:
            if observable.kind in provider.handles:
                lookup = _look_up(provider, observable)
                results.append(
                    LookupResult(
                        provider=provider.name,
                        observable=observable,
                        outcome=lookup.outcome,
                        detail=lookup.detail,
                        evidence=lookup.evidence,
                    )
                )
    return results


def find_not_checked(
    observables: Sequence[Observable], results: Sequence[LookupResult]
) -> list[NotChecked]:
    """Return each Observable that no Provider gave a real answer for.

    A real answer is malicious, suspicious, clean or Unknown. An Observable
    with only Not Checked results, or that no Provider handles, is Not Checked.
    """
    not_checked = []
    for observable in observables:
        own_results = [r for r in results if r.observable == observable]
        if any(r.outcome is not Outcome.NOT_CHECKED for r in own_results):
            continue
        reasons = [f"{r.provider}: {r.detail}" for r in own_results] or [NO_PROVIDER]
        not_checked.append(NotChecked(observable=observable, reasons=reasons))
    return not_checked


def _look_up(provider: Provider, observable: Observable) -> Lookup:
    """Ask one Provider, turning any failure into Not Checked."""
    try:
        return provider.lookup(observable)
    # Deliberately broad: a bug or surprise in any Provider must never crash
    # the Triage. The analyst sees the reason in the Not Checked section.
    except Exception as error:
        return Lookup(Outcome.NOT_CHECKED, f"the Provider failed ({type(error).__name__}: {error})")
