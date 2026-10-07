"""Running Reputation Lookups, and working out what was Not Checked.

A Provider failing, for any reason, never stops a Triage: its lookup becomes
Not Checked with the reason, so the gap is visible instead of hidden.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from phishing_triage.core.cache import CachedLookup, LookupCache, cache_key, is_fresh, worth_caching
from phishing_triage.core.clock import Clock
from phishing_triage.core.observables import Observable, ObservableKind
from phishing_triage.core.providers import Lookup, Outcome, Provider

# The reason given when no Provider handles an Observable's kind at all.
NO_PROVIDER = "no Provider looks this kind of Observable up yet"

# The reason given for URLs beyond the lookup cap.
OVER_CAP = "over lookup cap"

# A clean Verdict needs these kinds checked. A link or an attachment nobody
# checked could be the payload. Domains add context but aren't required.
KINDS_NEEDING_EVIDENCE = frozenset({ObservableKind.URL, ObservableKind.SHA256})

# The order kinds are looked up in. The Claimed Origin and domains go first: there are fewer of them,
# and they still get checked when URLs are over the lookup cap.
LOOKUP_ORDER = (
    ObservableKind.CLAIMED_ORIGIN,
    ObservableKind.SENDER_DOMAIN,
    ObservableKind.DOMAIN,
    ObservableKind.URL,
    ObservableKind.SHA256,
)

# Lookups are spaced 10% further apart than a Provider's limit strictly needs,
# so network delays can't squeeze one lookup too many into a minute (ADR 0008).
SAFETY_MARGIN = 1.1


@dataclass(frozen=True)
class LookupResult:
    """One Provider's answer about one Observable, as recorded in the Triage Report."""

    provider: str
    observable: Observable
    outcome: Outcome
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    # Whether this answer came from the cache, and when it was first fetched (UTC).
    from_cache: bool = False
    cached_at: str | None = None


@dataclass(frozen=True)
class NotChecked:
    """An Observable no Provider actually answered for, and why."""

    observable: Observable
    reasons: list[str]


@dataclass(frozen=True)
class LookupStarted:
    """Progress: lookup `number` of `total` is about to be made, or was found in the cache."""

    number: int
    total: int
    provider: str
    observable: Observable
    from_cache: bool = False


@dataclass(frozen=True)
class WaitingForRateLimit:
    """Progress: waiting `seconds` before a Provider can be asked again."""

    provider: str
    seconds: float


@dataclass(frozen=True)
class ProviderStopped:
    """Progress: a Provider can't answer, so it won't be asked again in this Triage."""

    provider: str
    reason: str


# What the core reports while lookups run, so a caller can show progress.
type Progress = LookupStarted | WaitingForRateLimit | ProviderStopped


def run_lookups(
    observables: Sequence[Observable],
    providers: Sequence[Provider],
    url_cap: int,
    clock: Clock,
    on_progress: Callable[[Progress], None],
    cache: LookupCache | None,
    decisive_engines: int,
) -> list[LookupResult]:
    """Ask every Provider about every Observable of a kind it handles, domains first.

    Only the first `url_cap` URLs are looked up; the rest are Not Checked.
    Each Provider is asked no faster than its rate limit allows, by waiting.
    A Provider that says to stop asking isn't asked again in this Triage.
    A fresh answer in `cache` is used instead of asking (or waiting).
    """
    urls = [o for o in observables if o.kind is ObservableKind.URL]
    over_cap = set(urls[url_cap:])
    # sorted() is stable, so within each kind the email's order is kept.
    in_order = sorted(observables, key=lambda o: LOOKUP_ORDER.index(o.kind))
    turns = [_ProviderTurns(provider, clock) for provider in providers]
    store: LookupCache = cache or _NoCache()
    to_do = [(observable, turn) for observable in in_order for turn in turns if turn.handles(observable)]
    total = sum(1 for observable, _ in to_do if observable not in over_cap)

    number = 0
    results = []
    for observable, turn in to_do:
        if observable in over_cap:
            lookup, stored_at = Lookup(Outcome.NOT_CHECKED, OVER_CAP), None
        else:
            number += 1
            key = cache_key(turn.provider.name, observable, decisive_engines)

            def ask() -> Lookup:
                return turn.look_up(observable, number, total, on_progress)

            def announce_hit() -> None:
                on_progress(LookupStarted(number, total, turn.provider.name, observable, from_cache=True))

            lookup, stored_at = _cached_or_asked(store, key, clock, ask, announce_hit)
        results.append(
            LookupResult(
                provider=turn.provider.name,
                observable=observable,
                outcome=lookup.outcome,
                detail=lookup.detail,
                evidence=lookup.evidence,
                from_cache=stored_at is not None,
                cached_at=_utc_text(stored_at) if stored_at is not None else None,
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
        # A Provider that crashed once will most likely crash again, so stop asking it.
        reason = f"the Provider failed ({type(error).__name__}: {error})"
        return Lookup(Outcome.NOT_CHECKED, reason, stop_asking=True)


class _ProviderTurns:
    """One Provider's turns during a Triage: its rate-limit pacing, and whether it said to stop.

    Lookups to it are kept at least 60 / lookups_per_minute seconds apart, by
    waiting. Once it says to stop asking, the rest are Not Checked for the
    same reason, without asking it or waiting for it.
    """

    def __init__(self, provider: Provider, clock: Clock) -> None:
        self.provider = provider
        rate = provider.lookups_per_minute
        self._gap = 60 / rate * SAFETY_MARGIN if rate else 0.0
        self._clock = clock
        self._last_asked: float | None = None
        self._stopped_by: Lookup | None = None

    def handles(self, observable: Observable) -> bool:
        return observable.kind in self.provider.handles

    def look_up(
        self, observable: Observable, number: int, total: int, on_progress: Callable[[Progress], None]
    ) -> Lookup:
        """Wait for this Provider's turn, if needed, then ask it about `observable`."""
        if self._stopped_by is not None:
            return Lookup(Outcome.NOT_CHECKED, self._stopped_by.detail)
        wait = self._wait_needed()
        if wait > 0:
            on_progress(WaitingForRateLimit(self.provider.name, wait))
            self._clock.sleep(wait)
        on_progress(LookupStarted(number, total, self.provider.name, observable))
        self._last_asked = self._clock.now()
        lookup = _look_up(self.provider, observable)
        if lookup.stop_asking:
            self._stopped_by = lookup
            on_progress(ProviderStopped(self.provider.name, lookup.detail))
        return lookup

    def _wait_needed(self) -> float:
        if self._last_asked is None:
            return 0.0
        return max(0.0, self._last_asked + self._gap - self._clock.now())


def _cached_or_asked(
    store: LookupCache,
    key: str,
    clock: Clock,
    ask: Callable[[], Lookup],
    announce_hit: Callable[[], None],
) -> tuple[Lookup, float | None]:
    """A fresh cached answer if there is one, otherwise ask (and cache the answer).

    Returns the Lookup and, if it came from the cache, when it was stored.
    """
    cached = store.get(key)
    if cached is not None and is_fresh(cached, clock.now()):
        announce_hit()
        return cached.lookup, cached.stored_at
    lookup = ask()
    if worth_caching(lookup):
        store.put(key, CachedLookup(lookup, clock.now()))
    return lookup, None


class _NoCache:
    """Stands in when no cache is given: never has anything, keeps nothing."""

    def get(self, key: str) -> CachedLookup | None:
        return None

    def put(self, key: str, entry: CachedLookup) -> None:
        pass


def _utc_text(seconds: float) -> str:
    """Seconds since 1970 as readable UTC, such as 2026-10-07T18:19:45Z."""
    return datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
