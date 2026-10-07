"""Caching Reputation Lookups, so re-running a Triage doesn't use up Provider quota.

The core decides what to cache and for how long. Where entries are kept is
the caller's job: the CLI passes a cache that writes a JSON file, and tests
pass one kept in memory. The core itself never saves files.
"""

from dataclasses import dataclass
from typing import Protocol

from phishing_triage.core.observables import Observable
from phishing_triage.core.providers import Lookup, Outcome

DAY = 24 * 60 * 60

# How long each outcome stays fresh, in seconds. Malicious answers rarely
# change, but "not known" ones must be refreshed quickly so a newly flagged
# phishing link isn't hidden. Not Checked is never cached.
LIFETIMES = {
    Outcome.MALICIOUS: 7 * DAY,
    Outcome.SUSPICIOUS: DAY,
    Outcome.CLEAN: DAY,
    Outcome.UNKNOWN: DAY,
}

# No entry is ever fresh for longer than this, so older ones can be thrown away.
LONGEST_LIFETIME = max(LIFETIMES.values())


@dataclass(frozen=True)
class CachedLookup:
    """A Lookup and when it was stored, in seconds since 1 January 1970 (UTC)."""

    lookup: Lookup
    stored_at: float


class LookupCache(Protocol):
    """Somewhere cached Lookups are kept between Triages."""

    def get(self, key: str) -> CachedLookup | None:
        """The entry stored under `key`, however old, or None."""
        ...

    def put(self, key: str, entry: CachedLookup) -> None:
        """Store `entry` under `key`, replacing any older one."""
        ...


def cache_key(provider: str, observable: Observable, decisive_engines: int) -> str:
    """The key a Lookup is cached under.

    The decisive Engine count is part of it, because VirusTotal's outcome
    depends on it: changing the setting must not reuse old outcomes.
    """
    return f"{provider}|{observable.kind}|{observable.value}|decisive_engines={decisive_engines}"


def is_fresh(entry: CachedLookup, now: float) -> bool:
    """Is a cached entry still young enough to use?

    An entry stored "in the future" (the computer's clock was fast, or the
    file was edited) isn't trusted, because it could outlive its lifetime.
    """
    lifetime = LIFETIMES.get(entry.lookup.outcome)
    age = now - entry.stored_at
    return lifetime is not None and 0 <= age < lifetime


def worth_caching(lookup: Lookup) -> bool:
    """Not Checked means the lookup never happened, so there's nothing to keep."""
    return lookup.outcome in LIFETIMES
