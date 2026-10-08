"""Keeping to Providers' rate limits across many Triages, for the live evaluation.

The core paces each Provider within one Triage, and forgets when the Triage
ends (ADR 0008). That's right for the CLI, which triages one email. The live
evaluation triages dozens in a row, so the next email's first lookup could
follow the last one's straight away and break a free tier's limit. Wrapping
each Provider in RunWidePacing remembers its last lookup for the whole run
(ADR 0016).

Like the CLI, this lives outside the core: it prints progress itself.
"""

import sys
from collections.abc import Set

from phishing_triage.core import SAFETY_MARGIN, Clock, Lookup, Observable, ObservableKind, Outcome, Provider


class RunWidePacing:
    """A Provider that waits its turn, and stops being asked, across every Triage in a run.

    It tells the core it has no rate limit, so the core doesn't wait as well:
    the waiting all happens here. Once the Provider says to stop asking (a
    rejected key, or a used-up quota), it isn't asked again for the rest of
    the run, because the next email won't fix that.
    """

    def __init__(self, provider: Provider, clock: Clock) -> None:
        self._provider = provider
        self._clock = clock
        rate = provider.lookups_per_minute
        self._gap = 60 / rate * SAFETY_MARGIN if rate else 0.0
        self._last_asked: float | None = None
        self._stopped_by: Lookup | None = None

    @property
    def name(self) -> str:
        return self._provider.name

    @property
    def handles(self) -> Set[ObservableKind]:
        return self._provider.handles

    @property
    def lookups_per_minute(self) -> None:
        return None  # The pacing happens here, across the whole run.

    def lookup(self, observable: Observable) -> Lookup:
        if self._stopped_by is not None:
            return Lookup(Outcome.NOT_CHECKED, self._stopped_by.detail, stop_asking=True)
        if self._last_asked is not None:
            wait = self._last_asked + self._gap - self._clock.now()
            if wait > 0:
                print(f"Waiting {wait:.0f}s for {self.name}'s rate limit...", file=sys.stderr, flush=True)
                self._clock.sleep(wait)
        self._last_asked = self._clock.now()
        lookup = self._provider.lookup(observable)
        if lookup.stop_asking:
            self._stopped_by = lookup
            print(f"Not asking {self.name} again in this evaluation: {lookup.detail}", file=sys.stderr, flush=True)
        return lookup
