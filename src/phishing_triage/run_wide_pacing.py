"""Keeping to Providers' rate limits across many Triages, for the Live Evaluation.

The core paces each Provider within one Triage, and forgets when the Triage
ends (ADR 0008). That's right for the CLI, which triages one email. The live
evaluation triages dozens in a row, so the next email's first lookup could
follow the last one's straight away and break a free tier's limit. Wrapping
each Provider in RunWidePacing keeps the core's own ProviderTurns for the
whole run, so it remembers the last lookup (ADR 0016).

Like the core, it never prints: it reports waits and stops through `on_progress`.
"""

from collections.abc import Callable, Set

from phishing_triage.core import Clock, Lookup, Observable, ObservableKind, Progress, Provider, ProviderTurns


class RunWidePacing:
    """A Provider that waits its turn, and stops being asked, across every Triage in a run.

    It tells the core it has no rate limit, so the core doesn't wait as well:
    the waiting all happens here. Once the Provider says to stop asking (a
    rejected key, or a used-up quota), it isn't asked again for the rest of
    the run, because the next email won't fix that.
    """

    def __init__(self, provider: Provider, clock: Clock, on_progress: Callable[[Progress], None]) -> None:
        self._provider = provider
        self._turns = ProviderTurns(provider, clock)  # Kept for the whole run
        self._on_progress = on_progress

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
        return self._turns.look_up(observable, self._on_progress)
