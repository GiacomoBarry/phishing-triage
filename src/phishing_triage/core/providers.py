"""The Provider interface, and what a Reputation Lookup can come back with.

A Provider is an outside source a Reputation Lookup is made against.
Providers are always built outside the core and passed in, so the core never
reads API keys or makes network calls itself, and tests can pass fakes.
"""

from collections.abc import Set
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from phishing_triage.core.observables import Observable, ObservableKind


# Names of Providers that a rule needs to recognise.
URLHAUS = "URLhaus"
VIRUSTOTAL = "VirusTotal"
RDAP = "RDAP"
ABUSEIPDB = "AbuseIPDB"


class Outcome(StrEnum):
    """What one Reputation Lookup concluded."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    # The Provider was asked and has no record. Never the same as clean.
    UNKNOWN = "unknown"
    # The lookup never happened (no key, an error, a timeout...).
    NOT_CHECKED = "not_checked"


@dataclass(frozen=True)
class Lookup:
    """What a Provider says about one Observable.

    `detail` explains the outcome in a few words: why it's malicious or
    suspicious, or, for Not Checked, the reason. `evidence` keeps the useful
    parts of the Provider's raw answer for the Triage Report.

    `stop_asking` means the Provider can't answer anything else in this
    Triage (it can't be reached, has no or a rejected key, or is rate
    limited), so the rest of its lookups are Not Checked for the same reason
    without asking it, or waiting for it, again.
    """

    outcome: Outcome
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    stop_asking: bool = False


class Provider(Protocol):
    """An outside source a Reputation Lookup is made against.

    Its only action is `lookup`: asking what it already knows. There is
    deliberately no way to submit or scan anything (ADR 0001).
    """

    @property
    def name(self) -> str:
        """The Provider's name as shown to analysts, such as "URLhaus"."""
        ...

    @property
    def handles(self) -> Set[ObservableKind]:
        """The kinds of Observable this Provider can look up."""
        ...

    @property
    def lookups_per_minute(self) -> int | None:
        """How many lookups a minute it allows, or None for no limit. The core waits to keep to it."""
        ...

    def lookup(self, observable: Observable) -> Lookup:
        """Look one Observable up. Problems should come back as Not Checked, not raise."""
        ...
