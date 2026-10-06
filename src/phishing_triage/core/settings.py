"""Settings that tune a Triage.

Empty for now. Finding points, Verdict thresholds and the other tunable
values arrive with the rules that use them (see ticket 02 onwards).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Tunable values for a Triage. Loaded by the CLI and passed in to the core."""
