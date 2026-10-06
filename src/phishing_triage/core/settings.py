"""Settings that tune a Triage.

The values themselves live in a settings file (see phishing_triage.config),
so they can be tuned without editing code. The core is simply handed a
Settings object.
"""

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Tunable values for a Triage. Loaded by the CLI and passed in to the core."""

    # Points each kind of Finding adds to the Score, keyed by rule identifier.
    points: Mapping[str, int]

    # The lowest Score that gives each Verdict. Anything lower is clean.
    suspicious_from: int
    malicious_from: int
