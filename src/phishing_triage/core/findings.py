"""Findings and the rules that produce them."""

from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage

from phishing_triage.core.settings import Settings


@dataclass(frozen=True)
class Finding:
    """The result of one red-flag rule firing, with the evidence that triggered it."""

    rule_id: str
    points: int
    decisive: bool
    evidence: str


# A rule looks at the parsed email and returns zero or more Findings.
# Each rule is independent of the others.
Rule = Callable[[EmailMessage, Settings], list[Finding]]
