"""Findings and the rules that produce them."""

from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage

from phishing_triage.core.attachments import Attachment
from phishing_triage.core.lookups import LookupResult
from phishing_triage.core.observables import Observable, ObservableKind
from phishing_triage.core.settings import Settings


@dataclass(frozen=True)
class Finding:
    """The result of one red-flag rule firing, with the evidence that triggered it."""

    rule_id: str
    points: int
    decisive: bool
    evidence: str


@dataclass(frozen=True)
class RuleInput:
    """Everything a rule is given to look at."""

    message: EmailMessage
    observables: list[Observable]
    attachments: list[Attachment]
    lookups: list[LookupResult]

    def values(self, kind: ObservableKind) -> list[str]:
        """The values of every Observable of one kind, in the order they were found."""
        return [o.value for o in self.observables if o.kind is kind]


# A rule looks at a RuleInput and returns zero or more Findings.
# Each rule is independent of the others.
Rule = Callable[[RuleInput, Settings], list[Finding]]
