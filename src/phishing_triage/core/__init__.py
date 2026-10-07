"""The triage core.

Everything a caller needs is importable from here. The core never prints,
saves files or reads environment variables: that is the CLI's job.
"""

from phishing_triage.core.attachments import Attachment, display_filename
from phishing_triage.core.errors import UnparseableEmailError
from phishing_triage.core.findings import Finding, Rule, RuleInput
from phishing_triage.core.incident_note import describe_finding, incident_note
from phishing_triage.core.lookups import LookupResult, NotChecked
from phishing_triage.core.observables import LABELS, Observable, ObservableKind, defanged
from phishing_triage.core.providers import URLHAUS, Lookup, Outcome, Provider
from phishing_triage.core.report import TriageReport, Verdict
from phishing_triage.core.settings import Settings
from phishing_triage.core.triage import triage

__all__ = [
    "LABELS",
    "Attachment",
    "Finding",
    "Lookup",
    "LookupResult",
    "NotChecked",
    "Observable",
    "ObservableKind",
    "Outcome",
    "Provider",
    "Rule",
    "RuleInput",
    "Settings",
    "TriageReport",
    "URLHAUS",
    "UnparseableEmailError",
    "Verdict",
    "defanged",
    "describe_finding",
    "display_filename",
    "incident_note",
    "triage",
]
