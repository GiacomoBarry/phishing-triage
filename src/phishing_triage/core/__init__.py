"""The triage core.

Everything a caller needs is importable from here. The core never prints,
saves files or reads environment variables: that is the CLI's job.
"""

from phishing_triage.core.attachments import Attachment, display_filename
from phishing_triage.core.authentication import AuthenticationCheck, AuthenticationResults
from phishing_triage.core.cache import LONGEST_LIFETIME, CachedLookup, LookupCache
from phishing_triage.core.errors import (
    NoAttachedEmailError,
    UnparseableAttachedEmailError,
    UnparseableEmailError,
)
from phishing_triage.core.findings import Finding, Rule, RuleInput
from phishing_triage.core.incident_note import describe_finding, incident_note
from phishing_triage.core.lookups import (
    LookupResult,
    LookupStarted,
    NotChecked,
    Progress,
    ProviderStopped,
    WaitingForRateLimit,
)
from phishing_triage.core.observables import LABELS, Observable, ObservableKind, defanged
from phishing_triage.core.providers import ABUSEIPDB, RDAP, URLHAUS, VIRUSTOTAL, Lookup, Outcome, Provider
from phishing_triage.core.received import ClaimedOrigin, ReceivedHop
from phishing_triage.core.report import TriageReport, Verdict
from phishing_triage.core.settings import Settings
from phishing_triage.core.triage import triage

__all__ = [
    "ABUSEIPDB",
    "LABELS",
    "LONGEST_LIFETIME",
    "Attachment",
    "AuthenticationCheck",
    "AuthenticationResults",
    "CachedLookup",
    "ClaimedOrigin",
    "Finding",
    "Lookup",
    "LookupCache",
    "LookupResult",
    "LookupStarted",
    "NoAttachedEmailError",
    "NotChecked",
    "Observable",
    "ObservableKind",
    "Outcome",
    "Progress",
    "ProviderStopped",
    "Provider",
    "ReceivedHop",
    "RDAP",
    "Rule",
    "RuleInput",
    "Settings",
    "TriageReport",
    "URLHAUS",
    "VIRUSTOTAL",
    "UnparseableAttachedEmailError",
    "UnparseableEmailError",
    "Verdict",
    "WaitingForRateLimit",
    "defanged",
    "describe_finding",
    "display_filename",
    "incident_note",
    "triage",
]
