"""The Triage Report: the structured record of one Triage.

This module is the one place the report's format is defined. Bump
FORMAT_VERSION whenever a field is renamed or removed, so that older saved
reports can still be interpreted.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from phishing_triage.core.attachments import Attachment
from phishing_triage.core.authentication import AuthenticationResults
from phishing_triage.core.findings import Finding
from phishing_triage.core.lookups import LookupResult, NotChecked
from phishing_triage.core.observables import Observable
from phishing_triage.core.received import ClaimedOrigin, ReceivedHop

FORMAT_VERSION = 1


class Verdict(StrEnum):
    """The conclusion of a Triage."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass(frozen=True)
class TriageReport:
    """The structured record of one Triage."""

    # Metadata, so later phases can find, de-duplicate and interpret reports.
    report_id: str
    analysed_at: datetime
    tool_version: str
    source_sha256: str

    # What the email claims about itself.
    from_address: str
    display_name: str
    subject: str

    # SPF, DKIM and DMARC as the receiving server recorded them.
    authentication: AuthenticationResults

    # The route the email took, earliest hop first.
    received_hops: list[ReceivedHop]
    # Where the email appears to have come from, or None if no public IP was found.
    claimed_origin: ClaimedOrigin | None

    # What was pulled out of the email: URLs, link domains, then attachment hashes.
    observables: list[Observable]

    # Each attachment, described without opening it.
    attachments: list[Attachment]

    # Every Reputation Lookup made, and the Observables no Provider answered for.
    lookups: list[LookupResult]
    not_checked: list[NotChecked]

    # The outcome. The Verdict may have been raised from clean because
    # something was Not Checked; `verdict_before_cap` and `cap_reason` show that.
    findings: list[Finding]
    score: int
    verdict: Verdict
    verdict_before_cap: Verdict
    cap_reason: str
    warnings: list[str] = field(default_factory=list)

    # Reserved for MITRE ATT&CK mapping in a later phase.
    tags: list[str] = field(default_factory=list)
    format_version: int = FORMAT_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Return the report as plain data, ready to be written out as JSON."""
        data = asdict(self)
        data["analysed_at"] = self.analysed_at.isoformat()
        data["verdict"] = str(self.verdict)
        data["verdict_before_cap"] = str(self.verdict_before_cap)
        return data
