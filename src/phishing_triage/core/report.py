"""The Triage Report: the structured record of one Triage.

This module is the one place the report's format is defined. Bump
FORMAT_VERSION whenever a field is renamed or removed, so that older saved
reports can still be interpreted.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

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

    # The outcome.
    score: int
    verdict: Verdict
    warnings: list[str] = field(default_factory=list)

    # Reserved for MITRE ATT&CK mapping in a later phase.
    tags: list[str] = field(default_factory=list)
    format_version: int = FORMAT_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Return the report as plain data, ready to be written out as JSON."""
        data = asdict(self)
        data["analysed_at"] = self.analysed_at.isoformat()
        data["verdict"] = str(self.verdict)
        return data
