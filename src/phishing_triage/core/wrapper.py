"""Wrapper Emails: spotting an email attached inside the email being triaged.

A user who reports a phish often forwards it "as an attachment", so the
.eml the analyst saves is the user's report (a Wrapper Email), with the
real phish attached inside it. Triaging the report by mistake would judge
a colleague's email, not the phish.

An attached email counts if it is attached as an email (declared type
message/rfc822) or as a file whose name ends in .eml, which is how some
mail programs attach one. Only emails attached directly to this email
count, never ones attached inside an attached email (ADR 0014).
"""

from dataclasses import dataclass
from email.message import EmailMessage

from phishing_triage.core.attachments import attachment_parts, content_of, extension_of


@dataclass(frozen=True)
class AttachedEmail:
    """One email attached inside another, as raw bytes ready to be triaged."""

    filename: str  # As the Wrapper Email gives it, which may be empty.
    raw: bytes  # The same bytes that are hashed for its attachment SHA-256.


def find_attached_emails(message: EmailMessage) -> list[AttachedEmail]:
    """Return every email attached directly to this one, in the order they appear."""
    return [
        AttachedEmail(filename=part.get_filename() or "", raw=content_of(part))
        for part in attachment_parts(message)
        if part.get_content_type() == "message/rfc822" or extension_of(part.get_filename() or "") == "eml"
    ]
