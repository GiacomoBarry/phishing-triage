"""Wrapper Emails: spotting an email attached inside the email being triaged.

A user who reports a phish often forwards it "as an attachment", so the
.eml the analyst saves is a Wrapper Email: the user's own email, with the
real phish attached inside it. Triaging the Wrapper Email by mistake would
judge a colleague's email, not the phish.

An attached email counts if it is attached as an email (declared type
message/rfc822) or as a file whose name ends in .eml, which is how some
mail programs attach one. Only emails attached directly to this email
count, never ones attached inside an attached email (ADR 0014).
"""

from phishing_triage.core.attachments import attachment_parts, content_of, extension_of


def find_attached_emails(raw_email: bytes) -> list[bytes]:
    """Return the raw bytes of every email attached directly to this one, in the order they appear.

    Each is exactly as it was sent (only a transfer encoding such as base64
    is undone), so its SHA-256 matches its attachment hash, and the same
    email saved straight to disk as a .eml file.
    """
    return [
        content_of(part)
        for part in attachment_parts(raw_email)
        if is_attached_email(part.get_content_type(), part.get_filename() or "")
    ]


def is_attached_email(content_type: str, filename: str) -> bool:
    """Is an attachment with this declared type and filename an attached email?"""
    return content_type == "message/rfc822" or extension_of(filename) == "eml"
