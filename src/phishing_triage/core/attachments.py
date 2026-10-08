"""Attachments: what can be learnt about them without opening them.

Each attachment is hashed whole, in memory. Nothing is unpacked, extracted,
executed or written to disk (ADR 0001). Spotting an archive uses only its
name, its declared type and its first few bytes; spotting a password-protected
ZIP reads only the ZIP's table of contents, never the files inside.
"""

import hashlib
import io
import unicodedata
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from email.message import EmailMessage

# The first bytes ("magic bytes") that identify common archive formats,
# whatever the file is called.
ARCHIVE_SIGNATURES = (
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),  # An empty ZIP.
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"MSCF", "cab"),
)

ARCHIVE_EXTENSIONS = frozenset(
    {"zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "cab", "arj", "ace", "lzh"}
)

ARCHIVE_TYPES = frozenset(
    {
        "application/zip",
        "application/x-zip-compressed",
        "application/vnd.rar",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/gzip",
        "application/x-gzip",
        "application/x-tar",
        "application/x-bzip2",
        "application/vnd.ms-cab-compressed",
    }
)

# Everyday formats that are ZIP files inside (Office, OpenDocument, ebooks).
# They start with ZIP's magic bytes but are not archives to an analyst.
ZIP_BASED_DOCUMENTS = frozenset(
    {"docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "odt", "ods", "odp", "epub", "vsdx"}
)


@dataclass(frozen=True)
class Attachment:
    """One attachment, described from the outside."""

    filename: str  # As the email gives it, which may be empty.
    content_type: str  # As the email declares it. The sender chooses this, so it can lie.
    size: int  # In bytes.
    sha256: str
    md5: str
    sha1: str
    archive_type: str  # Such as "zip" or "rar", or "" if it isn't an archive.
    password_protected: bool  # Only ever True for ZIPs, the one format we can check.


def extract_attachments(message: EmailMessage) -> list[Attachment]:
    """Describe every attachment in the email, in the order they appear."""
    return [_describe(part) for part in attachment_parts(message)]


def extension_of(filename: str) -> str:
    """Return a filename's last extension, lowercased, without the dot ("" if none)."""
    segments = _segments(filename)
    return segments[-1] if len(segments) > 1 else ""


def previous_extension_of(filename: str) -> str:
    """Return the extension before the last one ("pdf" in "invoice.pdf.exe"), or ""."""
    segments = _segments(filename)
    return segments[-2] if len(segments) > 2 else ""


def has_hidden_characters(filename: str) -> bool:
    """Does the filename contain invisible formatting characters?

    The right-to-left override (U+202E) placed before "gpj.exe" in
    "invoice[U+202E]gpj.exe" makes it display as "invoiceexe.jpg", hiding
    the real extension.
    """
    return any(unicodedata.category(character) == "Cf" for character in filename)


def display_filename(filename: str) -> str:
    """Return a filename safe to print: control and invisible characters are escaped.

    Without this, a crafted filename could reverse or scramble the text
    around it in the terminal or in a ticket.
    """
    if not filename:
        return "(no filename)"
    return "".join(
        f"\\u{ord(character):04x}" if unicodedata.category(character).startswith("C") else character
        for character in filename
    )


def attachment_parts(part: EmailMessage, is_top: bool = True) -> Iterator[EmailMessage]:
    """Yield each attachment part without looking inside attached emails.

    A part counts if it is marked as an attachment, has a filename (so an
    .exe marked "inline" can't slip past), or is an attached email.
    """
    is_attached_email = part.get_content_type() == "message/rfc822"
    if not is_top and (part.is_attachment() or part.get_filename() or is_attached_email):
        yield part
        return
    if part.is_multipart():
        for sub_part in part.iter_parts():
            assert isinstance(sub_part, EmailMessage)  # guaranteed by policy.default
            yield from attachment_parts(sub_part, is_top=False)


def _describe(part: EmailMessage) -> Attachment:
    content = content_of(part)
    filename = part.get_filename() or ""
    archive_type = _archive_type(content, filename, part.get_content_type())
    return Attachment(
        filename=filename,
        content_type=part.get_content_type(),
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        # MD5 and SHA-1 are broken for security, but some Providers still look files up by them.
        md5=hashlib.md5(content, usedforsecurity=False).hexdigest(),
        sha1=hashlib.sha1(content, usedforsecurity=False).hexdigest(),
        archive_type=archive_type,
        password_protected=archive_type == "zip" and _zip_is_encrypted(content),
    )


def content_of(part: EmailMessage) -> bytes:
    """Return the attachment's bytes, decoded from the email's transfer encoding."""
    if part.get_content_type() == "message/rfc822":
        attached_email = part.get_payload(0)
        return attached_email.as_bytes() if hasattr(attached_email, "as_bytes") else b""
    payload = part.get_payload(decode=True)
    return payload if isinstance(payload, bytes) else b""


def _archive_type(content: bytes, filename: str, content_type: str) -> str:
    """Name the archive format, judged by first bytes, then extension, then declared type."""
    extension = extension_of(filename)
    for signature, archive_type in ARCHIVE_SIGNATURES:
        if content.startswith(signature):
            if archive_type == "zip" and extension in ZIP_BASED_DOCUMENTS:
                return ""
            return archive_type
    if extension in ARCHIVE_EXTENSIONS:
        return extension
    if content_type in ARCHIVE_TYPES:
        return content_type.split("/")[1]
    return ""


def _zip_is_encrypted(content: bytes) -> bool:
    """Is any file in the ZIP marked as encrypted?

    Opening a ZipFile reads only the table of contents at the end of the
    file. Nothing is decompressed, so even a "zip bomb" is harmless here.
    Bit 0 of each entry's flags means "this file is encrypted".
    """
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            return any(entry.flag_bits & 0x1 for entry in archive.infolist())
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, EOFError):
        return False


def _segments(filename: str) -> list[str]:
    """Split a filename on dots, ignoring invisible characters, spaces and case."""
    visible = "".join(c for c in filename if unicodedata.category(c) != "Cf")
    return [segment.strip().lower() for segment in visible.split(".")]
