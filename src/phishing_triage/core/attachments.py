"""Attachments: what can be learnt about them without opening them.

Each attachment is hashed whole, in memory. Nothing is unpacked, extracted,
executed or written to disk (ADR 0001). Spotting an archive uses only its
name, its declared type and its first few bytes; spotting a password-protected
ZIP reads only the ZIP's table of contents, never the files inside.
"""

import hashlib
import io
import re
import unicodedata
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

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


def extract_attachments(raw_email: bytes) -> list[Attachment]:
    """Describe every attachment in the email, in the order they appear."""
    return [_describe(part) for part in attachment_parts(raw_email)]


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


def attachment_parts(raw_email: bytes) -> Iterator[EmailMessage]:
    """Yield each attachment part of the email, without looking inside attached emails.

    A part counts if it is marked as an attachment, has a filename (so an
    .exe marked "inline" can't slip past), or is an attached email.

    The email is walked from its raw bytes, not from Python's parsed email,
    because the parser rebuilds an attached email (changing line endings,
    decoding headers, refolding them), and its hash must be of the bytes
    exactly as they were sent (ADR 0014). Each part is parsed for its
    headers only, so its body stays as the original bytes.
    """
    yield from _attachment_parts(raw_email, is_top=True)


def _attachment_parts(raw_part: bytes, is_top: bool) -> Iterator[EmailMessage]:
    part = BytesParser(policy=policy.default).parsebytes(raw_part, headersonly=True)
    assert isinstance(part, EmailMessage)  # guaranteed by policy.default
    is_attached_email = part.get_content_type() == "message/rfc822"
    if not is_top and (part.is_attachment() or part.get_filename() or is_attached_email):
        yield part
        return
    boundary = part.get_boundary()
    if part.get_content_maintype() == "multipart" and boundary:
        for sub_part in _split_multipart(content_of(part), boundary):
            yield from _attachment_parts(sub_part, is_top=False)


def _split_multipart(body: bytes, boundary: str) -> list[bytes]:
    """Split a multipart body into the raw bytes of each part.

    Each part starts after a line "--boundary" and ends just before the next
    one. The line break before "--boundary" belongs to the boundary, not the
    part (RFC 2046). The line "--boundary--" closes the last part; anything
    after it is ignored.
    """
    delimiter = re.compile(
        rb"(?:\r?\n)?^--" + re.escape(boundary.encode("ascii", "replace")) + rb"(?P<close>--)?[ \t]*(?:\r?\n|$)",
        re.MULTILINE,
    )
    delimiters = list(delimiter.finditer(body))
    parts = []
    for number, current in enumerate(delimiters):
        if current.group("close"):
            break
        is_last = number + 1 == len(delimiters)
        end = len(body) if is_last else delimiters[number + 1].start()
        parts.append(body[current.end() : end])
    return parts


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
    """Return a part's body bytes, decoded from the email's transfer encoding (such as base64).

    `part` must come from attachment_parts(), so its body is still the
    original bytes: for an attached email, the email exactly as it was sent.
    """
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
