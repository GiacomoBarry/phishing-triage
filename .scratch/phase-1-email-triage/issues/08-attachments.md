# 08: Attachments: hashes and attachment Findings

**Moved to:** https://github.com/GiacomoBarry/phishing-triage/issues/8 — GitHub is now the source of truth.

**What to build:** The tool lists each attachment with its hashes and flags dangerous-looking attachments, using only what is visible without opening or unpacking them (ADR 0001).

**Blocked by:** 02

**Status:** resolved

- [x] Each attachment is recorded with filename, declared type, size, and SHA-256, MD5 and SHA-1 of the whole file; the hashes are Observables
- [x] Settings hold an editable list of risky extensions
- [x] Attachment Finding (25 points) for risky extensions, double extensions (such as `.pdf.exe`), archives, and password-protected archives (from the zip's encryption flag only), with evidence naming the file and reason
- [x] Attachments are never unpacked, extracted, executed or written to disk
- [x] Attachment hashes appear in the Incident Note's defanged IOCs section
- [x] Core-seam tests cover a benign attachment, each Finding reason, an encrypted zip, and correct hashes for a known fixture

## Comments

**2026-10-07, implemented.** Notes for later tickets:

- `core/attachments.py` describes each attachment as an `Attachment` (filename, declared type, size, SHA-256, MD5, SHA-1, `archive_type`, `password_protected`), in the report as `attachments` and in `RuleInput.attachments`. Hashing is in memory; nothing is opened, unpacked or written to disk, and a test fails if a file is opened or a ZIP's contents are read.
- Agreed with the maintainer: only SHA-256 becomes an Observable (`ObservableKind.SHA256`), de-duplicated across identical files. MD5 and SHA-1 stay on the `Attachment` for Providers that need them (tickets 09 and 10).
- Agreed with the maintainer: one Finding per email (25 points), naming every flagged file and its reasons, so three bad files don't stack to 75. The decisive signal will come from VirusTotal hash detections (ticket 10).
- Agreed with the maintainer: the ZIP encryption flag is read with `zipfile`'s table of contents only (every entry checked, nothing decompressed). RAR and 7z encryption isn't detected.
- Archives are spotted by first bytes, then extension, then declared type, so a ZIP renamed to `.pdf` counts. Office/OpenDocument files (ZIPs inside) are excluded. The archive lists are built in, not settings; only risky extensions are configurable, as the ticket asks.
- What counts as an attachment: any part marked as one, any part with a filename (so an inline `.exe` counts), and attached emails (`message/rfc822`), hashed whole and not opened; ticket 06 decides about looking inside.
- Extras beyond the ticket: hidden formatting characters in a filename (the right-to-left override trick) are a reason, and filenames are printed with control characters escaped everywhere. A double extension needs a risky last extension after a document-looking one (`DECOY_EXTENSIONS` in `core/rules.py`), and padding spaces are ignored.
- The ticket says hashes appear in the "defanged IOCs section"; following ticket 07, that section is "Observables (defanged)" until lookups can judge anything malicious. Each SHA-256 line names its file(s).
