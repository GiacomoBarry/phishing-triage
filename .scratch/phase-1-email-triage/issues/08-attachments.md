# 08: Attachments: hashes and attachment Findings

**What to build:** The tool lists each attachment with its hashes and flags dangerous-looking attachments, using only what is visible without opening or unpacking them (ADR 0001).

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Each attachment is recorded with filename, declared type, size, and SHA-256, MD5 and SHA-1 of the whole file; the hashes are Observables
- [ ] Settings hold an editable list of risky extensions
- [ ] Attachment Finding (25 points) for risky extensions, double extensions (such as `.pdf.exe`), archives, and password-protected archives (from the zip's encryption flag only), with evidence naming the file and reason
- [ ] Attachments are never unpacked, extracted, executed or written to disk
- [ ] Attachment hashes appear in the Incident Note's defanged IOCs section
- [ ] Core-seam tests cover a benign attachment, each Finding reason, an encrypted zip, and correct hashes for a known fixture
