# 06: Wrapper Email detection and `--inner`

**Moved to:** https://github.com/GiacomoBarry/phishing-triage/issues/6 — GitHub is now the source of truth.

**What to build:** When the `.eml` is a Wrapper Email (a user's report with the suspected phish attached), the tool warns that it may be triaging the wrong email, and `--inner` triages the attached email instead.

**Blocked by:** 01

**Status:** resolved

- [x] An email containing an attached email produces a warning in the Triage Report and terminal view suggesting `--inner`
- [x] `--inner` triages the attached email; the Triage Report records that it was taken from inside a Wrapper Email, and the source SHA-256 is of the inner email
- [x] `--inner` on an email with no attached email exits with a clear error (exit code 3 or higher)
- [x] If there are several attached emails, the tool says so and `--inner` picks the first, noting this in the warnings
- [x] Core-seam and CLI tests cover plain email, Wrapper Email without and with `--inner`, and `--inner` with nothing inside

## Comments

2026-10-08: Resolved on `integration/06-wrapper-email` in 8882087 (warning, `--inner`, exit code 8) and 1e10737 (docs, ADR 0014), with review fixes in b134f47 (attached emails hashed as their original bytes), ea2713a (transfer encoding undone; a bad attached email is blamed, not the Wrapper Email), 5a17ea6 (core warnings name no CLI flag; the terminal view adds the `--inner` hint) and 11fd96b (docs). Decisions are in docs/adr/0014-attached-emails-are-message-rfc822-or-eml-files-one-level-deep.md. Follow-ups: Outlook `.msg` attachments are not treated as attached emails; a quoted-printable attached email comes back with LF line endings, so its hash may differ from the original file.
