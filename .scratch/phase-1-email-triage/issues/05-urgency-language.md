# 05: Urgency language

**Moved to:** https://github.com/GiacomoBarry/phishing-triage/issues/5 — GitHub is now the source of truth.

**What to build:** The tool flags emails that pressure the reader ("account suspended", "verify within 24 hours") using an editable list of phrases, behind the same rule interface as other Findings so a smarter checker could replace it later.

**Blocked by:** 02

**Status:** resolved

- [x] Settings hold an editable list of urgency phrases with sensible defaults
- [x] Urgency Finding (10 points) when the subject or body text (plain text, or HTML converted to text) contains a listed phrase, case-insensitively; evidence quotes the matched phrases
- [x] The Finding fires at most once per email, however many phrases match
- [x] Body text is only examined locally and never sent anywhere
- [x] Core-seam tests cover matches in subject, plain body and HTML body, mixed case, and no match

## Comments

2026-10-08: Resolved on `main` in 9e9cc00 (urgency language Finding with an editable Urgency Phrase list). Status line updated retrospectively; checklist confirmed against the commit and a green test suite (340 passed).
