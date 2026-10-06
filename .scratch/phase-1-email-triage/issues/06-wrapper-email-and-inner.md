# 06: Wrapper Email detection and `--inner`

**What to build:** When the `.eml` is a Wrapper Email (a user's report with the suspected phish attached), the tool warns that it may be triaging the wrong email, and `--inner` triages the attached email instead.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] An email containing an attached email produces a warning in the Triage Report and terminal view suggesting `--inner`
- [ ] `--inner` triages the attached email; the Triage Report records that it was taken from inside a Wrapper Email, and the source SHA-256 is of the inner email
- [ ] `--inner` on an email with no attached email exits with a clear error (exit code 3 or higher)
- [ ] If there are several attached emails, the tool says so and `--inner` picks the first, noting this in the warnings
- [ ] Core-seam and CLI tests cover plain email, Wrapper Email without and with `--inner`, and `--inner` with nothing inside
