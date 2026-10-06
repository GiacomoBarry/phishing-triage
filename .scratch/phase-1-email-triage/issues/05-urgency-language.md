# 05: Urgency language

**What to build:** The tool flags emails that pressure the reader ("account suspended", "verify within 24 hours") using an editable list of phrases, behind the same rule interface as other Findings so a smarter checker could replace it later.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Settings hold an editable list of urgency phrases with sensible defaults
- [ ] Urgency Finding (10 points) when the subject or body text (plain text, or HTML converted to text) contains a listed phrase, case-insensitively; evidence quotes the matched phrases
- [ ] The Finding fires at most once per email, however many phrases match
- [ ] Body text is only examined locally and never sent anywhere
- [ ] Core-seam tests cover matches in subject, plain body and HTML body, mixed case, and no match
