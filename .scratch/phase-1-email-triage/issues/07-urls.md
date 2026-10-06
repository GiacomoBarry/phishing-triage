# 07: URLs: extraction, offline decoding, shorteners and link Lookalikes

**What to build:** The tool finds every link in the email, decodes obfuscated links offline to their real destinations, flags shorteners and lookalike link domains, and lists the URLs as defanged IOCs in the Incident Note. It never fetches, follows or expands any URL (ADR 0001).

**Blocked by:** 04

**Status:** ready-for-agent

- [ ] URLs are extracted from plain-text and HTML parts (link targets and visible text), de-duplicated, and recorded as Observables along with their domains
- [ ] Offline decoding as text only: defanged forms (`hxxp`, `[.]`), HTML entities, and SafeLinks-style wrappers whose real URL sits in a query parameter
- [ ] Settings hold an editable list of shortener domains; a URL shortener Finding (10 points) fires once per email with evidence listing the shortened URLs; shortened URLs are never expanded
- [ ] Link domains that are Lookalike Domains of a Protected Domain produce the Lookalike Domain Finding with evidence (reusing ticket 04's detection; one Finding per distinct imitated domain is fine)
- [ ] The Incident Note gains a defanged IOCs section; nothing in the note or terminal view is a clickable live URL
- [ ] A test proves no network access happens during URL handling
- [ ] Core-seam tests cover each decoding form, HTML-only links, shorteners, link lookalikes and de-duplication
