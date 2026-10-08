# 07: URLs: extraction, offline decoding, shorteners and link Lookalikes

**What to build:** The tool finds every link in the email, decodes obfuscated links offline to their real destinations, flags shorteners and lookalike link domains, and lists the URLs as defanged IOCs in the Incident Note. It never fetches, follows or expands any URL (ADR 0001).

**Blocked by:** 04

**Status:** resolved

- [x] URLs are extracted from plain-text and HTML parts (link targets and visible text), de-duplicated, and recorded as Observables along with their domains
- [x] Offline decoding as text only: defanged forms (`hxxp`, `[.]`), HTML entities, and SafeLinks-style wrappers whose real URL sits in a query parameter
- [x] Settings hold an editable list of shortener domains; a URL shortener Finding (10 points) fires once per email with evidence listing the shortened URLs; shortened URLs are never expanded
- [x] Link domains that are Lookalike Domains of a Protected Domain produce the Lookalike Domain Finding with evidence (reusing ticket 04's detection; one Finding per distinct imitated domain is fine)
- [x] The Incident Note gains a defanged IOCs section; nothing in the note or terminal view is a clickable live URL
- [x] A test proves no network access happens during URL handling
- [x] Core-seam tests cover each decoding form, HTML-only links, shorteners, link lookalikes and de-duplication

## Comments

**2026-10-07, implemented.** Notes for later tickets:

- Rules now take `(rule_input, settings)`. `RuleInput` (in `core/findings.py`) holds the parsed message and the Observables; `rule_input.values(ObservableKind.URL)` gives the values of one kind. Ticket 09 should add lookup results to `RuleInput` rather than changing the rule shape again.
- Observables are `Observable(kind, value)` in `core/observables.py`, in the report as `observables`: URLs first (in the order found, de-duplicated, scheme and host lowercased), then each URL's domain. IP-address hosts give no domain Observable; ticket 03 adds IP Observables. Not a format-version bump, since only a field was added.
- **Deviation from the ticket wording, agreed reasoning:** the Incident Note section is "Observables (defanged)", not "IOCs", because GLOSSARY defines an IOC as an Observable judged malicious, and nothing is judged until lookups arrive. Once ticket 09 lands, consider splitting it into IOCs (judged malicious) and other Observables.
- The Lookalike Domain rule now covers sender and link domains together, with one Finding per imitated Protected Domain (agreed with the maintainer), so the same brand isn't scored twice.
- Agreed with the maintainer: `<img src>` addresses are not extracted (mostly tracking pixels, which would use up ticket 11's URL cap). Revisit in ticket 16.
- Link wrappers recognised: Microsoft SafeLinks (`url=`) and Google redirects (`google.com/url?q=`), nested up to 5 deep (`LINK_WRAPPERS` in `core/urls.py`). Proofpoint URL Defense uses its own encoding and isn't decoded yet; add it if the datasets show it.
- URLs inside attached emails (`message/rfc822`) are not read; ticket 06 decides which email gets triaged.
- Idea for a later rule: an HTML link whose visible text is one URL but whose target is another (for example text `https://www.paypal.com/signin`, target `paypa1.com`) is a strong phishing sign. Both are recorded as Observables, but nothing compares them yet.
- Settings validation now checks each fixed key against the type of its shipped default (whole number or list of domains), which list settings in tickets 03, 05 and 08 can reuse.
