# 04: Display-name impersonation and sender Lookalike Domains

**What to build:** The tool spots emails pretending to be a well-known organisation: a display name claiming a Protected brand while the sending domain isn't theirs, and sender domains that are Lookalike Domains of Protected Domains.

**Blocked by:** 02

**Status:** resolved

- [x] Settings hold an editable list of Protected Domains and brand names (defaults include Microsoft, Google, PayPal, Apple, Amazon, DHL, HMRC, Royal Mail)
- [x] Display-name impersonation Finding (25 points) when the display name names a Protected brand and the sending domain isn't one of that brand's domains, with evidence naming both
- [x] Lookalike Domain Finding (30 points) when the sender domain imitates a Protected Domain (for example character swaps such as `paypa1.com`, extra words such as `paypal-secure.xyz`), with evidence naming the imitated domain
- [x] A genuine Protected Domain (or its subdomains) never triggers either Finding
- [x] Lookalike detection is usable by later rules for other domains (link domains in ticket 07)
- [x] Core-seam tests cover genuine brand senders, impersonators, several lookalike techniques and near-misses that should not fire

## Comments

**2026-10-07, implemented.** Notes for later tickets:

- Protected Brands live in a `[brands]` table in `settings.toml`: brand name = list of genuine domains. Protected Domains are all of those together (`Settings.protected_domains`). An analyst's own organisation is added as one more brand. Free webmail (gmail.com, outlook.com, live.com, icloud.com) is deliberately not listed as genuine.
- For ticket 07: call `imitated_domain(domain, settings.protected_domains)` from `core/lookalike.py`. It returns a `Lookalike` (imitated domain and a technique phrase that reads after "it") or None, and already ignores genuine domains and subdomains. `is_genuine()` is there too.
- Techniques and limits are in ADR 0004. Agreed with the maintainer: the same name on another ending (`paypal.xyz`) fires, one-letter-off only applies to names of 5+ letters, and `xn--` domains are decoded so Cyrillic lookalikes are caught.
- Display-name impersonation gives one Finding per email, for the first brand named, so a display name naming two brands can't score twice.
- For ticket 16, real domains that currently fire: `amazon.de`, `apple.news`, `royalmail.group`, `paypal-communication.com` (reuse/extra words) and `apply-now.co.uk` (one letter off Apple). `paypalsecure.com` (no hyphen) is a known miss. `dhl.de` was added to the defaults.
- Not done: the `Sender` type suggested in ticket 01's review. The rules only need the From display name and domain, read by `_sender_display_name_and_domain` in `core/rules.py`; revisit if more sender logic arrives.
