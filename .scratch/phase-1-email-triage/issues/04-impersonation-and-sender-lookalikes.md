# 04: Display-name impersonation and sender Lookalike Domains

**What to build:** The tool spots emails pretending to be a well-known organisation: a display name claiming a Protected brand while the sending domain isn't theirs, and sender domains that are Lookalike Domains of Protected Domains.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Settings hold an editable list of Protected Domains and brand names (defaults include Microsoft, Google, PayPal, Apple, Amazon, DHL, HMRC, Royal Mail)
- [ ] Display-name impersonation Finding (25 points) when the display name names a Protected brand and the sending domain isn't one of that brand's domains, with evidence naming both
- [ ] Lookalike Domain Finding (30 points) when the sender domain imitates a Protected Domain (for example character swaps such as `paypa1.com`, extra words such as `paypal-secure.xyz`), with evidence naming the imitated domain
- [ ] A genuine Protected Domain (or its subdomains) never triggers either Finding
- [ ] Lookalike detection is usable by later rules for other domains (link domains in ticket 07)
- [ ] Core-seam tests cover genuine brand senders, impersonators, several lookalike techniques and near-misses that should not fire
