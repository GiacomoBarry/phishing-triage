# Trust only headers added after the email reached us

Ticket 03 reads the Authentication Results and the Received chain. Both are headers, and the sender can write any header they like before sending. Real mail servers add their headers at the top, so anything the sender wrote always sits below them. Every choice here follows from that.

**Authentication Results come from the topmost Authentication-Results header only.** That is the one the delivering server added last. A lower one may have been planted, for example a fake `dmarc=pass`. The report names the server that recorded it (`recorded_by`), so the analyst can tell if it isn't their own. Microsoft 365 leaves out its name and starts straight with `spf=…`, so a first clause that is a check is read as one, and the recorder is "an unnamed server". Missing checks are "not recorded", which never gives a fail Finding. Results are never re-checked with live DNS: the DNS records may have changed since delivery, and the receiving server's decision then is the one that mattered.

**Without Trusted Relays, the Claimed Origin is the earliest public IP, labelled unverified.** Private and reserved addresses (anything Python's `ipaddress` says isn't global) are skipped. This picks whatever the bottom Hop says, which the sender could have forged. That's why it's labelled unverified and not quietly trusted.

**With Trusted Relays, start from the topmost Hop a Trusted Relay added, and stop at the first public IP.** The walk moves down past a trusted Hop only if it shows the email came from the organisation's own servers: it recorded a private IP (another internal server handed it on), or no sender at all (delivery within one server, such as `by gw.example.com with LMTP`). A Hop naming a sender whose IP couldn't be read stops the walk. It stops at the first public IP a Trusted Relay recorded, and that IP is the Claimed Origin, labelled verified. Continuing simply "while the Hop names a Trusted Relay" would follow a header the sender planted saying `by gw.example.com` just below the real one. If no Trusted Relay recorded a public IP (an internal email, say), it falls back to the unverified rule.

**A Trusted Relay matches its name or any subdomain, ignoring case.** This is the same rule as Protected Domains and shorteners. It copes with cloud mail services whose server names change, for example `protection.outlook.com` for Microsoft 365.

## Considered Options

- **Prefer the Authentication-Results header from a Trusted Relay**: harder to fool with a planted header, but more logic. The topmost header is already the delivering server's, and naming who recorded it lets the analyst judge.
- **Exact Trusted Relay names only**: stricter, but every one of a cloud provider's many server names would have to be listed.
- **The IP in the server's greeting (HELO) or the first IP in the line**: simpler parsing, but the sender chooses its greeting. The parser prefers the bracketed IP in the comment, which is what the receiving server saw, and ignores `helo=`.

## Consequences

- With no Trusted Relays configured (the default), the Claimed Origin is always unverified. That's honest, but a forged bottom Hop can name any public IP. Ticket 12 looks this IP up on AbuseIPDB, so its Finding must say the origin is unverified.
- Received headers are written in many slightly different ways. Parsing is best effort, and anything it can't find is left blank. The whole header is kept in the Triage Report so the analyst can check.
- An email that reached the recipient without passing any Trusted Relay, perhaps through a misconfiguration, could have a planted "trusted" Hop believed. Trusted Relays should be the servers every inbound email passes through.
