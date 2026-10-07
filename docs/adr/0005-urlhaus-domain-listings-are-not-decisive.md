# A URLhaus listing is decisive for a URL, but not for a domain

The spec made any URLhaus listing of a URL or a domain a Decisive Finding. We changed that for domains: a listed URL is still decisive, but a domain with listed URLs gives a non-decisive Finding worth 20 points, with the number of listed and still-online URLs as evidence. URLhaus lists malware URLs by host, and attackers routinely host payloads on shared platforms such as `github.com`, `drive.google.com` and `dropbox.com`. A domain lookup for those comes back listed, so a decisive domain listing would mark every email that links to GitHub as malicious, and analysts would soon stop trusting the Verdict.

## Considered Options

- **Decisive domain listings, as specified**: catches attacker-owned domains outright, but with constant false positives on shared platforms.
- **Decisive unless the domain is on a "shared platforms" list in settings**: closer to the spec, but the list would never be complete, and a missing entry silently brings the false positives back.

## Consequences

- An attacker-owned domain with listed URLs no longer makes the Verdict malicious on its own; it needs other Findings (for example a Lookalike Domain or a risky attachment) to reach malicious. The listed URL itself, when it appears in the email, is still decisive.
- The 20 points are a starting guess, to be tuned in the dataset evaluation (ticket 16).
