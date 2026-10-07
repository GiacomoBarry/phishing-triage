# VirusTotal detections are decisive for a URL or hash, but not for a domain

Ticket 10 said three or more VirusTotal Engines flagging an Observable is a Decisive Finding, but the spec only lists attachment hashes and URLs as decisive for VirusTotal. We followed the spec: a domain flagged by any number of Engines gives the 15-point `virustotal_low_detections` Finding instead. The reason is the same as for URLhaus domains ([ADR 0005](0005-urlhaus-domain-listings-are-not-decisive.md)). Engines flag a domain for what anyone hosts on it, and shared platforms collect detections: when the fixtures were captured, even google.com had 2. A decisive domain hit would make every email linking to a popular platform malicious.

## Considered Options

- **Decisive at the threshold for domains too, as the ticket said**: catches attacker-owned domains outright, but one more Engine on google.com, GitHub or Dropbox would make every link to them decisive.
- **A separate domain Finding with its own points, like `urlhaus_domain_listed`**: more tunable, but another setting to justify before the dataset evaluation has shown it's needed.

## Consequences

- An attacker-owned domain flagged by many Engines no longer makes the Verdict malicious on its own; it needs other Findings. A flagged URL or attachment in the same email is still decisive.
- A domain flagged by 16 Engines and one flagged by 1 are worth the same 15 points. Whether that needs splitting is a question for the dataset evaluation (ticket 16).
