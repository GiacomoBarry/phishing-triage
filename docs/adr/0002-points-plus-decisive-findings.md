# Verdicts use points plus Decisive Findings

Most Findings add weight to a Score, and thresholds turn the Score into a Verdict. A small set of Decisive Findings make the Verdict malicious on their own, whatever the Score: an attachment hash or URL flagged malicious by 3 or more VirusTotal engines, or a URL or domain listed on URLhaus. We chose this over pure points so that a confirmed IOC can never be outvoted by an otherwise clean-looking email. We also rejected letting every strong signal be decisive: DMARC failures and lookalike domains only add points, because they have legitimate explanations often enough.

## Consequences

- A Verdict of clean requires evidence. If any URL or attachment in the email could not be looked up (a missing API key, or a provider error), the best possible Verdict is suspicious, and the Incident Note says why.
