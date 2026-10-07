# VirusTotal "clean" needs an engine to vouch for a URL or domain

VirusTotal reports what each of its Engines said about an Observable: malicious, suspicious, harmless or undetected. We treat a file hash with no malicious detections as clean, because antivirus Engines scan the file's bytes, so "undetected" is a real verdict. But a URL or domain with no detections is only clean if at least one Engine says "harmless"; otherwise it is Unknown. For URLs and domains most Engines are blocklists, and "undetected" only means "not on my list".

This matters because looking a domain up on VirusTotal makes it create a record if it has none. While capturing test fixtures, a made-up domain answered 404 the first time and, a minute later, 200 with all 92 Engines "undetected", none "harmless", a fresh DNS lookup and a `dga` tag. Calling that clean would turn "VirusTotal knew nothing until we asked" into reassurance, which breaks the rule that Unknown is never clean.

## Considered Options

- **No detections is clean, for every kind**: simplest, but brand-new attacker domains would read as clean.
- **Compare `first_seen_date` with the lookup time**: catches only records created by our own lookup, not ones another user's lookup created minutes earlier, and depends on clocks.

## Consequences

- New or obscure URLs and domains come back Unknown more often. Domains don't count towards "clean requires evidence", and Unknown is still a real answer for URLs, so this doesn't raise Verdicts. It only makes the Triage Report more honest.
- A domain lookup has a side effect on VirusTotal's side: a first-time domain gets a record and a DNS lookup from VirusTotal's systems. This is still within ADR 0001, because nothing visits a URL and nothing is submitted for scanning. Note, though, that an attacker watching their DNS could see that someone looked their domain up.
- The decisive Engine count (`[virustotal] decisive_engines`, default 3) is applied inside the Provider, so a lookup's outcome depends on the settings. The cache (ticket 14) must store the Engine counts, not just the outcome, or changing the setting would leave stale answers.
