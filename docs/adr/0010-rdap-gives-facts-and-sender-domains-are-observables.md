# RDAP answers carry a date, not a verdict, and sender domains become Observables

Ticket 13 looks up each domain's Registration Date: a sender or link domain registered fewer than 30 days ago (`[rdap] new_domain_days`) gives a 20-point Finding. Two choices shape it.

**RDAP's outcome is always Unknown (or Not Checked).** RDAP tells us facts, such as when a domain was registered, not whether it is malicious or clean. So the RDAP Provider never says malicious, suspicious or clean: its outcome is Unknown, the date goes in the evidence (`registered`, or `None` for unknown age), and the `newly_registered_domain` rule judges the age against the injected clock. The cache keeps the date, not the judgement, so a cached answer stays right as the domain ages. In the readable view this shows as `unknown (registered 1994-12-13)`, which reads oddly but is honest: RDAP has no opinion on reputation.

**The sender's domain is a new kind of Observable, Sender Domain.** Before, only link domains were Observables. Only RDAP looks Sender Domains up for now: VirusTotal and URLhaus would add a 16.5-second lookup to every email, and big free-mail domains collect the odd Engine detection (google.com has 2), which would add noise to legitimate emails. Sender Domains appear in the Triage Report and the Incident Note's IOCs, which helps with blocking. Like link domains, they don't count towards "clean requires evidence".

## Considered Options

- **A "clean" outcome for old domains**: would let an old domain count as evidence of safety, but age isn't reputation; plenty of phishing comes from old, compromised domains.
- **The sender's domain as an ordinary domain Observable**: simpler, but every Provider would look it up (slower and noisier), and the Lookalike Domain rule would describe it as a link domain.
- **A public-suffix list to find the registered domain**: exact, but another dependency. Instead the Provider trims labels until the registry recognises one (`login.evil.co.uk`, then `evil.co.uk`).

## Consequences

- Domains whose ending has no RDAP service (.de and .io, for example), or whose registry hides the date, are "unknown age": never new, never old, but shown with the reason.
- If a domain in an email isn't registered at all, the trimming can reach a bare second-level ending such as `co.uk` and report that ending's age. This is rare (an unregistered domain in a real email) and would at worst miss a Finding.
- RDAP asks IANA's bootstrap list once per run, then the domain's registry; the domain itself is never contacted (ADR 0001). Registries are asked at most 30 times a minute.
