# Phishing Triage

Analyses a single reported email the way an L1 SOC analyst would: pull out what's in it, check it against threat intelligence, apply red-flag rules, and reach a verdict with evidence.

## Language

### Analysis

**Triage**:
One end-to-end analysis of one email, ending in a Verdict.
_Avoid_: Scan, investigation

**Wrapper Email**:
An email that carries the suspected phish as an attachment, typically a user's report forwarded to a reporting mailbox. The tool treats any email with an email attached directly to it (declared as `message/rfc822`, or a file ending in `.eml`) as a possible Wrapper Email (ADR 0014).
_Avoid_: Report email, outer email, forward

**Observable**:
An artefact pulled from an email (an IP address, domain, URL, email address or file hash), with no judgement attached.
_Avoid_: Indicator, artefact, entity

**IOC**:
An Observable that has been judged malicious.
_Avoid_: Indicator, threat, bad observable

**Provider**:
An outside source a Reputation Lookup is made against, such as a threat-intel service or a domain registry.
_Avoid_: Feed, source, vendor, engine

**Engine**:
One of the many antivirus products or blocklists whose results a Provider such as VirusTotal collects. One Provider can have dozens of Engines behind it, and a Reputation Lookup reports how many of them flag an Observable.
_Avoid_: Provider, scanner, vendor

**Sender Domain**:
The domain of an email's From address, as an Observable in its own right. Only RDAP looks it up for now (ADR 0010).
_Avoid_: From domain (in code), sending domain

**Registration Date**:
When a domain was first registered, as published by its registry through RDAP. A domain whose registry hides or lacks it has an "unknown age", which never counts as new or old.
_Avoid_: Creation date, domain age (age is worked out from it)

**Reputation Lookup**:
Asking a Provider what it already knows about an Observable, without the Provider visiting or scanning it.
_Avoid_: Scan, submission, check

**Lookup Cap**:
The most URLs looked up in one Triage (`[lookups] url_cap`, 10 by default). URLs over it are Not Checked with the reason "over lookup cap", so they can't let the email be called clean.
_Avoid_: Limit, quota (those are the Provider's rate limits)

**Cached Lookup**:
A Reputation Lookup's answer reused from an earlier Triage instead of asking the Provider again. It is only reused while fresh (7 days if malicious, 24 hours otherwise) and is always marked with when it was fetched.
_Avoid_: Stale result, offline lookup

**Unknown**:
The outcome of a Reputation Lookup where the Provider has no record of the Observable, or has a record but nothing vouching for it either way (ADR 0006). It is never the same as clean.
_Avoid_: Clean, benign, no result

**Not Checked**:
The outcome for an Observable whose Reputation Lookup never happened, for example because a key was missing or the Provider failed.
_Avoid_: Unknown, skipped, error

**Hop**:
One mail server passing an email on, as recorded in one Received header: who sent it (the name it gave and the IP seen), which server received it, and when. The Received chain is the email's hops, earliest first.
_Avoid_: Relay (a Hop is the handover, not the server), step

**Claimed Origin**:
The IP address an email appears to have been sent from: the public IP a Trusted Relay recorded, or else the earliest public IP in the Received chain. Earlier Hops may be forged, so it is unverified unless a Trusted Relay recorded it (ADR 0011).
_Avoid_: Source IP, sender IP, origin

**Abuse Confidence**:
AbuseIPDB's 0–100% estimate, from other people's reports over the last 30 days, that an IP address is abusive. Only the Claimed Origin's is looked up; at or above the threshold setting (75% by default) it adds points (ADR 0012).
_Avoid_: Abuse score, IP reputation, risk score

**Trusted Relay**:
A mail server whose Received lines are believed genuine, normally the receiving organisation's own gateway. Listed in settings (`[received] trusted_relays`); subdomains count too.
_Avoid_: Trusted hop, gateway

**Authentication Results**:
What the receiving server recorded for SPF, DKIM and DMARC, read from the topmost Authentication-Results header and never re-checked. Each is pass, fail, another recorded value (such as softfail), or "not recorded", which is never treated as a fail.
_Avoid_: Auth check, authentication status, SPF check (the tool checks nothing itself)

**Protected Brand**:
An organisation attackers are expected to pretend to be, listed with the Protected Domains that are genuinely its own. Its name in a display name, sent from any other domain, is impersonation.
_Avoid_: Brand, watched brand

**Protected Domain**:
A domain that attackers are expected to imitate, such as the organisation's own domain or a commonly impersonated brand's. Its subdomains are treated as genuine too.
_Avoid_: Brand list, watched domain

**Lookalike Domain**:
A domain built to be mistaken for a Protected Domain, for example by swapping or adding characters.
_Avoid_: Typosquat, fake domain, spoofed domain

**Finding**:
The result of one red-flag rule firing against an email, carrying the evidence that triggered it.
_Avoid_: Alert, hit, flag, indicator

**Rule**:
A check for one red flag in an email. When it fires, it produces a Finding.
_Avoid_: Detector, signature, check

**Urgency Phrase**:
Wording that pressures the reader to act before thinking, such as "verify your account" or "within 24 hours". Kept in an editable list in settings; any in the subject or body adds points once per email.
_Avoid_: Urgency keyword, trigger word, pressure word

**Decisive Finding**:
A Finding strong enough to make the Verdict malicious on its own, whatever the Score.
_Avoid_: Override, critical finding

### Outcome

**Score**:
The total weight of the non-decisive Findings for one Triage.
_Avoid_: Risk score, rating

**Verdict**:
The conclusion of a Triage: malicious, suspicious or clean.
_Avoid_: Result, classification, disposition

**Triage Report**:
The structured record of one Triage: its Observables, Reputation Lookup results, Findings, Score and Verdict.
_Avoid_: Output, result, case

**Incident Note**:
A short plain-text summary of a Triage Report, written to be pasted into a ticket.
_Avoid_: Summary, ticket note, case note

**Recommended Action**:
A standard next step suggested in an Incident Note for a human to carry out, such as blocking a sender domain. The tool never performs it.
_Avoid_: Response, remediation, playbook step

### Evaluation

**Phish**:
A sample known to be a phishing email, kept under `samples/phish/` (from the phishing_pot dataset).
_Avoid_: Spam, malicious sample, positive

**Ham**:
A sample known to be legitimate email, kept under `samples/ham/` (from the SpamAssassin ham corpora). The usual name in spam filtering for "not spam".
_Avoid_: Clean email (clean is a Verdict), benign, negative

**Offline Evaluation**:
Running the rules over every Phish and Ham sample with no Providers, and counting the Verdict each gets from before the clean-requires-evidence cap (ADR 0015). It measures the rules and weights alone.
_Avoid_: Benchmark, test run, live evaluation (that one asks the real Providers)

**Unparseable Sample**:
A sample that isn't an email, so it gets no Verdict. Counted in the Offline Evaluation's table but left out of both rates.
_Avoid_: Error (that one is our fault), bad sample

**Error Sample**:
A sample the Offline Evaluation couldn't triage through no fault of the email: the file couldn't be read, or the core failed on it (usually a bug in a rule). Counted in its own column, apart from Unparseable Samples, and left out of both rates.
_Avoid_: Unparseable (that one is the email's fault), crash

**False-Positive Rate**:
The share of triaged Ham whose Verdict isn't clean: legitimate email an analyst would waste time on.
_Avoid_: Error rate, FP (spell it out)

**Missed-Phish Rate**:
The share of triaged Phish whose Verdict is clean: the dangerous mistake.
_Avoid_: False-negative rate, miss rate, detection rate (its opposite)
