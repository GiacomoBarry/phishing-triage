# Phishing Triage

Analyses a single reported email the way an L1 SOC analyst would: pull out what's in it, check it against threat intelligence, apply red-flag rules, and reach a verdict with evidence.

## Language

### Analysis

**Triage**:
One end-to-end analysis of one email, ending in a Verdict.
_Avoid_: Scan, investigation

**Wrapper Email**:
An email that carries the suspected phish as an attachment, typically a user's report forwarded to a reporting mailbox.
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

**Reputation Lookup**:
Asking a Provider what it already knows about an Observable, without the Provider visiting or scanning it.
_Avoid_: Scan, submission, check

**Unknown**:
The outcome of a Reputation Lookup where the Provider has no record of the Observable. It is never the same as clean.
_Avoid_: Clean, benign, no result

**Not Checked**:
The outcome for an Observable whose Reputation Lookup never happened, for example because a key was missing or the Provider failed.
_Avoid_: Unknown, skipped, error

**Claimed Origin**:
The earliest public IP address in an email's Received chain. Earlier hops may be forged, so it is unverified unless a Trusted Relay recorded it.
_Avoid_: Source IP, sender IP, origin

**Trusted Relay**:
A mail server whose Received lines are believed genuine, normally the receiving organisation's own gateway.
_Avoid_: Trusted hop, gateway

**Protected Domain**:
A domain that attackers are expected to imitate, such as the organisation's own domain or a commonly impersonated brand.
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
