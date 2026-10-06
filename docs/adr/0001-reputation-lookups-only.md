# Reputation lookups only, never submit or visit

The tool may only ask threat-intel providers what they already know about an Observable. It must never fetch a URL, open an attachment, or submit a URL or file for scanning. Submitting to a provider such as VirusTotal makes that provider visit the URL, which can tip off the attacker that a uniquely tracked link is being investigated, and makes the sample visible to other users. Asking a domain registry (RDAP) for a domain's creation date is allowed, because it never contacts the domain itself.

## Consequences

- Shortened URLs are never expanded by requesting them. Using a shortener is a Finding, and the short URL itself gets a Reputation Lookup. The shortener's own expand API may be added later as an optional provider.
- Obfuscated URLs (defanged text, HTML entities, SafeLinks-style wrappers) are decoded offline only, as text.
- A provider having no record of an Observable means "unknown", never "clean".
- Only attacker-side Observables are sent to providers: URLs, domains, the Claimed Origin IP and attachment hashes. Recipient addresses, subject lines and body text never leave the machine, because they would reveal who was targeted.
- Attachments are hashed whole and never unpacked. Archives, password-protected files and risky or double extensions are Findings based on what is visible without opening them.
