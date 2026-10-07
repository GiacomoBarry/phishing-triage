# Pace each Provider with a margin, and stop asking it after a Provider-wide failure

The spec says each Provider's rate limit is respected "by waiting rather than failing". We do that by pacing in advance: every Provider states its `lookups_per_minute` (VirusTotal 4, its free-tier limit; URLhaus 30, a gentle pace, because abuse.ch publishes no limit but restricts heavy accounts for up to 72 hours). The core keeps lookups to each Provider at least 60 ÷ that number seconds apart, plus a 10% margin so network delays can't squeeze a fifth lookup into VirusTotal's minute.

When a Provider answers in a way that will affect every lookup (it can't be reached, there's no key, the key is rejected, it says it's rate limited, or it crashes), it sets `stop_asking`. The rest of its lookups in that Triage are Not Checked for the same reason, without asking it or waiting for it. A 429 is not retried.

## Considered Options

- **Retry a 429 after waiting**: closest to "waiting rather than failing", but VirusTotal's 429 also covers the 500-a-day quota, where waiting a minute won't help, and retrying burns quota abuse.ch might count against us. Pacing in advance should mean a 429 never happens.
- **Keep asking after a failure**: one unreachable Provider made a one-link email take 30 seconds (two 15-second timeouts), and a no-key VirusTotal made the test suite take 109 seconds by waiting between instant "no API key" answers.
- **Per-Provider rates in the settings file**: would suit a paid VirusTotal key, but nobody needs it yet.

## Consequences

- A link-heavy email is slow on a free VirusTotal key (about 16.5 seconds per lookup after the first), but every lookup gets a real answer. Progress lines show the waits. The cache (ticket 14) is what makes re-runs fast.
- One Provider-wide failure costs the rest of that Provider's lookups for this email. They are visible as Not Checked, so the email can't be called clean on missing evidence. The progress output says "Not asking VirusTotal again: …" so the jump in lookup numbers is explained.
- A cache hit must not wait its turn: ticket 14 should check the cache before pacing.
