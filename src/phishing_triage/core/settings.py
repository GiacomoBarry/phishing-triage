"""Settings that tune a Triage.

The values themselves live in a settings file (see phishing_triage.config),
so they can be tuned without editing code. The core is simply handed a
Settings object.
"""

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Tunable values for a Triage. Loaded by the CLI and passed in to the core."""

    # Points each kind of Finding adds to the Score, keyed by rule identifier.
    points: Mapping[str, int]

    # The lowest Score that gives each Verdict. Anything lower is clean.
    suspicious_from: int
    malicious_from: int

    # Protected Brands: each brand name, as it would appear in a display name,
    # with the domains that are genuinely theirs (their Protected Domains).
    brands: Mapping[str, tuple[str, ...]]

    # Domains of URL shorteners, whose links hide their real destination.
    shortener_domains: tuple[str, ...]

    # Urgency Phrases: wording that pressures the reader to act before thinking.
    urgency_phrases: tuple[str, ...]

    # Attachment extensions (without the dot) that can run code or fake a web page.
    risky_extensions: tuple[str, ...]

    # How many VirusTotal engines must flag an Observable as malicious for a
    # Decisive Finding. Fewer (but at least one) adds points instead.
    decisive_engines: int

    # The most URLs looked up per Triage. Any more are Not Checked ("over lookup cap").
    url_cap: int

    # A domain registered fewer than this many days ago gives a Finding.
    new_domain_days: int

    # Trusted Relays: mail servers (and their subdomains) whose Received
    # headers are believed genuine, normally the organisation's own gateway.
    trusted_relays: tuple[str, ...]

    # An AbuseIPDB abuse confidence (0-100%) at or above this for the Claimed
    # Origin gives a Finding.
    abuse_confidence_threshold: int

    @property
    def protected_domains(self) -> tuple[str, ...]:
        """Every brand's domains in one list, without repeats."""
        all_domains = (domain for domains in self.brands.values() for domain in domains)
        return tuple(dict.fromkeys(all_domains))
