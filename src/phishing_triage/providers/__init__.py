"""The real Providers, and building them from the environment.

This lives outside the core because it reads API keys and talks to the
network. The CLI and the live evaluation build the Providers and pass them
in to the core.
"""

import os
from collections.abc import Mapping
from pathlib import Path

from dotenv import load_dotenv

from phishing_triage.core import ABUSEIPDB, URLHAUS, VIRUSTOTAL, Provider, Settings
from phishing_triage.providers.abuseipdb import AbuseIPDBProvider
from phishing_triage.providers.rdap import RdapProvider
from phishing_triage.providers.transport import UrllibTransport
from phishing_triage.providers.urlhaus import URLhausProvider
from phishing_triage.providers.virustotal import VirusTotalProvider

# The environment variable each Provider reads its API key from. RDAP needs no key.
API_KEY_VARIABLES = {
    URLHAUS: "URLHAUS_AUTH_KEY",
    VIRUSTOTAL: "VIRUSTOTAL_API_KEY",
    ABUSEIPDB: "ABUSEIPDB_API_KEY",
}


def real_providers(settings: Settings) -> list[Provider]:
    """Build the real Providers, reading API keys from .env (if present) and the environment.

    Keys already set in the environment win over the .env file.
    """
    load_dotenv(Path(".env"))
    return build_providers(os.environ, settings)


def build_providers(environ: Mapping[str, str], settings: Settings) -> list[Provider]:
    """Build every real Provider, taking API keys from `environ`.

    A missing key still gives a Provider: it answers Not Checked ("no API
    key"), so the gap shows up in the Triage Report instead of vanishing.
    """
    transport = UrllibTransport()
    return [
        URLhausProvider(auth_key=_key(environ, URLHAUS), transport=transport),
        VirusTotalProvider(
            api_key=_key(environ, VIRUSTOTAL),
            transport=transport,
            decisive_engines=settings.decisive_engines,
        ),
        RdapProvider(transport=transport),  # Needs no key.
        AbuseIPDBProvider(api_key=_key(environ, ABUSEIPDB), transport=transport),
    ]


def missing_api_keys(environ: Mapping[str, str]) -> dict[str, str]:
    """Each Provider with no API key in `environ`, and the variable its key goes in.

    Only names are returned, never a key's value.
    """
    return {provider: variable for provider, variable in API_KEY_VARIABLES.items() if not _key(environ, provider)}


def _key(environ: Mapping[str, str], provider: str) -> str | None:
    """The Provider's API key from `environ`, or None if it isn't set (or is blank)."""
    return environ.get(API_KEY_VARIABLES[provider], "").strip() or None
