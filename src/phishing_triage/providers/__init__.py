"""The real Providers, and building them from the environment.

This lives outside the core because it reads API keys and talks to the
network. The CLI builds the Providers and passes them in to the core.
"""

from collections.abc import Mapping

from phishing_triage.core import Provider
from phishing_triage.providers.transport import UrllibTransport
from phishing_triage.providers.urlhaus import URLhausProvider


def build_providers(environ: Mapping[str, str]) -> list[Provider]:
    """Build every real Provider, taking API keys from `environ`.

    A missing key still gives a Provider: it answers Not Checked ("no API
    key"), so the gap shows up in the Triage Report instead of vanishing.
    """
    transport = UrllibTransport()
    return [
        URLhausProvider(auth_key=_key(environ, "URLHAUS_AUTH_KEY"), transport=transport),
    ]


def _key(environ: Mapping[str, str], name: str) -> str | None:
    return environ.get(name, "").strip() or None
