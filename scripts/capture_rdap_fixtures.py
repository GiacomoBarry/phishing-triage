"""Capture real RDAP responses as test fixtures. Run by hand, never by tests.

    uv run python scripts/capture_rdap_fixtures.py

RDAP needs no key. This makes 5 requests: IANA's bootstrap list (which
registry answers for each domain ending), then a few registry lookups. Each
body is saved to tests/fixtures/rdap/<case>.<status>.json.

Only registries are asked; no domain is ever contacted (ADR 0001).
"""

import sys
from pathlib import Path

from phishing_triage.providers.rdap import ACCEPT, BOOTSTRAP_URL
from phishing_triage.providers.transport import UrllibTransport

FIXTURES = Path(__file__).parent.parent / "tests" / "fixtures" / "rdap"

CASES = {
    # Registered in 2012, on the Public Interest Registry (.org).
    "registered": "https://rdap.publicinterestregistry.org/rdap/domain/wicar.org",
    # A subdomain: registries only know registered domains, so this is 404.
    "subdomain": "https://rdap.publicinterestregistry.org/rdap/domain/malware.wicar.org",
    # A .com that was never registered.
    "not_found": "https://rdap.verisign.com/com/v1/domain/never-registered-phishing-triage-fixture-4f9b9e.com",
    # A .co.uk, on Nominet.
    "registered_co_uk": "https://rdap.nominet.uk/uk/domain/bbc.co.uk",
}


def main() -> int:
    transport = UrllibTransport()
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for old in FIXTURES.glob("*.json"):
        old.unlink()
    for case, url in {"bootstrap": BOOTSTRAP_URL, **CASES}.items():
        answer = transport.get(url, ACCEPT)
        path = FIXTURES / f"{case}.{answer.status}.json"
        path.write_bytes(answer.body)
        print(f"saved {path.name} ({len(answer.body)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
