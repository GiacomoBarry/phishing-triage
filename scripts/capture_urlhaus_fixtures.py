"""Capture real URLhaus responses as test fixtures. Run by hand, never by tests.

    uv run python scripts/capture_urlhaus_fixtures.py

Makes 5 lookups with the key in .env (abuse.ch rate-limits heavy use, so
don't run this in a loop) and saves each response body to
tests/fixtures/urlhaus/<case>.<status>.json. The key is never printed or saved.
"""

import json
import os
import sys
import urllib.request
from pathlib import Path

from dotenv import load_dotenv

from phishing_triage.providers.transport import USER_AGENT, UrllibTransport
from phishing_triage.providers.urlhaus import API_ROOT

FIXTURES = Path(__file__).parent.parent / "tests" / "fixtures" / "urlhaus"


def main() -> int:
    load_dotenv(Path(".env"))
    key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if not key:
        print("Put URLHAUS_AUTH_KEY in .env first.", file=sys.stderr)
        return 1

    transport = UrllibTransport()
    headers = {"Auth-Key": key}

    # 1. A URL listed right now, from URLhaus's own recent list.
    request = urllib.request.Request(
        API_ROOT + "urls/recent/limit/1/", headers={"User-Agent": USER_AGENT, **headers}
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        listed = json.load(response)["urls"][0]

    cases = {
        "url_listed": (API_ROOT + "url/", {"url": listed["url"]}, headers),
        "url_not_listed": (API_ROOT + "url/", {"url": "https://example.com/never-listed"}, headers),
        "host_listed": (API_ROOT + "host/", {"host": listed["host"]}, headers),
        "host_not_listed": (API_ROOT + "host/", {"host": "example.com"}, headers),
        "bad_key": (API_ROOT + "url/", {"url": listed["url"]}, {"Auth-Key": "not-a-real-key"}),
    }
    for old in FIXTURES.glob("*.json"):
        old.unlink()
    for case, (endpoint, form, case_headers) in cases.items():
        answer = transport.post(endpoint, form, case_headers)
        if key.encode() in answer.body:
            print(f"{case}: response contains the key, not saved.", file=sys.stderr)
            return 1
        path = FIXTURES / f"{case}.{answer.status}.json"
        path.write_bytes(answer.body)
        print(f"saved {path.name} ({len(answer.body)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
