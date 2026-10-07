"""Capture real AbuseIPDB responses as test fixtures. Run by hand, never by tests.

    uv run python scripts/capture_abuseipdb_fixtures.py

Makes at most 12 requests with the key in .env (the free tier allows 1,000
checks a day). Each response body is saved to
tests/fixtures/abuseipdb/<case>.<status>.json. The key is never printed or saved.

Only read endpoints (GET) are used: the check endpoint, plus the blacklist
once, to find an IP that is certainly reported. Nothing is ever reported
to AbuseIPDB (ADR 0001).
"""

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from phishing_triage.providers.abuseipdb import API_ROOT, check_url, request_headers
from phishing_triage.providers.transport import HttpResponse, UrllibTransport

FIXTURES = Path(__file__).parent.parent / "tests" / "fixtures" / "abuseipdb"

# Google's public DNS server, which AbuseIPDB lists as known-good.
ALLOWLISTED_IP = "8.8.8.8"

# Public IPs to try for a never-reported one and a low-confidence one. Which is
# which changes over time, so the script looks at each answer.
CANDIDATES = ["185.199.108.153", "151.101.1.69", "17.253.144.10", "146.75.2.132", "13.107.42.14"]

# Below this an abuse confidence counts as "low" for the fixture (the default threshold is 75).
LOW_CONFIDENCE_BELOW = 75


def main() -> int:
    load_dotenv(Path(".env"))
    key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not key:
        print("Put ABUSEIPDB_API_KEY in .env first.", file=sys.stderr)
        return 1

    transport = UrllibTransport()

    def get(url: str, case_key: str = key) -> HttpResponse:
        return transport.get(url, request_headers(case_key))

    FIXTURES.mkdir(parents=True, exist_ok=True)
    for old in FIXTURES.glob("*.json"):
        old.unlink()

    def save(case: str, answer: HttpResponse) -> None:
        if key.encode() in answer.body:
            raise SystemExit(f"{case}: response contains the key, not saved.")
        (FIXTURES / f"{case}.{answer.status}.json").write_bytes(answer.body)
        print(f"saved {case}.{answer.status}.json ({len(answer.body)} bytes)")

    save("bad_key", get(check_url(ALLOWLISTED_IP), "not-a-real-key"))
    save("invalid_ip", get(check_url("not-an-ip")))
    save("allowlisted", get(check_url(ALLOWLISTED_IP)))

    blacklist = get(API_ROOT + "blacklist?limit=1")
    reported_ip = json.loads(blacklist.body)["data"][0]["ipAddress"]
    save("high_confidence", get(check_url(reported_ip)))

    wanted = {"not_reported", "low_confidence"}
    for ip in CANDIDATES:
        if not wanted:
            break
        answer = get(check_url(ip))
        data = json.loads(answer.body).get("data", {})
        if data.get("isWhitelisted"):
            continue
        if data.get("totalReports") == 0 and "not_reported" in wanted:
            save("not_reported", answer)
            wanted.discard("not_reported")
        elif 0 < data.get("abuseConfidenceScore", 0) < LOW_CONFIDENCE_BELOW and "low_confidence" in wanted:
            save("low_confidence", answer)
            wanted.discard("low_confidence")
    for case in sorted(wanted):
        print(f"no candidate IP gave a {case} answer, so no {case} fixture", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
