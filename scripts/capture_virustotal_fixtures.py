"""Capture real VirusTotal responses as test fixtures. Run by hand, never by tests.

    uv run python scripts/capture_virustotal_fixtures.py

Makes up to 19 lookups with the key in .env, pausing between them because
the free API allows 4 a minute, then deliberately makes quick ones until
VirusTotal says "rate limited". Each response body is saved to
tests/fixtures/virustotal/<case>.<status>.json. The key is never printed or saved.

Only lookup endpoints (GET) are used. Nothing is submitted or scanned (ADR 0001).
"""

import base64
import hashlib
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

from phishing_triage.providers.transport import HttpResponse, UrllibTransport
from phishing_triage.providers.virustotal import API_ROOT

FIXTURES = Path(__file__).parent.parent / "tests" / "fixtures" / "virustotal"

# The free API allows 4 lookups a minute.
PAUSE_SECONDS = 16

# The EICAR test file: harmless, but every antivirus flags it on purpose.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
# The empty file, which VirusTotal has seen countless times.
EMPTY_FILE_SHA256 = hashlib.sha256(b"").hexdigest()
# A hash of text that has never been a file anywhere.
NEVER_SEEN_SHA256 = hashlib.sha256(b"phishing-triage fixture, never uploaded").hexdigest()
# A well-known test URL that serves the EICAR file, flagged by many engines.
DETECTED_URL = "http://malware.wicar.org/data/eicar.com"


def url_id(url: str) -> str:
    """VirusTotal's identifier for a URL: the URL in base64url, without padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def main() -> int:
    load_dotenv(Path(".env"))
    key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        print("Put VIRUSTOTAL_API_KEY in .env first.", file=sys.stderr)
        return 1

    transport = UrllibTransport()
    cases = {
        "file_detected": f"files/{EICAR_SHA256}",
        "file_clean": f"files/{EMPTY_FILE_SHA256}",
        "file_not_found": f"files/{NEVER_SEEN_SHA256}",
        "domain_detected": "domains/malware.wicar.org",
        "domain_low_detections": "domains/google.com",  # 2 engines flag it
        "domain_just_created": "domains/never-registered-phishing-triage-fixture-4f9b9e.com",
        # VirusTotal refuses reserved names like .example as "not a valid domain".
        "domain_invalid": "domains/never-registered-phishing-triage-fixture.example",
        "url_detected": f"urls/{url_id(DETECTED_URL)}",
        "url_clean": f"urls/{url_id('https://www.google.com/')}",
        "url_not_found": f"urls/{url_id('https://example.com/phishing-triage-fixture-never-seen')}",
    }

    FIXTURES.mkdir(parents=True, exist_ok=True)
    for old in FIXTURES.glob("*.json"):
        old.unlink()

    def save(case: str, answer: HttpResponse) -> None:
        if key.encode() in answer.body:
            raise SystemExit(f"{case}: response contains the key, not saved.")
        (FIXTURES / f"{case}.{answer.status}.json").write_bytes(answer.body)
        print(f"saved {case}.{answer.status}.json ({len(answer.body)} bytes)")

    def look_up(path: str, case_key: str = key) -> HttpResponse:
        return transport.get(API_ROOT + path, {"x-apikey": case_key})

    save("bad_key", look_up(f"files/{EICAR_SHA256}", "not-a-real-key"))
    for case, path in cases.items():
        time.sleep(PAUSE_SECONDS)
        save(case, look_up(path))

    # Quick lookups until the per-minute limit is hit (at most 8 tries).
    time.sleep(PAUSE_SECONDS)
    for _ in range(8):
        answer = look_up(f"files/{EICAR_SHA256}")
        if answer.status == 429:
            save("rate_limited", answer)
            break
    else:
        print("never got rate limited, so no rate_limited fixture", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
