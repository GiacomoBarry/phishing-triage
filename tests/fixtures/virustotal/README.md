# VirusTotal response fixtures

Real VirusTotal API v3 response bodies, captured on 2026-10-07 with
`scripts/capture_virustotal_fixtures.py`. They're fed to the VirusTotal
Provider through a fake transport, so no test touches the network. Each file
is named `<case>.<HTTP status>.json`.

- `file_detected` is the EICAR test file, which is harmless but flagged on
  purpose by every antivirus. `url_detected` and `domain_detected` are the
  wicar.org test URL that serves it.
- `domain_low_detections` is google.com, which 2 engines flag as malicious:
  a real example of how noisy low detection counts on domains can be.
- `domain_just_created` answered 200, not 404: an earlier lookup of the same
  made-up domain made VirusTotal create a record for it on the spot, with
  every engine "undetected" and none "harmless". That is why such an answer
  is treated as Unknown, not clean (ADR 0006).
- `domain_invalid` is VirusTotal refusing a reserved name (`.example`).
- **`rate_limited.429.json` is hand-written** from VirusTotal's documented
  error format (`QuotaExceededError`). Eight quick lookups in a row never
  produced a real 429, so it couldn't be captured.

The URLs and domains are kept as text only and are never visited by the tests.

To refresh them, run the script again. It makes up to 19 lookups with the key
in `.env`, pausing between them for the free tier's 4-a-minute limit.
