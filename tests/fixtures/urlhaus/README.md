# URLhaus response fixtures

Saved URLhaus API response bodies, fed to the URLhaus Provider through a fake
transport so no test touches the network. Each file is named
`<case>.<HTTP status>.json`.

**Status: provisional.** URLhaus was down when these were written
(2026-10-07), so they follow URLhaus's documented format rather than being
captured. Replace them with real responses by running:

    uv run python scripts/capture_urlhaus_fixtures.py

That makes 5 queries with the key in `.env` (abuse.ch now rate-limits heavy
use), then re-run the tests. Delete this "provisional" note once done.
