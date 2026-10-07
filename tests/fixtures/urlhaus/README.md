# URLhaus response fixtures

Real URLhaus API response bodies, captured on 2026-10-07 with
`scripts/capture_urlhaus_fixtures.py`. They're fed to the URLhaus Provider
through a fake transport, so no test touches the network. Each file is named
`<case>.<HTTP status>.json`.

The listed URL (on trycloudflare.com) was already offline when captured.
It's kept as text only and is never visited by the tests.

To refresh them, run the script again. It makes 6 queries with the key in
`.env`; abuse.ch limits accounts that send unusually many, so don't run it
in a loop.
