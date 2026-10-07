# RDAP response fixtures

Real RDAP response bodies, captured on 2026-10-07 with
`scripts/capture_rdap_fixtures.py`. They're fed to the RDAP Provider through a
fake transport, so no test touches the network. Each file is named
`<case>.<HTTP status>.json`.

- `bootstrap` is IANA's list of which registry answers for each domain ending
  (`.de` and `.io` have no RDAP service in it).
- `registered` is wicar.org (registered 2012) and `registered_co_uk` is
  bbc.co.uk (registered 1994).
- `subdomain` is the .org registry refusing `malware.wicar.org` with **400**,
  not 404: registries only know registered domains, and some say "bad request"
  for anything else.
- `not_found` is Verisign's answer for a .com that was never registered: a 404
  with an empty body.
- **`registered_no_date.200.json` is derived**, not captured: it's `registered`
  with its registration event removed, standing in for registries that don't
  publish the date. No real example was found.

To refresh them, run the script again (5 requests, no key needed), then
re-derive `registered_no_date` the same way.
