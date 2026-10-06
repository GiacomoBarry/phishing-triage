# Settings live in one packaged TOML file, which is also the template for edited copies

All tunable values (Finding points, Verdict thresholds and, in later tickets, lists such as Protected Domains) live in `src/phishing_triage/settings.toml`, which ships inside the package so the tool works wherever it is run. To tune, an analyst copies the file and passes the copy with `--settings PATH`. The edited copy must contain exactly the same sections and keys as the shipped file, and anything missing, misspelt or of the wrong type stops the run with exit code 7. We chose a full copy over "override only the keys you change" because a silently ignored typo (for example `reply_to_mismach = 5`) would make the analyst believe a weight was tuned when it wasn't, and that would skew the dataset evaluation.

## Considered Options

- **`settings.toml` at the repo root, read from the current folder**: easiest to find, but the tool would only work when run from the repo.
- **Packaged file only, edited in place**: no extra option, but tuning would mean editing a file inside the source code.

## Consequences

- Validation checks an edited copy's keys against the shipped file, so adding a key there is enough for missing or misspelt keys to be caught. A new setting still needs a field in `Settings` and a line in `config._build`.
- Validation currently expects whole numbers of 0 or more. When list settings arrive (such as Protected Domains), it will need to check each value against the type of the shipped default instead.
- Existing edited copies must be updated when a new setting is added, and the error message names the missing key.
