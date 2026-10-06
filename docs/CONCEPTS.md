# Concepts

Programming concepts this project uses, one line each, with where they appear.

- **src layout**: the package lives in `src/phishing_triage/`, so tests have to import the installed package rather than loose files (`pyproject.toml`, `src/`).
- **Editable install**: `uv sync` installs the project so that code changes take effect straight away, with no reinstall (`uv.lock`, `pyproject.toml`).
- **Console script entry point**: `[project.scripts]` turns a Python function into a terminal command, `phishing-triage` (`pyproject.toml` → `cli.main`).
- **Core/CLI split (separation of concerns)**: the logic is kept apart from input and output so it can be reused and tested (`core/` vs `cli.py`).
- **Dependency injection**: the core is *given* its settings and Providers instead of creating them, so tests can pass in fakes (`triage(raw_email, settings, providers)` in `core/triage.py`).
- **Pure function**: the output depends only on the input and nothing else changes (`incident_note()` in `core/incident_note.py`).
- **Dataclass**: a class that mainly holds data, with the boilerplate generated for you; `frozen=True` makes it read-only (`TriageReport` in `core/report.py`, `Settings` in `core/settings.py`).
- **Enum (StrEnum, IntEnum)**: a fixed set of named choices; a `StrEnum` member is also a string, so it turns into JSON easily (`Verdict` in `core/report.py`), and an `IntEnum` member is also a number, so it can be an exit code (`ExitCode` in `cli.py`).
- **Protocol**: describes the shape an object must have, without forcing it to inherit from anything (`Provider` in `core/providers.py`).
- **Custom exception**: a named error the caller can catch and handle on purpose (`UnparseableEmailError` in `core/errors.py`, caught in `cli.py`).
- **Exit codes**: the number a program hands back to the shell, so scripts can react without reading any text (`ExitCode` in `cli.py`).
- **Set intersection**: `a & b` keeps only what's in both sets, used to check that at least one standard email header is present (`_parse` in `core/triage.py`).
- **Overriding a method**: replacing a library behaviour in a subclass; here it stops argparse's default exit code 2 clashing with "malicious" (`_ArgumentParser.error` in `cli.py`).
- **Hashing (SHA-256)**: a fingerprint of the exact bytes, used to spot the same email being triaged twice (`source_sha256` in `core/triage.py`).
- **UUID**: a randomly generated ID that is unique in practice, used to name each report (`report_id` in `core/triage.py`).
- **Timezone-aware datetime**: a timestamp that records its timezone (UTC), so it's never ambiguous (`analysed_at` in `core/triage.py`).
- **Type hints and mypy**: annotations saying what types are expected, checked by `uv run mypy` in strict mode (everywhere; config in `pyproject.toml`).
- **Testing at seams**: tests go through public entry points only, so the inside can be reorganised freely (`tests/test_triage.py` for the core, `tests/test_cli.py` for the CLI).
- **Test fixtures**: small saved sample files and reusable setup for tests (`tests/fixtures/*.eml`, the `work_in_tmp_path` fixture in `tests/test_cli.py`).
- **Parametrised test**: one test run against several inputs (`test_input_with_no_email_headers_is_refused` in `tests/test_triage.py`).
- **Secrets in `.env`**: API keys stay in a git-ignored file, and `.env.example` lists the names without values (`.gitignore`, `.env.example`).
