"""Loading settings from a TOML file into the core's Settings.

This lives outside the core because reading files is the caller's job.

The default settings file shipped with the tool doubles as the template for
any edited copy: an edited file must have exactly the same sections and keys,
so a typo is reported instead of being silently ignored.
"""

import tomllib
from importlib.resources import files
from pathlib import Path
from typing import Any

from phishing_triage.core import Settings


class SettingsError(ValueError):
    """A settings file could not be read, or its contents are not valid."""


def load_settings(path: Path | None = None) -> Settings:
    """Load settings from a TOML file, or the defaults shipped with the tool.

    Raises SettingsError with a message naming the problem.
    """
    defaults = tomllib.loads(_default_settings_text())
    if path is None:
        return _build(defaults)

    try:
        data = tomllib.loads(path.read_text("utf-8"))
    except OSError as error:
        message = f"settings file {path} could not be read: {error.strerror}"
        raise SettingsError(message) from error
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        message = f"settings file {path} is not valid TOML: {error}"
        raise SettingsError(message) from error

    problem = _first_problem(data, template=defaults)
    if problem:
        raise SettingsError(f"settings file {path}: {problem}")
    return _build(data)


def _default_settings_text() -> str:
    return files("phishing_triage").joinpath("settings.toml").read_text("utf-8")


def _first_problem(data: dict[str, Any], template: dict[str, Any]) -> str | None:
    """Return a description of the first problem in `data`, or None if it's valid."""
    for section, template_values in template.items():
        if section not in data:
            return f"missing section [{section}]"
        values = data[section]
        if not isinstance(values, dict):
            return f"{section} must be a section, like [{section}]"
        # The analyst chooses the brand names, so [brands] can't be checked
        # key by key against the template like the other sections.
        if section == "brands":
            problem = _brands_problem(values)
        else:
            problem = _fixed_keys_problem(section, values, template_values)
        if problem:
            return problem

    for section in data:
        if section not in template:
            return f"unknown setting {section}"

    verdict = data["verdict"]
    if verdict["suspicious_from"] < 1:
        return "verdict.suspicious_from must be at least 1, or nothing could be clean"
    if verdict["suspicious_from"] >= verdict["malicious_from"]:
        return "verdict.suspicious_from must be lower than verdict.malicious_from"
    if data["virustotal"]["decisive_engines"] < 1:
        return "virustotal.decisive_engines must be at least 1"
    if not 1 <= data["abuseipdb"]["confidence_threshold"] <= 100:
        return "abuseipdb.confidence_threshold must be from 1 to 100 (a percentage)"
    return None


def _fixed_keys_problem(
    section: str, values: dict[str, Any], template_values: dict[str, Any]
) -> str | None:
    """Check a section that must have exactly the template's keys.

    Each value must be the same sort as the shipped default: a whole number
    of 0 or more, or a list of the items LIST_ITEM_CHECKS describes.
    """
    for key, default in template_values.items():
        if key not in values:
            return f"missing {section}.{key}"
        value = values[key]
        if isinstance(default, list):
            looks_right, described = LIST_ITEM_CHECKS[key]
            if not isinstance(value, list) or not all(looks_right(v) for v in value):
                return f"{section}.{key} must be {described}"
            continue
        # bool is a kind of int in Python, so rule it out explicitly.
        if not isinstance(value, int) or isinstance(value, bool):
            return f"{section}.{key} must be a whole number"
        if value < 0:
            return f"{section}.{key} must not be negative"
    for key in values:
        if key not in template_values:
            return f"unknown setting {section}.{key}"
    return None


def _brands_problem(brands: dict[str, Any]) -> str | None:
    """Check the [brands] section: any brand names, each with a list of domains."""
    for brand, domains in brands.items():
        if not brand.strip():
            return "brand names in [brands] must not be empty"
        if (
            not isinstance(domains, list)
            or not domains
            or not all(_looks_like_a_domain(domain) for domain in domains)
        ):
            return f'brands."{brand}" must be a list of one or more domains, like ["example.com"]'
    return None


def _looks_like_a_domain(value: Any) -> bool:
    return (
        isinstance(value, str)
        and "." in value.strip(".")
        and not any(character.isspace() or character == "@" for character in value)
    )


def _looks_like_a_phrase(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _looks_like_an_extension(value: Any) -> bool:
    return isinstance(value, str) and value.removeprefix(".").isalnum()


# How to check each item of a list setting, and how to describe it in an error.
LIST_ITEM_CHECKS = {
    "domains": (_looks_like_a_domain, 'a list of domains, like ["example.com"]'),
    "phrases": (_looks_like_a_phrase, 'a list of phrases, like ["verify your account"]'),
    "risky_extensions": (_looks_like_an_extension, 'a list of file extensions, like ["exe"]'),
    "trusted_relays": (_looks_like_a_domain, 'a list of mail server names, like ["mx.example.com"]'),
}


def _build(data: dict[str, Any]) -> Settings:
    return Settings(
        points=data["points"],
        suspicious_from=data["verdict"]["suspicious_from"],
        malicious_from=data["verdict"]["malicious_from"],
        brands={
            brand: tuple(domain.strip(".").lower() for domain in domains)
            for brand, domains in data["brands"].items()
        },
        shortener_domains=tuple(
            domain.strip(".").lower() for domain in data["shorteners"]["domains"]
        ),
        # Spacing and apostrophes are evened out when matching (core/rules.py).
        urgency_phrases=tuple(data["urgency"]["phrases"]),
        risky_extensions=tuple(
            extension.removeprefix(".").lower()
            for extension in data["attachments"]["risky_extensions"]
        ),
        decisive_engines=data["virustotal"]["decisive_engines"],
        url_cap=data["lookups"]["url_cap"],
        new_domain_days=data["rdap"]["new_domain_days"],
        abuse_confidence_threshold=data["abuseipdb"]["confidence_threshold"],
        trusted_relays=tuple(
            relay.strip(".").lower() for relay in data["received"]["trusted_relays"]
        ),
    )
