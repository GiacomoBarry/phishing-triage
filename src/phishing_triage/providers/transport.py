"""Sending HTTP requests to Providers, behind an interface tests can replace.

Real Providers talk to the network only through a Transport. Tests give them
a fake one that returns saved real responses, so no test touches the network.
"""

import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.metadata import version
from typing import Protocol
from urllib.parse import urlencode

# How long to wait for a Provider before giving up (it becomes Not Checked).
TIMEOUT_SECONDS = 15.0

USER_AGENT = f"phishing-triage/{version('phishing-triage')}"


@dataclass(frozen=True)
class HttpResponse:
    """A Provider's answer: the HTTP status code and the raw body."""

    status: int
    body: bytes


class TransportError(Exception):
    """The Provider couldn't be reached at all (no connection, timeout...)."""


class Transport(Protocol):
    """Something that can POST a form to a Provider's API."""

    def post(self, url: str, form: Mapping[str, str], headers: Mapping[str, str]) -> HttpResponse:
        """POST `form` to `url`. Raises TransportError if no answer came back."""
        ...


class UrllibTransport:
    """The real Transport, using Python's built-in urllib."""

    def __init__(self, timeout: float = TIMEOUT_SECONDS) -> None:
        self._timeout = timeout

    def post(self, url: str, form: Mapping[str, str], headers: Mapping[str, str]) -> HttpResponse:
        request = urllib.request.Request(
            url,
            data=urlencode(form).encode(),
            headers={"User-Agent": USER_AGENT, **headers},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                return HttpResponse(status=response.status, body=response.read())
        except urllib.error.HTTPError as error:
            # An error status (401, 429, 500...) is still an answer worth reading.
            return HttpResponse(status=error.code, body=error.read())
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            reason = getattr(error, "reason", error)
            raise TransportError(str(reason)) from error
