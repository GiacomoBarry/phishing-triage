"""Telling the time and waiting, behind an interface tests can replace.

The core waits between lookups to respect each Provider's rate limit. Tests
pass a fake clock whose sleep just moves its time on, so no test really waits.
"""

import time
from typing import Protocol


class Clock(Protocol):
    """Something that can tell the time (in seconds) and wait."""

    def now(self) -> float:
        """The current time, in seconds since 1 January 1970 (UTC)."""
        ...

    def sleep(self, seconds: float) -> None:
        """Wait for `seconds`."""
        ...


class SystemClock:
    """The real clock."""

    def now(self) -> float:
        # Calendar time, because cache entries are compared across runs. If the
        # computer's clock is corrected mid-run, pacing at worst waits a little
        # less or more once; a wait is never negative.
        return time.time()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)
