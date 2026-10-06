"""The Provider interface.

A Provider is an outside source a Reputation Lookup is made against.
Providers are always passed in to the core, never created inside it.
The interface is filled in when the first real Provider arrives (ticket 09).
"""

from typing import Protocol


class Provider(Protocol):
    """An outside source a Reputation Lookup is made against."""
