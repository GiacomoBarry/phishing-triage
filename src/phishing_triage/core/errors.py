"""Errors the core can raise to its caller."""


class UnparseableEmailError(ValueError):
    """The input could not be read as an email, so no Verdict can be given."""
