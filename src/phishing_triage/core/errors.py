"""Errors the core can raise to its caller."""


class UnparseableEmailError(ValueError):
    """The input could not be read as an email, so no Verdict can be given."""


class NoAttachedEmailError(ValueError):
    """The inner email was asked for, but the email has no email attached."""


class UnparseableAttachedEmailError(UnparseableEmailError):
    """The email attached inside a Wrapper Email could not be read as an email.

    The Wrapper Email itself was fine, so the caller should say it is the
    attached email that is unreadable.
    """
