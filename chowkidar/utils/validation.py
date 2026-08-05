from __future__ import annotations

from re import match


def validate_email(email: str) -> str:
    """Validate an email address against a basic RFC-like regex pattern.

    Parameters
    ----------
    email : str
        The email address string to validate.

    Returns
    -------
    str
        The validated email address, returned unchanged.

    Raises
    ------
    AuthError
        If the email address does not match the expected pattern (code ``INVALID_EMAIL``).

    """
    from chowkidar.utils.exceptions import AuthError

    if not match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email):
        raise AuthError(
            message="You have entered an invalid email address",
            code="INVALID_EMAIL",
        )

    return email


__all__ = ["validate_email"]
