from __future__ import annotations

from graphql import GraphQLError


class APIError(GraphQLError):
    """GraphQL error with a structured code and message for API responses.

    Attributes
    ----------
    locations : list
        List of locations in the GraphQL query where the error occurred.
    path : list
        List representing the path to the field that caused the error.
    code : str | None
            Machine-readable error code, optional.
    message : str
        Human-readable error message.


    """

    def __init__(
        self,
        message: str,
        code: str | None = None,
        *args: tuple,
        **kwargs: dict,
    ):
        """Initialize the APIError with a message and optional code.

        Parameters
        ----------
        message : str
            Human-readable error message.
        code : str | None, optional
            Machine-readable error code, by default None.
        *args : tuple
            Additional positional arguments forwarded to ``GraphQLError``.
        **kwargs : dict
            Additional keyword arguments forwarded to ``GraphQLError``.

        """
        super().__init__(
            message,
            *args,
            **kwargs,
        )
        self.locations = []
        self.path = []
        self.code = code
        self.message = message

    @property
    def formatted(self):
        """Format the error as a dict with ``message`` and ``code`` keys.

        Returns
        -------
        dict[str, str]
            Dictionary containing ``message`` and ``code``.

        """
        return {
            "message": self.message or "An unknown error occurred.",
            "code": self.code or "UNKNOWN_ERROR",
        }


class AuthError(Exception):
    """Authentication error raised when credentials or tokens are invalid.

    Parameters
    ----------
    code : str, optional
        Machine-readable error code, by default None.
    message : str
        Human-readable error description.

    """

    def __init__(
        self,
        message: str,
        code: str | None = None,
    ):
        """Initialize the AuthError with a message and optional code.

        Parameters
        ----------
        message : str
            Human-readable error message.
        code : str | None, optional
            Machine-readable error code, by default None.

        """
        if code:
            self.code = code

        self.message = message
        super().__init__(message)


class PermissionDenied(Exception):
    """Authorization error raised when the user lacks required permissions.

    Attributes
    ----------
    message : str
        Human-readable error description.
    code : str, optional
        Machine-readable error code, by default None.

    """

    def __init__(
        self,
        message: str,
        code: str | None = None,
    ):
        """Initialize the PermissionDenied error with a message and optional code.

        Parameters
        ----------
        message : str
            Human-readable error message.
        code : str | None, optional
            Machine-readable error code, by default None.

        """
        if code:
            self.code = code

        self.message = message
        super().__init__(message)


__all__ = [
    "APIError",
    "AuthError",
    "PermissionDenied",
]
