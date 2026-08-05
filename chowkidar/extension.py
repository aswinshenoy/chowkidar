from __future__ import annotations

from typing import TYPE_CHECKING
from collections.abc import Callable

import strawberry
from django.apps import apps
from django.http import HttpRequest
from django.utils import timezone
from strawberry.types import ExecutionContext
from strawberry.extensions import SchemaExtension

if TYPE_CHECKING:
    from chowkidar.models import AbstractRefreshToken


class JWTAuthExtension(SchemaExtension):
    """Strawberry schema extension for JWT cookie-based authentication.

    Processes incoming request cookies to resolve the requester's identity,
    refreshes expired access tokens when a valid refresh token exists, and
    populates ``info.context`` with auth state for downstream resolvers.

    Notes
    -----
    - Register on the schema via
      ``strawberry.Schema(query=Query, extensions=[JWTAuthExtension])``.
    - ``execution_context`` is optional; Strawberry sets it on the instance
      before invoking hooks.

    """

    def __init__(
        self,
        *,
        execution_context: ExecutionContext | None = None,
    ):
        """Initialize the extension and set default state variables.

        Parameters
        ----------
        execution_context : ExecutionContext | None, optional
            The Strawberry execution context. Strawberry sets this on the instance
            after construction in newer versions, by default None.

        """
        super().__init__(execution_context=execution_context)
        self._request: HttpRequest | None = None
        self.userID: int | None = None
        self.refreshToken: str | None = None
        self.refreshTokenObj: AbstractRefreshToken | None = None
        self._new_JWT_access_token: str | None = None
        self._remove_auth_cookies: bool = False

    def _init_request_state(self) -> None:
        """Reset all state variables to defaults for a new request.

        Notes
        -----
        - Called at the start of each ``on_operation`` cycle to prevent state
          leakage between requests.

        """
        self._request: HttpRequest | None = None
        self.userID: int | None = None
        self.refreshToken: str | None = None
        self.refreshTokenObj: AbstractRefreshToken | None = None
        self._new_JWT_access_token: str | None = None
        self._remove_auth_cookies: bool = False

    def is_cookie_in_request(self, cookie_name: str) -> bool:
        """Check whether a non-empty cookie exists in the current request.

        Parameters
        ----------
        cookie_name : str
            The name of the cookie to look up.

        Returns
        -------
        bool
            ``True`` if the cookie exists and has a truthy value.

        """
        return cookie_name in self._request.COOKIES and self._request.COOKIES[cookie_name]

    def _get_token_payload_from_cookie(self, cookie_name: str) -> dict | None:
        """Decode and return the JWT payload from a request cookie.

        Parameters
        ----------
        cookie_name : str
            The name of the cookie containing the JWT token.

        Returns
        -------
        dict | None
            The decoded JWT payload, or ``None`` if the cookie is missing or
            the token is invalid.

        """
        from chowkidar.utils.jwt import decode_payload_from_token
        from chowkidar.utils.exceptions import AuthError

        if self.is_cookie_in_request(cookie_name):
            try:
                return decode_payload_from_token(token=self._request.COOKIES[cookie_name])
            except AuthError:
                return None

    def _get_refresh_token_object(self) -> AbstractRefreshToken | None:
        """Look up the refresh token in the database and validate it.

        Returns
        -------
        AbstractRefreshToken | None
            The valid refresh token instance, or ``None`` if the token is missing,
            revoked, or expired.

        Notes
        -----
        - Sets ``_remove_auth_cookies`` to ``True`` when the token exists in the
          cookie but is not found or is invalid in the database.

        """
        from chowkidar.settings import REFRESH_TOKEN_MODEL

        if self.refreshToken is None:
            return

        RefreshToken = apps.get_model(REFRESH_TOKEN_MODEL, require_ready=False)

        try:
            return RefreshToken.objects.get(
                token=self.refreshToken,
                revoked__isnull=True,
                issued__gte=timezone.now() - RefreshToken().get_refresh_token_expiry_delta(),
            )
        except RefreshToken.DoesNotExist:
            self._remove_auth_cookies = True
            return None

    def on_operation(self):
        """Strawberry operation hook that runs auth logic before query execution.

        Yields
        ------
        None
            Yields once after completing pre-operation auth processing.

        Notes
        -----
        - Resets state, resolves access and refresh tokens from cookies, and
          generates a new access token when the current one is expired but a
          valid refresh token exists.

        """
        from chowkidar.settings import JWT_ACCESS_TOKEN_COOKIE_NAME
        from chowkidar.settings import JWT_REFRESH_TOKEN_COOKIE_NAME
        from chowkidar.utils.jwt import generate_token_from_claims

        self._init_request_state()

        execution_context = self.execution_context
        self._request = execution_context.context["request"]

        access_token_payload = self._get_token_payload_from_cookie(JWT_ACCESS_TOKEN_COOKIE_NAME)

        refresh_token_payload = self._get_token_payload_from_cookie(JWT_REFRESH_TOKEN_COOKIE_NAME)
        if refresh_token_payload is not None:
            self.refreshToken = refresh_token_payload["refreshToken"]

        if access_token_payload is not None:
            self.userID = access_token_payload["userID"]

        elif refresh_token_payload is not None:
            self.refreshTokenObj: AbstractRefreshToken = self._get_refresh_token_object()

            if self.refreshTokenObj is not None:
                self.refreshToken = self.refreshTokenObj.token
                user = self.refreshTokenObj.user

                user.last_login = timezone.now()
                user.save()

                self._new_JWT_access_token = generate_token_from_claims(
                    claims={
                        "userID": user.id,
                        "origIat": self.refreshTokenObj.issued.timestamp(),
                    },
                    expiration_delta=self.refreshTokenObj.get_access_token_expiry_delta(),
                )

                self.userID = user.id

        else:
            if self.is_cookie_in_request(JWT_ACCESS_TOKEN_COOKIE_NAME) or self.is_cookie_in_request(
                JWT_REFRESH_TOKEN_COOKIE_NAME
            ):
                self._remove_auth_cookies = True

        yield

    def resolve(
        self,
        _next: Callable,
        root: object,
        info: strawberry.Info,
        *args: tuple,
        **kwargs: dict,
    ):
        """Populate ``info.context`` with auth state on every field resolution.

        Parameters
        ----------
        _next : Callable
            The next resolver in the middleware chain.
        root : object
            The parent resolved value.
        info : Info
            The Strawberry resolver info object.
        *args : tuple
            Additional positional arguments.
        **kwargs : dict
            Additional keyword arguments forwarded to the next resolver.

        Returns
        -------
        Any
            The result of calling ``_next``.

        """
        if not hasattr(self, "_new_JWT_access_token"):
            self._new_JWT_access_token = None

        if not hasattr(self, "_remove_auth_cookies"):
            self._remove_auth_cookies = False

        if self._new_JWT_access_token is not None:
            setattr(
                info.context.request,
                "REFRESHED_ACCESS_TOKEN",
                self._new_JWT_access_token,
            )

        elif self._remove_auth_cookies:
            setattr(
                info.context.request,
                "PERFORM_LOGOUT",
                True,
            )

        setattr(
            info.context,
            "refreshTokenObj",
            getattr(self, "refreshTokenObj", None),
        )
        setattr(
            info.context,
            "refreshToken",
            getattr(self, "refreshToken", None),
        )
        setattr(
            info.context,
            "userID",
            getattr(self, "userID", None),
        )
        setattr(
            info.context,
            "request",
            getattr(self, "_request", None),
        )

        return _next(
            root,
            info,
            **kwargs,
        )


__all__ = ["JWTAuthExtension"]
