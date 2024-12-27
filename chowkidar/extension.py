from typing import Optional
from django.http import HttpRequest
from django.utils import timezone
from strawberry.extensions import Extension
from strawberry.types import ExecutionContext, Info

from .settings import (
    JWT_REFRESH_TOKEN_COOKIE_NAME,
    JWT_ACCESS_TOKEN_COOKIE_NAME,
)
from .utils.exceptions import AuthError
from .utils.jwt import decode_payload_from_token, generate_token_from_claims
from .models import AbstractRefreshToken


class JWTAuthExtension(Extension):
    """
    Strawberry extension to process the request, setup info.context.userID and perform token refresh.
    This class persists throughout the processing of entire request, and is called multiple times.

    This extension must be added, and registered with the strawberry schema, -
    strawberry.Schema(query=Query, mutation=Mutation, extensions=[JWTAuthExtension,])

    Read more about custom extensions here -> https://strawberry.rocks/docs/guides/custom-extensions
    """

    def __init__(self, *, execution_context: ExecutionContext):
        # Initialize extension with the execution context
        super().__init__(execution_context=execution_context)
        # We don't initialize state here as it needs to be reset for each request
        # State will be initialized in on_request_start

    def _init_request_state(self) -> None:
        """
        Initialize/reset all state variables for the current request.
        This ensures each request gets a fresh state, preventing state leakage between requests.
        """
        self._request: Optional[HttpRequest] = None
        self.userID = None
        self.refreshToken = None
        self.refreshTokenObj: Optional[AbstractRefreshToken] = None
        self._new_JWT_access_token = None
        self._remove_auth_cookies = False

    def is_cookie_in_request(self, cookie_name: str) -> bool:
        return cookie_name in self._request.COOKIES and self._request.COOKIES[cookie_name]

    def _get_token_payload_from_cookie(self, cookie_name: str) -> Optional[dict]:
        """
        Get token payload from request cookies for the cookie_name given after decoding the token, if it exists

        :param cookie_name: name of the cookie which carries the token
        :return: JWT Access Token as str
        """
        if self.is_cookie_in_request(cookie_name):
            try:
                return decode_payload_from_token(token=self._request.COOKIES[cookie_name])
            except AuthError:
                return None

    def _get_refresh_token_object(self) -> Optional[AbstractRefreshToken]:
        """
        Get RefreshToken object from the already available self.refreshToken, if it exists and is valid.
        The refresh token is valid if it is not expired and is not revoked.

        :return: A RefreshToken object if a valid refresh token is available, else None
        """
        if self.refreshToken is None:
            return

        from django.apps import apps
        from .settings import REFRESH_TOKEN_MODEL
        RefreshToken = apps.get_model(REFRESH_TOKEN_MODEL, require_ready=False)

        # Verify the refresh token validity with database, and get the RefreshToken object
        try:
            return RefreshToken.objects.get(
                token=self.refreshToken,
                # Avoid revoked tokens -  A refresh token is revoked if the revoked (timestamp) is set.
                revoked__isnull=True,
                # Avoid expired tokens -
                # JWT_REFRESH_TOKEN_EXPIRATION_DELTA + issued_at (timestamp) > now for a valid token
                issued__gte=timezone.now() - RefreshToken().get_refresh_token_expiry_delta(),
            )
        except RefreshToken.DoesNotExist:
            self._remove_auth_cookies = True
            return None

    def on_request_start(self):
        """
        This function is called by strawberry before it starts to process/resolve the actual graphql query/mutation.
        This function performs the following tasks:
            - resolves and sets IP address of the client
            - resolve and cache requester userID in the class, which would later be used to set info.context.userID
            - generate a new JWT access token if the current one is expired, if there is an active refresh token

        Note: State is reset at the start of each request to prevent state leakage between requests
        due to potential extension instance reuse by Strawberry.
        """
        # Reset all state variables to ensure clean state for new request
        self._init_request_state()

        execution_context = self.execution_context
        self._request = execution_context.context["request"]

        # Resolve Access Token
        access_token_payload = self._get_token_payload_from_cookie(JWT_ACCESS_TOKEN_COOKIE_NAME)

        # Resolve Refresh Token
        refresh_token_payload = self._get_token_payload_from_cookie(JWT_REFRESH_TOKEN_COOKIE_NAME)
        if refresh_token_payload is not None:
            self.refreshToken = refresh_token_payload["refreshToken"]

        # if a valid access token cookie was available, then we set the userID directly from the cookie payload
        if access_token_payload is not None:
            self.userID = access_token_payload["userID"]

        # if a valid refresh token cookie was available, we try to generate new access token with the refresh token
        elif refresh_token_payload is not None:
            # Resolve Refresh Token model instance using the token resolved from cookie payload,
            # and thereby, also check if it exists and is valid in database records
            self.refreshTokenObj: AbstractRefreshToken = self._get_refresh_token_object()

            # if a valid refresh token was available, then we generate a new access token
            if self.refreshTokenObj is not None:
                self.refreshToken = self.refreshTokenObj.token
                user = self.refreshTokenObj.user

                # update last login timestamp of the user
                user.last_login = timezone.now()
                user.save()

                # generate a new access token to be given to the user
                self._new_JWT_access_token = generate_token_from_claims(
                    claims={
                        "userID": user.id,
                        "origIat": self.refreshTokenObj.issued.timestamp(),
                    },
                    expiration_delta=self.refreshTokenObj.get_access_token_expiry_delta(),
                )

                self.userID = user.id

        # if both access_token_payload & refresh_token_payload could not be resolved
        else:
            # if the cookies existed in the request, they are invalid now, and thus remove them
            if (
                self.is_cookie_in_request(JWT_ACCESS_TOKEN_COOKIE_NAME) or
                self.is_cookie_in_request(JWT_REFRESH_TOKEN_COOKIE_NAME)
            ):
                self._remove_auth_cookies = True

    def resolve(self, _next, root, info: Info, *args, **kwargs):
        """
        This function is called by strawberry after everytime it resolves a field/type.
        So for efficiency, resolving or much processing should not be done here.
        Therefore, we already use the on_request_start() function to resolve and cache required data in the class.
        """
        # Incase a new JWT access token was generated earlier from `on_request_start`, we set it to request contest
        # this will be later picked up by view.py and to set the access token cookie in the response
        if self._new_JWT_access_token is not None:
            setattr(info.context.request, "REFRESHED_ACCESS_TOKEN", self._new_JWT_access_token)

        # In case refresh token was not available or was invalid, we remove all the auth cookies from the response
        elif self._remove_auth_cookies:
            setattr(info.context.request, "PERFORM_LOGOUT", True)

        setattr(info.context, "refreshTokenObj", self.refreshTokenObj)
        setattr(info.context, "refreshToken", self.refreshToken)
        setattr(info.context, "userID", self.userID)
        setattr(info.context, "request", self._request)

        return _next(root, info, **kwargs)


__all__ = [
    "JWTAuthExtension"
]
