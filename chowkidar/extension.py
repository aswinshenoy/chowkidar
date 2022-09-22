from typing import Optional
from django.http import HttpRequest
from django.utils import timezone
from ipware import get_client_ip
from strawberry.extensions import Extension
from strawberry.types import ExecutionContext, Info

from .settings import (
    JWT_REFRESH_TOKEN_EXPIRATION_DELTA,
    JWT_ACCESS_TOKEN_EXPIRATION_DELTA,
    JWT_REFRESH_TOKEN_COOKIE_NAME,
    JWT_ACCESS_TOKEN_COOKIE_NAME,
)
from .utils.exceptions import AuthError
from .utils.jwt import decode_payload_from_token, generate_token_from_claims
from .models import RefreshToken


class JWTAuthExtension(Extension):
    """
    Strawberry extension to process the request, setup info.context.userID and perform token refresh.
    This class persists throughout the processing of entire request, and is called multiple times.

    This extension must be added, and registered with the strawberry schema, -
    strawberry.Schema(query=Query, mutation=Mutation, extensions=[JWTAuthExtension,])

    Read more about custom extensions here -> https://strawberry.rocks/docs/guides/custom-extensions
    """

    def __init__(self, *, execution_context: ExecutionContext):
        self._request: Optional[HttpRequest] = None

        self.IPAddress = None
        self.userID = None

        self.refreshToken = None
        self.refreshTokenObj: Optional[RefreshToken] = None

        self._newJWTToken = None
        self._remove_auth_cookies = False

        super().__init__(execution_context=execution_context)

    def _get_token_payload_from_cookie(self, cookie_name: str) -> Optional[dict]:
        """
        Get token payload from request cookies for the cookie_name given after decoding the token, if it exists

        :param cookie_name: name of the cookie which carries the token
        :return: JWT Access Token as str
        """
        if (
            cookie_name in self._request.COOKIES and
            self._request.COOKIES[cookie_name]
        ):
            try:
                return decode_payload_from_token(token=self._request.COOKIES[cookie_name])
            except AuthError:
                return None

    def _get_valid_refresh_token_from_request(self) -> Optional[RefreshToken]:
        """
        Get RefreshToken object from the request cookie, if it exists and is valid.
        The refresh token is valid if it is not expired and is not revoked.
        A DB query is made only if the refresh token is present in the request cookie.

        :return: A RefreshToken object if a valid refresh token is available, else None
        """

        # Resolve refresh token string from the cookie
        refresh_token_payload = self._get_token_payload_from_cookie(JWT_REFRESH_TOKEN_COOKIE_NAME)
        if not refresh_token_payload:
            self._remove_auth_cookies = True
            return None

        # Verify the refresh token validity with database, and get the RefreshToken object
        try:
            return RefreshToken.objects.get(
                token=refresh_token_payload["refreshToken"],
                # Avoid revoked tokens -  A refresh token is revoked if the revoked (timestamp) is set.
                revoked__isnull=True,
                # Avoid expired tokens -
                # JWT_REFRESH_TOKEN_EXPIRATION_DELTA + issued_at (timestamp) > now for a valid token
                issued__gte=timezone.now() - JWT_REFRESH_TOKEN_EXPIRATION_DELTA,
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
        """
        execution_context = self.execution_context
        self._request = execution_context.context["request"]

        # Resolve IP Address
        ip, is_routable = get_client_ip(self._request)
        self.IPAddress = ip

        # Resolve Access Token
        access_token_payload = self._get_token_payload_from_cookie(JWT_ACCESS_TOKEN_COOKIE_NAME)

        if access_token_payload:  # if a valid access token was available, then we set the userID directly
            self.userID = access_token_payload["userID"]
        else:
            # Resolve Refresh Token from request, if it exists and is valid
            self.refreshTokenObj: RefreshToken = self._get_valid_refresh_token_from_request()

            # if a valid refresh token was available, then we generate a new access token
            if self.refreshTokenObj is not None:
                self.refreshToken = self.refreshTokenObj.token
                user = self.refreshTokenObj.user

                # update last login timestamp of the user
                user.last_login = timezone.now()
                user.save()

                # generate a new access token to be given to the user
                self._newJWTToken = generate_token_from_claims(
                    claims={
                        "userID": user.id,
                        "origIat": self.refreshTokenObj.issued.timestamp(),
                    },
                    expiration_delta=JWT_ACCESS_TOKEN_EXPIRATION_DELTA,
                )

                self.userID = user.id

    def resolve(self, _next, root, info: Info, *args, **kwargs):
        """
            This function is called by strawberry after everytime it resolves a field/type.
            So for efficiency, resolving or much processing should not be done here.
            Therefore, we already use the on_request_start() function to resolve and cache required data in the class.
        """
        # In case refresh token was not available or was invalid, we remove all the auth cookies from the response
        if self._remove_auth_cookies:
            setattr(info.context.request, "REMOVE_REFRESH_TOKEN", True)
            setattr(info.context.request, "REMOVE_JWT_TOKEN", True)

        else:
            # Incase a new JWT access token was generated earlier from `on_request_start`, we set it to request contest
            # this will be later picked up by view.py and to set the access token cookie in the response
            if self._newJWTToken is not None:
                setattr(info.context.request, "NEW_JWT_TOKEN", self._newJWTToken)

            # sets up info.context.userID, info.context.IPAddress
            setattr(info.context, "userID", self.userID)
            setattr(info.context, "IPAddress", self.IPAddress)

            setattr(info.context, "refreshTokenObj", self.refreshTokenObj)
            setattr(info.context, "refreshToken", self.refreshToken)

        return _next(root, info, **kwargs)


__all__ = [
    "JWTAuthExtension"
]
