from functools import wraps

from .settings import (
    JWT_ACCESS_TOKEN_COOKIE_NAME,
    JWT_REFRESH_TOKEN_COOKIE_NAME,
)
from .utils.cookie import set_cookie, delete_cookie
from .utils.jwt import generate_token_from_claims


def auth_enabled_view(view_func):
    """
    Wrap the graphql endpoint view with this function to enable support for authentication.

    This function helps to manage the cookies for the access token and refresh token after the request has been
    processed, and HTTP response has been prepared. The data to this is passed through setting custom attributes
    on the request object (done by extension.py).

    For example, like this:-
    ```auth_enabled_view(GraphQLView.as_view(schema=schema, graphiql=settings.DEBUG))```
    """

    def set_refresh_token_cookie(request, response):
        if hasattr(request, "NEW_REFRESH_TOKEN"):
            rt = request.NEW_REFRESH_TOKEN
            data = generate_token_from_claims(
                claims={
                    "refreshToken": rt.get_token(),
                },
                expiration_delta=rt.get_refresh_token_expiry_delta(),
            )
            response = set_cookie(
                name=JWT_REFRESH_TOKEN_COOKIE_NAME,
                value=data["token"],
                expires=data["payload"]["exp"],
                response=response,
            )
        return response

    def set_access_token_cookie(request, response):
        if hasattr(request, "REFRESHED_ACCESS_TOKEN"):
            data = request.REFRESHED_ACCESS_TOKEN
            response = set_cookie(
                name=JWT_ACCESS_TOKEN_COOKIE_NAME,
                value=data["token"],
                expires=data["payload"]["exp"],
                response=response,
            )
        return response

    def finish_response(request, response):
        """
            This function is called after the view function has been processed by Django, and is ready with a response.
        """

        if hasattr(request, "PERFORM_LOGIN") or hasattr(request, "PERFORM_LOGOUT"):
            if hasattr(request, 'PERFORM_LOGIN'):
                response = set_refresh_token_cookie(request, response)
            else:
                response = delete_cookie(response=response, name=JWT_REFRESH_TOKEN_COOKIE_NAME)
                response = delete_cookie(response=response, name=JWT_ACCESS_TOKEN_COOKIE_NAME)
        elif hasattr(request, "REFRESHED_ACCESS_TOKEN"):
            response = set_access_token_cookie(request, response)

        return response

    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        return finish_response(request, view_func(request, *args, **kwargs))

    return wrapped_view


__all__ = [
    "auth_enabled_view",
]
