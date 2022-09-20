from functools import wraps

from .settings import (
    JWT_ACCESS_TOKEN_COOKIE_NAME,
    JWT_REFRESH_TOKEN_COOKIE_NAME,
    JWT_REFRESH_TOKEN_EXPIRATION_DELTA,
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

    def finish_response(request, response):
        """
            This function is called after the view function has been processed by Django, and is ready with a response.
        """

        # If the request was earlier set a NEW_JWT_TOKEN attribute by extension.py.
        # then we need to set a cookie with the new JWT access token.
        if hasattr(request, "NEW_JWT_TOKEN"):
            data = request.NEW_JWT_TOKEN
            response = set_cookie(
                name=JWT_ACCESS_TOKEN_COOKIE_NAME,
                value=data["token"],
                expires=data["payload"]["exp"],
                response=response,
            )

        # If the request was earlier set a NEW_REFRESH_TOKEN attribute by extension.py or by login decorator
        # then we need to set a cookie with the new JWT refresh token
        if hasattr(request, "NEW_REFRESH_TOKEN"):
            rt = request.NEW_REFRESH_TOKEN
            data = generate_token_from_claims(
                claims={
                    "refreshToken": rt.get_token(),
                },
                expiration_delta=JWT_REFRESH_TOKEN_EXPIRATION_DELTA,
            )
            response = set_cookie(
                name=JWT_REFRESH_TOKEN_COOKIE_NAME,
                value=data["token"],
                expires=data["payload"]["exp"],
                response=response,
            )

        # If the request was earlier set a REMOVE_JWT_TOKEN attribute by extension.py or by logout decorator
        # then we need to delete the JWT access token cookie
        if hasattr(request, "REMOVE_JWT_TOKEN"):
            delete_cookie(response=response, name=JWT_ACCESS_TOKEN_COOKIE_NAME)

        # If the request was earlier set a REMOVE_REFRESH_TOKEN attribute by extension.py or by logout decorator
        # then we need to delete the JWT refresh token cookie
        if hasattr(request, "REMOVE_REFRESH_TOKEN"):
            delete_cookie(response=response, name=JWT_REFRESH_TOKEN_COOKIE_NAME)

        return response

    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        request.jwt_cookie = True
        response = view_func(request, *args, **kwargs)
        return finish_response(request, response)

    return wrapped_view


__all__ = [
    "auth_enabled_view",
]
