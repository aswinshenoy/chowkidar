from functools import wraps
from django.http import HttpRequest

from .utils import get_context


def issue_tokens_on_login(f):
    """
    Wrap this decorator around a graphql resolver function (eg- Login Mutation) to issue auth tokens and login the user.
    The wrapped resolver function must set info.context.LOGIN_USER to the User model instance.
    """

    def generate_refresh_token(userID, request: HttpRequest):
        from django.apps import apps
        from .settings import REFRESH_TOKEN_MODEL
        RefreshToken = apps.get_model(REFRESH_TOKEN_MODEL, require_ready=False)

        token = RefreshToken(user_id=userID)
        token.process_request_before_save(request)
        token.save()
        return token

    @wraps(f)
    def wrapper(cls, info, *args, **kwargs):
        result = f(cls, info, *args, **kwargs)
        ctx = get_context(info)
        if hasattr(info.context, "LOGIN_USER") and info.context.LOGIN_USER:
            token = generate_refresh_token(info.context.LOGIN_USER.id, ctx)
            ctx.PERFORM_LOGIN = True
            ctx.NEW_REFRESH_TOKEN = token
        return result

    return wrapper


def revoke_tokens_on_logout(f):
    """
    Wrap this decorator around a graphql resolver function (eg- Logout Mutation) to revoke auth tokens and logout the
    user. To revoke, the wrapped resolver function must set info.context.LOGOUT_USER to True.
    """

    @wraps(f)
    def wrapper(cls, info, *args, **kwargs):
        result = f(cls, info, *args, **kwargs)
        ctx = get_context(info)
        if hasattr(info.context, "LOGOUT_USER") and info.context.LOGOUT_USER:

            # Revoke associated refresh token model instance
            if info.context.userID and info.context.refreshToken:
                from django.apps import apps
                from django.utils import timezone
                from .settings import REFRESH_TOKEN_MODEL

                RefreshToken = apps.get_model(REFRESH_TOKEN_MODEL, require_ready=False)

                RefreshToken.objects.filter(
                    token=info.context.refreshToken, user_id=info.context.userID
                ).update(revoked=timezone.now())

            # Used to remove the JWT Access Token & Refresh Token cookies from the response
            ctx.PERFORM_LOGOUT = True
        return result

    return wrapper


__all__ = [
    "issue_tokens_on_login",
    "revoke_tokens_on_logout"
]
