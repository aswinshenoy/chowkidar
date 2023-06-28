from typing import Optional

from django.http import HttpRequest
from django.apps import apps
from django.conf import settings

from .utils import validate_email
from .utils.exceptions import AuthError

User = apps.get_model(settings.AUTH_USER_MODEL, require_ready=False)


def authenticate_with_username(password: str, username: str, request: Optional[HttpRequest] = None) -> User:
    from django.contrib.auth import authenticate
    user = authenticate(request=request, username=username, password=password)
    if user is None:
        msg = 'The username or password you entered is wrong'
        if username is None:
            msg = 'The email or password you entered is wrong'
        raise AuthError(message=msg, code='INVALID_CREDENTIALS')
    return user


def authenticate_with_email(password: str, email: str, request: Optional[HttpRequest] = None) -> User:
    try:
        username = User.objects.get(email__iexact=validate_email(email)).username
        return authenticate_with_username(password=password, username=username, request=request)
    except User.DoesNotExist:
        raise AuthError(message='An account with this email address does not exist', code='EMAIL_NOT_FOUND')
    except User.MultipleObjectsReturned:
        raise AuthError(
            message='We cannot authenticate you with your email address, please enter your username',
            code='EMAIL_NOT_UNIQUE'
        )


def authenticate(
    password: str,
    username: Optional[str] = None,
    email: Optional[str] = None,
    request: Optional[HttpRequest] = None
) -> User:
    if username is None and email is None:
        raise AuthError(message='Email or username is required for authentication', code='EMAIL_USERNAME_MISSING')
    if email is not None:
        user = authenticate_with_email(email=email, password=password, request=request)
    else:
        user = authenticate_with_username(username=username, password=password, request=request)
    return user


__all__ = [
    'authenticate_with_username',
    'authenticate_with_email',
    'authenticate'
]
