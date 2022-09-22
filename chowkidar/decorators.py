from functools import wraps


def login_required(resolver):
    """
       Wrap this decorator around any resolver function (query, mutation or field) to ensure that only requests from
       logged-in users get resolved, and others are given an empty response.

       Restricts access without hitting the DB, so is faster, and should be preferred over @resolve_user.
    """
    @wraps(resolver)
    def wrapper(parent, info, *args, **kwargs):
        userID = getattr(info.context, "userID", None)
        if userID:
            return resolver(parent, info, *args, **kwargs)
        return None

    return wrapper


def resolve_user(resolver):
    """
         Wrap this decorator around any resolver function (query, mutation or field) to resolve User instance of the
         requesting user to be set in info.context.user, or otherwise fails the request if requester is not logged-in.

        Hits the DB, so is inefficient than @login_required.
        Use @login_required if you only need to restrict access to logged in users.

        Do not use this decorator unless you need info.context.user (User instance of requester).
        Most of the time you could do away with info.context.userID which is available by default without any decorator.
    """

    @wraps(resolver)
    @login_required
    def wrapper(parent, info, *args, **kwargs):
        from django.apps import apps
        from django.conf import settings
        User = apps.get_model(settings.AUTH_USER_MODEL, require_ready=False)

        try:
            info.context.user = User.objects.get(id=info.context.userID)
        except User.DoesNotExist:
            return None
        return resolver(parent, info, *args, **kwargs)

    return wrapper


__all__ = [
    'resolve_user',
    'login_required'
]
