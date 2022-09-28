from django.conf import settings
from django.utils import timezone

JWT_REFRESH_TOKEN_N_BYTES = (
    settings.JWT_REFRESH_TOKEN_N_BYTES
    if hasattr(settings, "JWT_REFRESH_TOKEN_N_BYTES")
    else 20
)

# Expiry Settings

JWT_ACCESS_TOKEN_EXPIRATION_DELTA = (
    settings.JWT_ACCESS_TOKEN_EXPIRATION_DELTA
    if hasattr(settings, "JWT_ACCESS_TOKEN_EXPIRATION_DELTA")
    else timezone.timedelta(seconds=60)
)

JWT_REFRESH_TOKEN_EXPIRATION_DELTA = (
    settings.JWT_REFRESH_TOKEN_EXPIRATION_DELTA
    if hasattr(settings, "JWT_REFRESH_TOKEN_EXPIRATION_DELTA")
    else timezone.timedelta(seconds=60 * 60 * 24 * 7)
)

# Cookie Settings

JWT_ACCESS_TOKEN_COOKIE_NAME = (
    settings.JWT_ACCESS_TOKEN_COOKIE_NAME
    if hasattr(settings, "JWT_ACCESS_TOKEN_COOKIE_NAME")
    else 'JWT_ACCESS_TOKEN'
)

JWT_REFRESH_TOKEN_COOKIE_NAME = (
    settings.JWT_REFRESH_TOKEN_COOKIE_NAME
    if hasattr(settings, "JWT_REFRESH_TOKEN_COOKIE_NAME")
    else 'JWT_REFRESH_TOKEN'
)

JWT_COOKIE_DOMAIN = settings.JWT_COOKIE_DOMAIN if hasattr(settings, "JWT_COOKIE_DOMAIN") else None
JWT_COOKIE_SAME_SITE = settings.JWT_COOKIE_SAME_SITE if hasattr(settings, "JWT_COOKIE_SAME_SITE") else "Lax"
JWT_COOKIE_SECURE = settings.JWT_COOKIE_SECURE if hasattr(settings, "JWT_COOKIE_SECURE") else False
JWT_COOKIE_HTTP_ONLY = settings.JWT_COOKIE_HTTP_ONLY if hasattr(settings, "JWT_COOKIE_HTTP_ONLY") else True


# JWT Settings
JWT_SECRET_KEY = (
    settings.JWT_SECRET_KEY
    if hasattr(settings, "JWT_SECRET_KEY")
    else settings.SECRET_KEY
)
JWT_PUBLIC_KEY = (
    settings.JWT_PUBLIC_KEY if hasattr(settings, "JWT_PUBLIC_KEY") else None
)
JWT_PRIVATE_KEY = (
    settings.JWT_PRIVATE_KEY if hasattr(settings, "JWT_PRIVATE_KEY") else None
)

JWT_ALGORITHM = settings.JWT_ALGORITHM if hasattr(settings, "JWT_ALGORITHM") else "HS256"
JWT_LEEWAY = settings.JWT_LEEWAY if hasattr(settings, "JWT_LEEWAY") else 0
JWT_ISSUER = settings.JWT_ISSUER if hasattr(settings, "JWT_ISSUER") else None

REFRESH_TOKEN_MODEL = (
    settings.REFRESH_TOKEN_MODEL if hasattr(settings, "REFRESH_TOKEN_MODEL") else None
)
