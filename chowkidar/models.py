from __future__ import annotations

from os import urandom
from binascii import hexlify
from datetime import timedelta

from django.db import models
from django.conf import settings
from django.http import HttpRequest


class AbstractRefreshToken(models.Model):
    """Abstract base model for JWT refresh tokens.

    Stores a per-user refresh token with issue and revocation timestamps.
    Subclass this model in your application and set ``REFRESH_TOKEN_MODEL``
    in Django settings to point to the concrete model.

    Attributes
    ----------
    id : int
        Auto-incrementing primary key.
    user : User
        Foreign key to the Django user model.
    token : str
        The refresh token string, generated on first save.
    issued : datetime
        Timestamp when the token was issued (auto-set on creation).
    revoked : datetime | None
        Timestamp when the token was revoked, or ``NULL`` if still valid.

    Notes
    -----
    - A token is considered valid when ``revoked`` is ``NULL`` and ``issued``
      is within the configured expiry window.
    - A unique constraint on ``(token, revoked)`` ensures only one active
      (non-revoked) token exists per token string.

    """

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="refresh_token",
        editable=False,
    )
    token = models.CharField(max_length=255, editable=False)
    issued = models.DateTimeField(auto_now_add=True, editable=False)
    revoked = models.DateTimeField(null=True, blank=True)

    @staticmethod
    def generate_token() -> str:
        """Generate a cryptographically random hex-encoded refresh token string.

        Returns
        -------
        str
            A hex-encoded random token of ``JWT_REFRESH_TOKEN_N_BYTES`` bytes.

        """
        from chowkidar.settings import JWT_REFRESH_TOKEN_N_BYTES

        return hexlify(urandom(JWT_REFRESH_TOKEN_N_BYTES)).decode()

    @staticmethod
    def get_access_token_expiry_delta() -> timedelta:
        """Return the configured expiry delta for access tokens.

        Returns
        -------
        timedelta
            The access token expiration duration from ``chowkidar.settings``.

        """
        from chowkidar.settings import JWT_ACCESS_TOKEN_EXPIRATION_DELTA

        return JWT_ACCESS_TOKEN_EXPIRATION_DELTA

    @staticmethod
    def get_refresh_token_expiry_delta() -> timedelta:
        """Return the configured expiry delta for refresh tokens.

        Returns
        -------
        timedelta
            The refresh token expiration duration from ``chowkidar.settings``.

        """
        from chowkidar.settings import JWT_REFRESH_TOKEN_EXPIRATION_DELTA

        return JWT_REFRESH_TOKEN_EXPIRATION_DELTA

    def get_token(self) -> str:
        """Return the token string, preferring the cached value set during save.

        Returns
        -------
        str
            The refresh token string.

        """
        if hasattr(self, "_cached_token"):
            return self._cached_token

        return self.token

    def process_request_before_save(self, request: HttpRequest) -> None:
        """Hook called before a new refresh token is saved.

        Override in a concrete subclass to attach additional request-derived
        data (e.g. IP address, user agent) to the token instance.

        Parameters
        ----------
        request : HttpRequest
            The current HTTP request object.

        """
        pass

    def save(self, *args, **kwargs):
        """Save the token, auto-generating a token string on first save.

        Parameters
        ----------
        *args : tuple
            Positional arguments forwarded to ``Model.save()``.
        **kwargs : dict
            Keyword arguments forwarded to ``Model.save()``.

        """
        if not self.token:
            self.token = self._cached_token = self.generate_token()

        super().save(*args, **kwargs)

    class Meta:
        """Abstract base model for JWT refresh tokens."""

        abstract = True
        verbose_name_plural = "User Refresh Tokens"
        verbose_name = "User Refresh Token"
        constraints = [
            models.UniqueConstraint(
                fields=["token", "revoked"],
                name="%(app_label)s_%(class)s_unique_token_revoked",
            )
        ]

    def __str__(self) -> str:
        """Return a string representation of the refresh token."""
        return self.token


__all__ = ["AbstractRefreshToken"]
