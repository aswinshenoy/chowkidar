from datetime import timedelta

from django.db import models
from django.conf import settings
from django.http import HttpRequest


class AbstractRefreshToken(models.Model):
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
    def generate_token():
        """Generates a refresh token"""
        from binascii import hexlify
        from os import urandom
        from .settings import JWT_REFRESH_TOKEN_N_BYTES
        return hexlify(urandom(JWT_REFRESH_TOKEN_N_BYTES)).decode()

    @staticmethod
    def get_access_token_expiry_delta() -> timedelta:
        """
         Returns the expiry delta for access tokens
        """
        from .settings import JWT_ACCESS_TOKEN_EXPIRATION_DELTA
        return JWT_ACCESS_TOKEN_EXPIRATION_DELTA

    @staticmethod
    def get_refresh_token_expiry_delta() -> timedelta:
        """
         Returns the expiry delta for refresh tokens
        """
        from .settings import JWT_REFRESH_TOKEN_EXPIRATION_DELTA
        return JWT_REFRESH_TOKEN_EXPIRATION_DELTA

    def get_token(self):
        if hasattr(self, "_cached_token"):
            return self._cached_token
        return self.token

    def process_request_before_save(self, request: HttpRequest) -> None:
        """
        This function is called just before a new refresh token is saved.
        This can be used to add additional information to the refresh token.

        :param request: HTTP request object
        :return: None
        """
        pass

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = self._cached_token = self.generate_token()
        super().save(*args, **kwargs)

    class Meta:
        abstract = True
        verbose_name_plural = "User Refresh Tokens"
        verbose_name = "User Refresh Token"
        unique_together = [
            # (token, revoked) ensures uniqueness of non-revoked tokens (since revoked=null)
            ("token", "revoked")
        ]

    def __str__(self):
        return self.token


__all__ = [
    'AbstractRefreshToken'
]
