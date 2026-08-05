"""
Tests for chowkidar/utils/cookie.py

Covers:
  - set_cookie() sets cookie with correct attributes
  - delete_cookie() removes cookie
  - response passthrough (returns the same response object)
"""

from datetime import UTC
from datetime import datetime
import unittest
from unittest.mock import patch

from django.http import HttpResponse
from django.http import JsonResponse


class TestSetCookie(unittest.TestCase):
    """Tests for set_cookie()."""

    @patch("chowkidar.settings.JWT_COOKIE_DOMAIN", "example.com")
    @patch("chowkidar.settings.JWT_COOKIE_SECURE", True)
    @patch("chowkidar.settings.JWT_COOKIE_HTTP_ONLY", True)
    @patch("chowkidar.settings.JWT_COOKIE_SAME_SITE", "Strict")
    def test_set_cookie_calls_response_set_cookie(self) -> None:
        from chowkidar.utils.cookie import set_cookie

        response = HttpResponse()
        expires = datetime(2030, 1, 1, tzinfo=UTC)

        result = set_cookie(
            name="test_cookie",
            value="test_value",
            response=response,
            expires=expires,
        )

        self.assertIs(
            result,
            response,
            "Should return the same response object",
        )
        self.assertIn(
            "test_cookie",
            result.cookies,
            "Cookie should be set on the response",
        )
        self.assertEqual(
            result.cookies["test_cookie"].value,
            "test_value",
            "Cookie value should match",
        )

    def test_set_cookie_returns_response(self) -> None:
        from chowkidar.utils.cookie import set_cookie

        response = JsonResponse({"ok": True})
        expires = datetime(2030, 1, 1, tzinfo=UTC)

        result = set_cookie(
            name="jwt_token",
            value="abc123",
            response=response,
            expires=expires,
        )

        self.assertIs(
            result,
            response,
            "Should return the same JsonResponse object",
        )

    @patch("chowkidar.settings.JWT_COOKIE_SECURE", False)
    @patch("chowkidar.settings.JWT_COOKIE_HTTP_ONLY", False)
    @patch("chowkidar.settings.JWT_COOKIE_SAME_SITE", "Lax")
    @patch("chowkidar.settings.JWT_COOKIE_DOMAIN", None)
    def test_set_cookie_with_insecure_settings(self) -> None:
        from chowkidar.utils.cookie import set_cookie

        response = HttpResponse()
        expires = datetime(2030, 1, 1, tzinfo=UTC)

        result = set_cookie(
            name="my_cookie",
            value="val",
            response=response,
            expires=expires,
        )

        cookie = result.cookies["my_cookie"]
        self.assertEqual(
            cookie["samesite"],
            "Lax",
            "SameSite should be Lax",
        )


class TestDeleteCookie(unittest.TestCase):
    """Tests for delete_cookie()."""

    def test_delete_cookie_returns_response(self) -> None:
        from chowkidar.utils.cookie import delete_cookie

        response = HttpResponse()

        result = delete_cookie(
            name="test_cookie",
            response=response,
        )

        self.assertIs(
            result,
            response,
            "Should return the same response object",
        )

    def test_delete_cookie_removes_cookie(self) -> None:
        from chowkidar.utils.cookie import set_cookie
        from chowkidar.utils.cookie import delete_cookie

        response = HttpResponse()
        expires = datetime(2030, 1, 1, tzinfo=UTC)

        set_cookie(
            name="to_delete",
            value="val",
            response=response,
            expires=expires,
        )
        result = delete_cookie(
            name="to_delete",
            response=response,
        )

        cookie = result.cookies.get("to_delete")
        self.assertEqual(
            cookie["max-age"],
            0,
            "Deleted cookie should have max-age=0",
        )


class TestCookieSecurityAttributes(unittest.TestCase):
    """Security tests verifying cookie attributes are enforced."""

    @patch("chowkidar.settings.JWT_COOKIE_DOMAIN", "example.com")
    @patch("chowkidar.settings.JWT_COOKIE_SECURE", True)
    @patch("chowkidar.settings.JWT_COOKIE_HTTP_ONLY", True)
    @patch("chowkidar.settings.JWT_COOKIE_SAME_SITE", "Strict")
    def test_secure_flag_is_set(self) -> None:
        """Cookie must have Secure flag when configured."""
        from chowkidar.utils.cookie import set_cookie

        response = HttpResponse()
        expires = datetime(2030, 1, 1, tzinfo=UTC)

        result = set_cookie(
            name="auth_token",
            value="secret",
            response=response,
            expires=expires,
        )

        cookie = result.cookies["auth_token"]
        self.assertTrue(
            cookie["secure"],
            "Cookie must have Secure flag set",
        )

    @patch("chowkidar.settings.JWT_COOKIE_DOMAIN", "example.com")
    @patch("chowkidar.settings.JWT_COOKIE_SECURE", True)
    @patch("chowkidar.settings.JWT_COOKIE_HTTP_ONLY", True)
    @patch("chowkidar.settings.JWT_COOKIE_SAME_SITE", "Strict")
    def test_httponly_flag_is_set(self) -> None:
        """Cookie must have HttpOnly flag to prevent JS access."""
        from chowkidar.utils.cookie import set_cookie

        response = HttpResponse()
        expires = datetime(2030, 1, 1, tzinfo=UTC)

        result = set_cookie(
            name="auth_token",
            value="secret",
            response=response,
            expires=expires,
        )

        cookie = result.cookies["auth_token"]
        self.assertTrue(
            cookie["httponly"],
            "Cookie must have HttpOnly flag to prevent XSS token theft",
        )

    @patch("chowkidar.settings.JWT_COOKIE_DOMAIN", "example.com")
    @patch("chowkidar.settings.JWT_COOKIE_SECURE", True)
    @patch("chowkidar.settings.JWT_COOKIE_HTTP_ONLY", True)
    @patch("chowkidar.settings.JWT_COOKIE_SAME_SITE", "Strict")
    def test_samesite_strict_is_set(self) -> None:
        """Cookie must have SameSite=Strict for CSRF protection."""
        from chowkidar.utils.cookie import set_cookie

        response = HttpResponse()
        expires = datetime(2030, 1, 1, tzinfo=UTC)

        result = set_cookie(
            name="auth_token",
            value="secret",
            response=response,
            expires=expires,
        )

        cookie = result.cookies["auth_token"]
        self.assertEqual(
            cookie["samesite"],
            "Strict",
            "Cookie must have SameSite=Strict for CSRF protection",
        )

    @patch("chowkidar.settings.JWT_COOKIE_DOMAIN", "example.com")
    @patch("chowkidar.settings.JWT_COOKIE_SECURE", True)
    @patch("chowkidar.settings.JWT_COOKIE_HTTP_ONLY", True)
    @patch("chowkidar.settings.JWT_COOKIE_SAME_SITE", "Strict")
    def test_domain_is_set(self) -> None:
        """Cookie domain must match configured value."""
        from chowkidar.utils.cookie import set_cookie

        response = HttpResponse()
        expires = datetime(2030, 1, 1, tzinfo=UTC)

        result = set_cookie(
            name="auth_token",
            value="secret",
            response=response,
            expires=expires,
        )

        cookie = result.cookies["auth_token"]
        self.assertEqual(
            cookie["domain"],
            "example.com",
            "Cookie domain should match configuration",
        )

    def test_delete_cookie_sets_max_age_zero(self) -> None:
        """Deleted cookies must expire immediately."""
        from chowkidar.utils.cookie import set_cookie
        from chowkidar.utils.cookie import delete_cookie

        response = HttpResponse()
        expires = datetime(2030, 1, 1, tzinfo=UTC)

        set_cookie(
            name="auth_token",
            value="secret",
            response=response,
            expires=expires,
        )
        result = delete_cookie(
            name="auth_token",
            response=response,
        )

        cookie = result.cookies["auth_token"]
        self.assertEqual(
            cookie["max-age"],
            0,
            "Deleted cookie must have max-age=0 to prevent reuse",
        )


__all__ = [
    "TestSetCookie",
    "TestDeleteCookie",
    "TestCookieSecurityAttributes",
]
