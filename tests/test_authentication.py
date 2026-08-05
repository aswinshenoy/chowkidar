"""
Tests for chowkidar/authentication.py

Covers:
  - authenticate_with_username() success and failure paths
  - authenticate_with_email() success, not found, and multiple accounts
  - authenticate() dispatcher: email precedence, username fallback, missing both
  - Edge cases: None username message variant, invalid email
"""

import unittest
from unittest.mock import MagicMock
from unittest.mock import patch


class TestAuthenticateWithUsername(unittest.TestCase):
    """Tests for authenticate_with_username()."""

    @patch("django.contrib.auth.authenticate")
    def test_success_returns_user(
        self,
        mock_django_auth: MagicMock,
    ) -> None:
        from chowkidar.authentication import authenticate_with_username

        mock_user = MagicMock()
        mock_django_auth.return_value = mock_user

        result = authenticate_with_username(
            password="secret",
            username="testuser",
        )

        self.assertEqual(result, mock_user)

    @patch("django.contrib.auth.authenticate")
    def test_failure_raises_auth_error(
        self,
        mock_django_auth: MagicMock,
    ) -> None:
        from chowkidar.authentication import authenticate_with_username
        from chowkidar.utils.exceptions import AuthError

        mock_django_auth.return_value = None

        with self.assertRaises(AuthError) as ctx:
            authenticate_with_username(
                password="wrong",
                username="testuser",
            )

        self.assertEqual(ctx.exception.code, "INVALID_CREDENTIALS")
        self.assertIn("username", ctx.exception.message)

    @patch("django.contrib.auth.authenticate")
    def test_failure_with_none_username_shows_email_message(
        self,
        mock_django_auth: MagicMock,
    ) -> None:
        from chowkidar.authentication import authenticate_with_username
        from chowkidar.utils.exceptions import AuthError

        mock_django_auth.return_value = None

        with self.assertRaises(AuthError) as ctx:
            authenticate_with_username(
                password="wrong",
                username=None,
            )

        self.assertIn("email", ctx.exception.message)

    @patch("django.contrib.auth.authenticate")
    def test_passes_request_to_django_authenticate(
        self,
        mock_django_auth: MagicMock,
    ) -> None:
        from chowkidar.authentication import authenticate_with_username

        mock_user = MagicMock()
        mock_django_auth.return_value = mock_user
        mock_request = MagicMock()

        authenticate_with_username(
            password="secret",
            username="testuser",
            request=mock_request,
        )

        mock_django_auth.assert_called_once_with(
            request=mock_request,
            username="testuser",
            password="secret",
        )


class TestAuthenticateWithEmail(unittest.TestCase):
    """Tests for authenticate_with_email()."""

    @patch("django.contrib.auth.authenticate")
    @patch("chowkidar.authentication.User")
    def test_success_returns_user(
        self,
        mock_user_model: MagicMock,
        mock_django_auth: MagicMock,
    ) -> None:
        from chowkidar.authentication import authenticate_with_email

        mock_user_obj = MagicMock()
        mock_user_obj.username = "founduser"
        mock_user_model.objects.get.return_value = mock_user_obj
        mock_django_auth.return_value = MagicMock()

        result = authenticate_with_email(
            password="secret",
            email="user@example.com",
        )

        self.assertIsNotNone(result)

    @patch("chowkidar.authentication.User")
    def test_email_not_found_raises_auth_error(
        self,
        mock_user_model: MagicMock,
    ) -> None:
        from chowkidar.authentication import authenticate_with_email
        from chowkidar.utils.exceptions import AuthError

        mock_user_model.DoesNotExist = Exception
        mock_user_model.objects.get.side_effect = Exception

        with self.assertRaises(AuthError) as ctx:
            authenticate_with_email(
                password="secret",
                email="nobody@example.com",
            )

        self.assertEqual(ctx.exception.code, "EMAIL_NOT_FOUND")

    @patch("chowkidar.authentication.User")
    def test_multiple_accounts_raises_auth_error(
        self,
        mock_user_model: MagicMock,
    ) -> None:
        from chowkidar.authentication import authenticate_with_email
        from chowkidar.utils.exceptions import AuthError

        class MultipleReturned(Exception):
            pass

        mock_user_model.DoesNotExist = type("DoesNotExist", (Exception,), {})
        mock_user_model.MultipleObjectsReturned = MultipleReturned
        mock_user_model.objects.get.side_effect = MultipleReturned

        with self.assertRaises(AuthError) as ctx:
            authenticate_with_email(
                password="secret",
                email="dup@example.com",
            )

        self.assertEqual(ctx.exception.code, "EMAIL_NOT_UNIQUE")

    def test_invalid_email_raises_auth_error(self) -> None:
        from chowkidar.authentication import authenticate_with_email
        from chowkidar.utils.exceptions import AuthError

        with self.assertRaises(AuthError) as ctx:
            authenticate_with_email(
                password="secret",
                email="not-an-email",
            )

        self.assertEqual(ctx.exception.code, "INVALID_EMAIL")


class TestAuthenticate(unittest.TestCase):
    """Tests for the authenticate() dispatcher."""

    def test_missing_both_email_and_username_raises_error(self) -> None:
        from chowkidar.authentication import authenticate
        from chowkidar.utils.exceptions import AuthError

        with self.assertRaises(AuthError) as ctx:
            authenticate(password="secret")

        self.assertEqual(ctx.exception.code, "EMAIL_USERNAME_MISSING")

    @patch("chowkidar.authentication.authenticate_with_email")
    def test_email_takes_precedence_over_username(
        self,
        mock_auth_email: MagicMock,
    ) -> None:
        from chowkidar.authentication import authenticate

        mock_user = MagicMock()
        mock_auth_email.return_value = mock_user

        result = authenticate(
            password="secret",
            username="testuser",
            email="user@example.com",
        )

        self.assertEqual(result, mock_user)
        mock_auth_email.assert_called_once()

    @patch("chowkidar.authentication.authenticate_with_username")
    def test_username_fallback_when_no_email(
        self,
        mock_auth_username: MagicMock,
    ) -> None:
        from chowkidar.authentication import authenticate

        mock_user = MagicMock()
        mock_auth_username.return_value = mock_user

        result = authenticate(
            password="secret",
            username="testuser",
        )

        self.assertEqual(result, mock_user)
        mock_auth_username.assert_called_once()

    @patch("chowkidar.authentication.authenticate_with_email")
    def test_passes_request_through(
        self,
        mock_auth_email: MagicMock,
    ) -> None:
        from chowkidar.authentication import authenticate

        mock_request = MagicMock()
        mock_auth_email.return_value = MagicMock()

        authenticate(
            password="secret",
            email="user@example.com",
            request=mock_request,
        )

        mock_auth_email.assert_called_once_with(
            email="user@example.com",
            password="secret",
            request=mock_request,
        )


class TestAuthenticationSecurityEdgeCases(unittest.TestCase):
    """Security edge cases for authentication functions."""

    @patch("django.contrib.auth.authenticate")
    def test_empty_password_rejected(
        self,
        mock_django_auth: MagicMock,
    ) -> None:
        """Empty password should fail authentication."""
        from chowkidar.authentication import authenticate_with_username
        from chowkidar.utils.exceptions import AuthError

        mock_django_auth.return_value = None

        with self.assertRaises(AuthError) as ctx:
            authenticate_with_username(
                password="",
                username="testuser",
            )

        self.assertEqual(
            ctx.exception.code,
            "INVALID_CREDENTIALS",
            "Empty password should not authenticate",
        )

    @patch("django.contrib.auth.authenticate")
    def test_whitespace_only_password_rejected(
        self,
        mock_django_auth: MagicMock,
    ) -> None:
        """Whitespace-only password should fail authentication."""
        from chowkidar.authentication import authenticate_with_username
        from chowkidar.utils.exceptions import AuthError

        mock_django_auth.return_value = None

        with self.assertRaises(AuthError) as ctx:
            authenticate_with_username(
                password="   ",
                username="testuser",
            )

        self.assertEqual(ctx.exception.code, "INVALID_CREDENTIALS")

    def test_email_with_sql_injection_rejected(self) -> None:
        """SQL injection via email field should be rejected by validate_email."""
        from chowkidar.authentication import authenticate_with_email
        from chowkidar.utils.exceptions import AuthError

        with self.assertRaises(AuthError) as ctx:
            authenticate_with_email(
                password="secret",
                email="' OR 1=1 --@example.com",
            )

        self.assertEqual(
            ctx.exception.code,
            "INVALID_EMAIL",
            "SQL injection in email should be caught by validation",
        )

    def test_email_with_header_injection_rejected(self) -> None:
        """Header injection via email should be rejected."""
        from chowkidar.authentication import authenticate_with_email
        from chowkidar.utils.exceptions import AuthError

        with self.assertRaises(AuthError) as ctx:
            authenticate_with_email(
                password="secret",
                email="user@example.com\r\nBcc:attacker@evil.com",
            )

        self.assertEqual(ctx.exception.code, "INVALID_EMAIL")

    def test_both_none_explicitly_raises_error(self) -> None:
        """Explicitly passing None for both should raise."""
        from chowkidar.authentication import authenticate
        from chowkidar.utils.exceptions import AuthError

        with self.assertRaises(AuthError) as ctx:
            authenticate(
                password="secret",
                username=None,
                email=None,
            )

        self.assertEqual(ctx.exception.code, "EMAIL_USERNAME_MISSING")

    @patch("django.contrib.auth.authenticate")
    def test_very_long_username_handled(
        self,
        mock_django_auth: MagicMock,
    ) -> None:
        """Very long username should not crash, just fail auth."""
        from chowkidar.authentication import authenticate_with_username
        from chowkidar.utils.exceptions import AuthError

        mock_django_auth.return_value = None

        with self.assertRaises(AuthError):
            authenticate_with_username(
                password="secret",
                username="a" * 10000,
            )

    @patch("django.contrib.auth.authenticate")
    def test_very_long_password_handled(
        self,
        mock_django_auth: MagicMock,
    ) -> None:
        """Very long password should not crash, just fail auth."""
        from chowkidar.authentication import authenticate_with_username
        from chowkidar.utils.exceptions import AuthError

        mock_django_auth.return_value = None

        with self.assertRaises(AuthError):
            authenticate_with_username(
                password="x" * 100000,
                username="testuser",
            )


__all__ = [
    "TestAuthenticateWithUsername",
    "TestAuthenticateWithEmail",
    "TestAuthenticate",
    "TestAuthenticationSecurityEdgeCases",
]
