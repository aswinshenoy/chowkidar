"""
Tests for chowkidar/utils/exceptions.py

Covers:
  - APIError initialization, message, code, formatted property
  - AuthError initialization with and without code
  - PermissionDenied initialization with and without code
  - Edge cases: None message, empty string message
"""

import unittest

from parameterized import parameterized


class TestAPIError(unittest.TestCase):
    """Tests for APIError class."""

    def test_init_with_message_and_code(self) -> None:
        from chowkidar.utils.exceptions import APIError

        error = APIError(
            message="Something went wrong",
            code="TEST_ERROR",
        )

        self.assertEqual(error.message, "Something went wrong")
        self.assertEqual(error.code, "TEST_ERROR")
        self.assertEqual(error.locations, [])
        self.assertEqual(error.path, [])

    def test_init_with_message_only(self) -> None:
        from chowkidar.utils.exceptions import APIError

        error = APIError(message="Just a message")

        self.assertEqual(error.message, "Just a message")
        self.assertIsNone(error.code)

    def test_formatted_with_message_and_code(self) -> None:
        from chowkidar.utils.exceptions import APIError

        error = APIError(
            message="Bad request",
            code="BAD_REQUEST",
        )

        self.assertEqual(
            error.formatted,
            {"message": "Bad request", "code": "BAD_REQUEST"},
        )

    def test_formatted_with_none_message(self) -> None:
        from chowkidar.utils.exceptions import APIError

        error = APIError(message=None)

        self.assertEqual(
            error.formatted["message"],
            "An unknown error occurred.",
            "None message should fallback to default",
        )

    def test_formatted_with_none_code(self) -> None:
        from chowkidar.utils.exceptions import APIError

        error = APIError(message="err")

        self.assertEqual(
            error.formatted["code"],
            "UNKNOWN_ERROR",
            "None code should fallback to UNKNOWN_ERROR",
        )

    def test_formatted_with_empty_message(self) -> None:
        from chowkidar.utils.exceptions import APIError

        error = APIError(message="")

        self.assertEqual(
            error.formatted["message"],
            "An unknown error occurred.",
            "Empty string message should fallback to default",
        )

    def test_is_exception(self) -> None:
        from chowkidar.utils.exceptions import APIError

        error = APIError(message="test")

        self.assertIsInstance(error, Exception)

    def test_str_representation(self) -> None:
        from chowkidar.utils.exceptions import APIError

        error = APIError(message="test error")

        self.assertEqual(str(error), "test error")


class TestAuthError(unittest.TestCase):
    """Tests for AuthError class."""

    def test_init_with_code(self) -> None:
        from chowkidar.utils.exceptions import AuthError

        error = AuthError(
            message="Invalid token",
            code="INVALID_TOKEN",
        )

        self.assertEqual(error.message, "Invalid token")
        self.assertEqual(error.code, "INVALID_TOKEN")

    def test_init_without_code(self) -> None:
        from chowkidar.utils.exceptions import AuthError

        error = AuthError(message="Something failed")

        self.assertEqual(error.message, "Something failed")
        self.assertFalse(
            hasattr(error, "code"),
            "code attribute should not be set when None",
        )

    def test_is_exception(self) -> None:
        from chowkidar.utils.exceptions import AuthError

        error = AuthError(message="test")

        self.assertIsInstance(error, Exception)

    def test_str_representation(self) -> None:
        from chowkidar.utils.exceptions import AuthError

        error = AuthError(message="auth failed")

        self.assertEqual(str(error), "auth failed")

    @parameterized.expand(
        [
            (
                "expired_token",
                "Token expired",
                "EXPIRED_TOKEN",
            ),
            (
                "invalid_credentials",
                "Wrong password",
                "INVALID_CREDENTIALS",
            ),
            (
                "email_not_found",
                "No account",
                "EMAIL_NOT_FOUND",
            ),
        ]
    )
    def test_various_error_codes(
        self,
        case_name: str,
        message: str,
        code: str,
    ) -> None:
        from chowkidar.utils.exceptions import AuthError

        error = AuthError(message=message, code=code)

        self.assertEqual(error.message, message)
        self.assertEqual(error.code, code)


class TestPermissionDenied(unittest.TestCase):
    """Tests for PermissionDenied class."""

    def test_init_with_code(self) -> None:
        from chowkidar.utils.exceptions import PermissionDenied

        error = PermissionDenied(
            message="Access denied",
            code="FORBIDDEN",
        )

        self.assertEqual(error.message, "Access denied")
        self.assertEqual(error.code, "FORBIDDEN")

    def test_init_without_code(self) -> None:
        from chowkidar.utils.exceptions import PermissionDenied

        error = PermissionDenied(message="Not allowed")

        self.assertEqual(error.message, "Not allowed")
        self.assertFalse(
            hasattr(error, "code"),
            "code attribute should not be set when None",
        )

    def test_is_exception(self) -> None:
        from chowkidar.utils.exceptions import PermissionDenied

        error = PermissionDenied(message="test")

        self.assertIsInstance(error, Exception)

    def test_str_representation(self) -> None:
        from chowkidar.utils.exceptions import PermissionDenied

        error = PermissionDenied(message="denied")

        self.assertEqual(str(error), "denied")


__all__ = [
    "TestAPIError",
    "TestAuthError",
    "TestPermissionDenied",
]
