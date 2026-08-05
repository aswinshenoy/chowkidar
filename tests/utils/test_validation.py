"""
Tests for chowkidar/utils/validation.py

Covers:
  - validate_email() with valid and invalid emails
  - edge cases: empty string, missing parts, special characters
"""

import unittest

from parameterized import parameterized


class TestValidateEmail(unittest.TestCase):
    """Tests for validate_email() regex validation."""

    @parameterized.expand(
        [
            (
                "simple_email",
                "user@example.com",
            ),
            (
                "email_with_dots",
                "first.last@example.com",
            ),
            (
                "email_with_plus",
                "user+tag@example.com",
            ),
            (
                "email_with_underscore",
                "user_name@example.com",
            ),
            (
                "email_with_hyphen_domain",
                "user@my-domain.com",
            ),
            (
                "email_with_subdomain",
                "user@sub.domain.com",
            ),
        ]
    )
    def test_validate_email_valid(
        self,
        case_name: str,
        email: str,
    ) -> None:
        from chowkidar.utils.validation import validate_email

        result = validate_email(email)

        self.assertEqual(
            result,
            email,
            f"Valid email '{email}' should be returned unchanged",
        )

    @parameterized.expand(
        [
            (
                "missing_at_sign",
                "userexample.com",
            ),
            (
                "missing_domain",
                "user@",
            ),
            (
                "missing_username",
                "@example.com",
            ),
            (
                "missing_tld",
                "user@example",
            ),
            (
                "spaces_in_email",
                "user @example.com",
            ),
            (
                "double_at_sign",
                "user@@example.com",
            ),
            (
                "empty_string",
                "",
            ),
        ]
    )
    def test_validate_email_invalid(
        self,
        case_name: str,
        email: str,
    ) -> None:
        from chowkidar.utils.exceptions import AuthError
        from chowkidar.utils.validation import validate_email

        with self.assertRaises(AuthError) as ctx:
            validate_email(email)

        self.assertEqual(
            ctx.exception.code,
            "INVALID_EMAIL",
            f"Invalid email '{email}' should raise AuthError with INVALID_EMAIL code",
        )

    @parameterized.expand(
        [
            (
                "newline_injection",
                "user@example.com\nBcc: attacker@evil.com",
            ),
            (
                "null_byte",
                "user\x00@example.com",
            ),
            (
                "tab_in_local",
                "user\t@example.com",
            ),
            (
                "carriage_return",
                "user@example.com\r\n",
            ),
            (
                "semicolon_injection",
                "user@example.com; DROP TABLE users;",
            ),
            (
                "angle_bracket_xss",
                "<script>alert(1)</script>@example.com",
            ),
            (
                "single_quote_sqli",
                "user'OR'1'='1@example.com",
            ),
            (
                "unicode_homograph",
                "user@exаmple.com",
            ),
        ]
    )
    def test_validate_email_security_injection(
        self,
        case_name: str,
        email: str,
    ) -> None:
        """Ensure injection attempts and malformed inputs are rejected."""
        from chowkidar.utils.exceptions import AuthError
        from chowkidar.utils.validation import validate_email

        with self.assertRaises(AuthError) as ctx:
            validate_email(email)

        self.assertEqual(
            ctx.exception.code,
            "INVALID_EMAIL",
            f"Security input '{case_name}' should be rejected",
        )


__all__ = ["TestValidateEmail"]
