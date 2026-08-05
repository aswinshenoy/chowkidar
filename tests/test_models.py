"""
Tests for chowkidar/models.py

Covers:
  - Meta constraints (UniqueConstraint, not unique_together)
  - generate_token() produces hex tokens of correct length
  - get_access_token_expiry_delta() returns configured timedelta
  - get_refresh_token_expiry_delta() returns configured timedelta
  - get_token() with and without _cached_token
  - process_request_before_save() is a no-op hook
  - save() auto-generates token on first save
  - __str__() returns the token string
"""

import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from django.db import models

from chowkidar.models import AbstractRefreshToken


class TestAbstractRefreshTokenMeta(unittest.TestCase):
    """Tests for the Meta class migration from unique_together to UniqueConstraint."""

    def test_no_unique_together(self) -> None:
        meta = AbstractRefreshToken._meta
        self.assertFalse(
            meta.unique_together,
            f"unique_together should be empty, got: {meta.unique_together}",
        )

    def test_has_constraints(self) -> None:
        constraints = AbstractRefreshToken._meta.constraints
        self.assertGreaterEqual(
            len(constraints),
            1,
            "Expected at least one constraint",
        )

    def test_constraint_is_unique_constraint(self) -> None:
        constraint = AbstractRefreshToken._meta.constraints[0]
        self.assertIsInstance(constraint, models.UniqueConstraint)

    def test_constraint_fields(self) -> None:
        constraint = AbstractRefreshToken._meta.constraints[0]
        self.assertEqual(
            list(constraint.fields),
            ["token", "revoked"],
        )

    def test_constraint_name_uses_template(self) -> None:
        constraint = AbstractRefreshToken._meta.constraints[0]
        self.assertTrue(
            "%(app_label)s" in constraint.name or "%(class)s" in constraint.name,
            f"Constraint name should use template syntax, got: {constraint.name}",
        )


class TestGenerateToken(unittest.TestCase):
    """Tests for AbstractRefreshToken.generate_token()."""

    @patch("chowkidar.models.urandom")
    def test_generate_token_returns_hex_string(
        self,
        mock_urandom: MagicMock,
    ) -> None:
        mock_urandom.return_value = b"\xab\xcd\xef\x01\x23" * 4
        token = AbstractRefreshToken.generate_token()
        self.assertIsInstance(
            token,
            str,
            "generate_token should return a string",
        )
        self.assertTrue(
            all(c in "0123456789abcdef" for c in token),
            "Token should be hex-encoded",
        )

    @patch("chowkidar.settings.JWT_REFRESH_TOKEN_N_BYTES", 20)
    def test_generate_token_length(self) -> None:
        token = AbstractRefreshToken.generate_token()
        self.assertEqual(
            len(token),
            40,
            "Token should be 2 * N_BYTES hex characters",
        )


class TestExpiryDeltas(unittest.TestCase):
    """Tests for get_access_token_expiry_delta and get_refresh_token_expiry_delta."""

    def test_get_access_token_expiry_delta_returns_timedelta(self) -> None:
        from datetime import timedelta

        result = AbstractRefreshToken.get_access_token_expiry_delta()
        self.assertIsInstance(
            result,
            timedelta,
            "Should return a timedelta",
        )

    def test_get_refresh_token_expiry_delta_returns_timedelta(self) -> None:
        from datetime import timedelta

        result = AbstractRefreshToken.get_refresh_token_expiry_delta()
        self.assertIsInstance(
            result,
            timedelta,
            "Should return a timedelta",
        )


class TestGetToken(unittest.TestCase):
    """Tests for AbstractRefreshToken.get_token()."""

    def test_get_token_returns_cached_token_when_present(self) -> None:
        instance = AbstractRefreshToken.__new__(AbstractRefreshToken)
        instance.token = "db-token"
        instance._cached_token = "cached-token"

        self.assertEqual(
            instance.get_token(),
            "cached-token",
            "Should return _cached_token when it exists",
        )

    def test_get_token_returns_token_when_no_cache(self) -> None:
        instance = AbstractRefreshToken.__new__(AbstractRefreshToken)
        instance.token = "db-token"

        self.assertEqual(
            instance.get_token(),
            "db-token",
            "Should return token field when _cached_token is absent",
        )


class TestProcessRequestBeforeSave(unittest.TestCase):
    """Tests for AbstractRefreshToken.process_request_before_save()."""

    def test_process_request_before_save_is_noop(self) -> None:
        instance = AbstractRefreshToken.__new__(AbstractRefreshToken)
        mock_request = MagicMock()

        result = instance.process_request_before_save(mock_request)

        self.assertIsNone(
            result,
            "Default process_request_before_save should return None",
        )


class TestSave(unittest.TestCase):
    """Tests for AbstractRefreshToken.save() auto-generation."""

    @patch.object(models.Model, "save")
    def test_save_generates_token_when_empty(
        self,
        mock_super_save: MagicMock,
    ) -> None:
        instance = AbstractRefreshToken.__new__(AbstractRefreshToken)
        instance.token = ""

        instance.save()

        self.assertTrue(
            len(instance.token) > 0,
            "save() should generate a token when token is empty",
        )
        self.assertEqual(
            instance._cached_token,
            instance.token,
            "save() should cache the generated token",
        )
        mock_super_save.assert_called_once()

    @patch.object(models.Model, "save")
    def test_save_preserves_existing_token(
        self,
        mock_super_save: MagicMock,
    ) -> None:
        instance = AbstractRefreshToken.__new__(AbstractRefreshToken)
        instance.token = "existing-token"

        instance.save()

        self.assertEqual(
            instance.token,
            "existing-token",
            "save() should not overwrite an existing token",
        )
        mock_super_save.assert_called_once()


class TestStr(unittest.TestCase):
    """Tests for AbstractRefreshToken.__str__()."""

    def test_str_returns_token(self) -> None:
        instance = AbstractRefreshToken.__new__(AbstractRefreshToken)
        instance.token = "my-refresh-token-string"

        self.assertEqual(
            str(instance),
            "my-refresh-token-string",
            "__str__ should return the token string",
        )


class TestRefreshTokenSecurityEdgeCases(unittest.TestCase):
    """Security edge cases for AbstractRefreshToken."""

    def test_generate_token_is_cryptographically_random(self) -> None:
        """Two generated tokens must not collide."""
        token1 = AbstractRefreshToken.generate_token()
        token2 = AbstractRefreshToken.generate_token()

        self.assertNotEqual(
            token1,
            token2,
            "Consecutive generate_token calls must produce unique values",
        )

    def test_generate_token_sufficient_entropy(self) -> None:
        """Default 20 bytes = 40 hex chars = 160 bits of entropy."""
        token = AbstractRefreshToken.generate_token()
        self.assertGreaterEqual(
            len(token),
            40,
            "Token must have at least 160 bits of entropy (40 hex chars)",
        )

    @patch.object(models.Model, "save")
    def test_save_does_not_regenerate_on_second_save(
        self,
        mock_super_save: MagicMock,
    ) -> None:
        """Token must not change on subsequent saves (update scenario)."""
        instance = AbstractRefreshToken.__new__(AbstractRefreshToken)
        instance.token = ""

        instance.save()
        first_token = instance.token

        instance.save()

        self.assertEqual(
            instance.token,
            first_token,
            "Token must not change on second save",
        )

    def test_str_does_not_expose_user_data(self) -> None:
        """__str__ must only return the token, not user info."""
        instance = AbstractRefreshToken.__new__(AbstractRefreshToken)
        instance.token = "abc123"

        result = str(instance)

        self.assertEqual(result, "abc123")
        self.assertNotIn("user", result.lower())
