"""
Tests for chowkidar/decorators.py

Covers:
  - @login_required allows authenticated users
  - @login_required blocks unauthenticated users (returns None)
  - @login_required with userID=0 or userID=None
  - @resolve_user sets info.context.user on success
  - @resolve_user returns None when user doesn't exist
  - @resolve_user returns None when not authenticated
"""

import unittest
from unittest.mock import MagicMock
from unittest.mock import patch


class TestLoginRequired(unittest.TestCase):
    """Tests for @login_required decorator."""

    def _make_info(self, userID=None) -> MagicMock:
        """Create a mock info object with the given userID."""
        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.userID = userID
        return mock_info

    def test_allows_authenticated_user(self) -> None:
        from chowkidar.decorators import login_required

        resolver = MagicMock(return_value="resolved")
        wrapped = login_required(resolver)
        mock_info = self._make_info(userID=42)

        result = wrapped(None, mock_info)

        self.assertEqual(result, "resolved")
        resolver.assert_called_once()

    def test_blocks_unauthenticated_user(self) -> None:
        from chowkidar.decorators import login_required

        resolver = MagicMock(return_value="resolved")
        wrapped = login_required(resolver)
        mock_info = self._make_info(userID=None)

        result = wrapped(None, mock_info)

        self.assertIsNone(
            result,
            "Should return None for unauthenticated users",
        )
        resolver.assert_not_called()

    def test_blocks_zero_user_id(self) -> None:
        from chowkidar.decorators import login_required

        resolver = MagicMock(return_value="resolved")
        wrapped = login_required(resolver)
        mock_info = self._make_info(userID=0)

        result = wrapped(None, mock_info)

        self.assertIsNone(
            result,
            "Should return None when userID is 0 (falsy)",
        )

    def test_missing_userID_attribute(self) -> None:
        from chowkidar.decorators import login_required

        resolver = MagicMock(return_value="resolved")
        wrapped = login_required(resolver)
        mock_info = MagicMock()
        mock_info.context = MagicMock(spec=[])

        result = wrapped(None, mock_info)

        self.assertIsNone(
            result,
            "Should return None when userID attribute is missing entirely",
        )

    def test_preserves_function_name(self) -> None:
        from chowkidar.decorators import login_required

        def my_resolver(parent, info):
            pass

        wrapped = login_required(my_resolver)

        self.assertEqual(
            wrapped.__name__,
            "my_resolver",
            "Should preserve the original function name via @wraps",
        )

    def test_passes_args_and_kwargs(self) -> None:
        from chowkidar.decorators import login_required

        resolver = MagicMock(return_value="ok")
        wrapped = login_required(resolver)
        mock_info = self._make_info(userID=1)

        wrapped(None, mock_info, "extra_arg", key="value")

        resolver.assert_called_once_with(
            None,
            mock_info,
            "extra_arg",
            key="value",
        )


class TestResolveUser(unittest.TestCase):
    """Tests for @resolve_user decorator."""

    @patch("chowkidar.decorators.apps")
    @patch("chowkidar.decorators.settings")
    def test_sets_context_user_on_success(
        self,
        mock_settings: MagicMock,
        mock_apps: MagicMock,
    ) -> None:
        from chowkidar.decorators import resolve_user

        mock_settings.AUTH_USER_MODEL = "auth.User"
        mock_user = MagicMock()
        mock_model = MagicMock()
        mock_model.objects.get.return_value = mock_user
        mock_apps.get_model.return_value = mock_model

        resolver = MagicMock(return_value="resolved")
        wrapped = resolve_user(resolver)

        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.userID = 42

        result = wrapped(None, mock_info)

        self.assertEqual(result, "resolved")
        self.assertEqual(
            mock_info.context.user,
            mock_user,
            "Should set info.context.user to the User instance",
        )

    @patch("chowkidar.decorators.apps")
    @patch("chowkidar.decorators.settings")
    def test_returns_none_when_user_not_found(
        self,
        mock_settings: MagicMock,
        mock_apps: MagicMock,
    ) -> None:
        from chowkidar.decorators import resolve_user

        mock_settings.AUTH_USER_MODEL = "auth.User"

        class UserDoesNotExist(Exception):
            pass

        mock_model = MagicMock()
        mock_model.DoesNotExist = UserDoesNotExist
        mock_model.objects.get.side_effect = UserDoesNotExist
        mock_apps.get_model.return_value = mock_model

        resolver = MagicMock(return_value="resolved")
        wrapped = resolve_user(resolver)

        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.userID = 999

        result = wrapped(None, mock_info)

        self.assertIsNone(
            result,
            "Should return None when User.DoesNotExist is raised",
        )
        resolver.assert_not_called()

    def test_returns_none_when_not_authenticated(self) -> None:
        from chowkidar.decorators import resolve_user

        resolver = MagicMock(return_value="resolved")
        wrapped = resolve_user(resolver)

        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.userID = None

        result = wrapped(None, mock_info)

        self.assertIsNone(
            result,
            "Should return None when user is not authenticated",
        )
        resolver.assert_not_called()


class TestLoginRequiredSecurityEdgeCases(unittest.TestCase):
    """Security edge cases for @login_required."""

    def _make_info(self, userID=None) -> MagicMock:
        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.userID = userID
        return mock_info

    def test_negative_user_id_still_passes(self) -> None:
        """Negative userID is truthy — login_required passes it through.
        The DB layer is responsible for rejecting invalid IDs.
        """
        from chowkidar.decorators import login_required

        resolver = MagicMock(return_value="resolved")
        wrapped = login_required(resolver)
        mock_info = self._make_info(userID=-1)

        result = wrapped(None, mock_info)

        self.assertEqual(
            result,
            "resolved",
            "Negative userID is truthy, so resolver should be called",
        )

    def test_string_user_id_passes(self) -> None:
        """String userID is truthy — login_required does not type-check."""
        from chowkidar.decorators import login_required

        resolver = MagicMock(return_value="resolved")
        wrapped = login_required(resolver)
        mock_info = self._make_info(userID="not-an-int")

        result = wrapped(None, mock_info)

        self.assertEqual(
            result,
            "resolved",
            "String userID is truthy, resolver should be called",
        )

    def test_false_user_id_blocks(self) -> None:
        """Boolean False is falsy — should block access."""
        from chowkidar.decorators import login_required

        resolver = MagicMock(return_value="resolved")
        wrapped = login_required(resolver)
        mock_info = self._make_info(userID=False)

        result = wrapped(None, mock_info)

        self.assertIsNone(
            result,
            "False userID should block access",
        )
        resolver.assert_not_called()

    def test_empty_string_user_id_blocks(self) -> None:
        """Empty string is falsy — should block access."""
        from chowkidar.decorators import login_required

        resolver = MagicMock(return_value="resolved")
        wrapped = login_required(resolver)
        mock_info = self._make_info(userID="")

        result = wrapped(None, mock_info)

        self.assertIsNone(
            result,
            "Empty string userID should block access",
        )
        resolver.assert_not_called()


__all__ = [
    "TestLoginRequired",
    "TestResolveUser",
    "TestLoginRequiredSecurityEdgeCases",
]
