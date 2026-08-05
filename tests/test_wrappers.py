"""
Tests for chowkidar/wrappers.py

Covers:
  - @issue_tokens_on_login creates a refresh token when LOGIN_USER is set
  - @issue_tokens_on_login does nothing when LOGIN_USER is not set
  - @revoke_tokens_on_logout revokes token when LOGOUT_USER is True
  - @revoke_tokens_on_logout does nothing when LOGOUT_USER is not set
  - Edge cases: LOGOUT_USER True but no refreshToken
"""

import unittest
from unittest.mock import MagicMock
from unittest.mock import patch


class TestIssueTokensOnLogin(unittest.TestCase):
    """Tests for @issue_tokens_on_login decorator."""

    def _make_info(self, login_user=None) -> MagicMock:
        """Create a mock info object."""
        mock_info = MagicMock()
        mock_info.context = MagicMock()
        if login_user is not None:
            mock_info.context.LOGIN_USER = login_user
        else:
            mock_info.context = MagicMock(spec=[])
            mock_info.context.LOGIN_USER = None
        return mock_info

    @patch("chowkidar.wrappers.apps")
    def test_creates_refresh_token_on_login(
        self,
        mock_apps: MagicMock,
    ) -> None:
        from chowkidar.wrappers import issue_tokens_on_login

        mock_token = MagicMock()
        mock_model = MagicMock()
        mock_model.return_value = mock_token
        mock_apps.get_model.return_value = mock_model

        mock_user = MagicMock()
        mock_user.id = 42

        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.LOGIN_USER = mock_user

        resolver = MagicMock(return_value="login_result")
        wrapped = issue_tokens_on_login(resolver)

        result = wrapped(None, mock_info)

        self.assertEqual(result, "login_result")
        mock_token.process_request_before_save.assert_called_once()
        mock_token.save.assert_called_once()
        self.assertTrue(hasattr(mock_info.context, "PERFORM_LOGIN"))

    def test_no_login_user_does_nothing(self) -> None:
        from chowkidar.wrappers import issue_tokens_on_login

        mock_info = MagicMock()
        mock_info.context = MagicMock(spec=[])

        resolver = MagicMock(return_value="result")
        wrapped = issue_tokens_on_login(resolver)

        result = wrapped(None, mock_info)

        self.assertEqual(result, "result")

    def test_login_user_set_to_none_does_nothing(self) -> None:
        from chowkidar.wrappers import issue_tokens_on_login

        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.LOGIN_USER = None

        resolver = MagicMock(return_value="result")
        wrapped = issue_tokens_on_login(resolver)

        result = wrapped(None, mock_info)

        self.assertEqual(result, "result")

    def test_preserves_function_name(self) -> None:
        from chowkidar.wrappers import issue_tokens_on_login

        def my_login_resolver(cls, info):
            pass

        wrapped = issue_tokens_on_login(my_login_resolver)

        self.assertEqual(
            wrapped.__name__,
            "my_login_resolver",
        )


class TestRevokeTokensOnLogout(unittest.TestCase):
    """Tests for @revoke_tokens_on_logout decorator."""

    @patch("chowkidar.wrappers.apps")
    def test_revokes_token_on_logout(
        self,
        mock_apps: MagicMock,
    ) -> None:
        from chowkidar.wrappers import revoke_tokens_on_logout

        mock_qs = MagicMock()
        mock_model = MagicMock()
        mock_model.objects.filter.return_value = mock_qs
        mock_apps.get_model.return_value = mock_model

        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.LOGOUT_USER = True
        mock_info.context.userID = 42
        mock_info.context.refreshToken = "token-abc"

        resolver = MagicMock(return_value="logout_result")
        wrapped = revoke_tokens_on_logout(resolver)

        result = wrapped(None, mock_info)

        self.assertEqual(result, "logout_result")
        mock_model.objects.filter.assert_called_once_with(
            token="token-abc",
            user_id=42,
        )
        mock_qs.update.assert_called_once()

    def test_no_logout_user_does_nothing(self) -> None:
        from chowkidar.wrappers import revoke_tokens_on_logout

        mock_info = MagicMock()
        mock_info.context = MagicMock(spec=[])

        resolver = MagicMock(return_value="result")
        wrapped = revoke_tokens_on_logout(resolver)

        result = wrapped(None, mock_info)

        self.assertEqual(result, "result")

    def test_logout_user_false_does_nothing(self) -> None:
        from chowkidar.wrappers import revoke_tokens_on_logout

        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.LOGOUT_USER = False

        resolver = MagicMock(return_value="result")
        wrapped = revoke_tokens_on_logout(resolver)

        result = wrapped(None, mock_info)

        self.assertEqual(result, "result")

    def test_logout_without_refresh_token_skips_revoke(self) -> None:
        from chowkidar.wrappers import revoke_tokens_on_logout

        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.LOGOUT_USER = True
        mock_info.context.userID = 42
        mock_info.context.refreshToken = None

        resolver = MagicMock(return_value="result")
        wrapped = revoke_tokens_on_logout(resolver)

        result = wrapped(None, mock_info)

        self.assertEqual(result, "result")
        self.assertTrue(hasattr(mock_info.context, "PERFORM_LOGOUT"))

    def test_preserves_function_name(self) -> None:
        from chowkidar.wrappers import revoke_tokens_on_logout

        def my_logout_resolver(cls, info):
            pass

        wrapped = revoke_tokens_on_logout(my_logout_resolver)

        self.assertEqual(
            wrapped.__name__,
            "my_logout_resolver",
        )


class TestWrappersSecurityEdgeCases(unittest.TestCase):
    """Security edge cases for login/logout wrappers."""

    def test_logout_without_user_id_skips_revoke(self) -> None:
        """Logout with no userID must not attempt DB query."""
        from chowkidar.wrappers import revoke_tokens_on_logout

        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.LOGOUT_USER = True
        mock_info.context.userID = None
        mock_info.context.refreshToken = "some-token"

        resolver = MagicMock(return_value="result")
        wrapped = revoke_tokens_on_logout(resolver)

        result = wrapped(None, mock_info)

        self.assertEqual(result, "result")
        self.assertTrue(
            hasattr(mock_info.context, "PERFORM_LOGOUT"),
            "PERFORM_LOGOUT should still be set to clear cookies",
        )

    def test_logout_without_both_user_id_and_token_skips_revoke(self) -> None:
        """Logout with neither userID nor refreshToken must not crash."""
        from chowkidar.wrappers import revoke_tokens_on_logout

        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.LOGOUT_USER = True
        mock_info.context.userID = None
        mock_info.context.refreshToken = None

        resolver = MagicMock(return_value="result")
        wrapped = revoke_tokens_on_logout(resolver)

        result = wrapped(None, mock_info)

        self.assertEqual(result, "result")

    @patch("chowkidar.wrappers.apps")
    def test_login_token_saved_to_database(
        self,
        mock_apps: MagicMock,
    ) -> None:
        """Token must be persisted via save() during login."""
        from chowkidar.wrappers import issue_tokens_on_login

        mock_token = MagicMock()
        mock_model = MagicMock()
        mock_model.return_value = mock_token
        mock_apps.get_model.return_value = mock_model

        mock_user = MagicMock()
        mock_user.id = 1

        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.LOGIN_USER = mock_user

        resolver = MagicMock(return_value="ok")
        wrapped = issue_tokens_on_login(resolver)
        wrapped(None, mock_info)

        mock_token.save.assert_called_once()

    @patch("chowkidar.wrappers.apps")
    def test_login_calls_process_request_before_save(
        self,
        mock_apps: MagicMock,
    ) -> None:
        """process_request_before_save hook must be called before save."""
        from chowkidar.wrappers import issue_tokens_on_login

        call_order = []
        mock_token = MagicMock()
        mock_token.process_request_before_save.side_effect = lambda _: call_order.append("process")
        mock_token.save.side_effect = lambda: call_order.append("save")
        mock_model = MagicMock()
        mock_model.return_value = mock_token
        mock_apps.get_model.return_value = mock_model

        mock_user = MagicMock()
        mock_user.id = 1

        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.LOGIN_USER = mock_user

        resolver = MagicMock(return_value="ok")
        wrapped = issue_tokens_on_login(resolver)
        wrapped(None, mock_info)

        self.assertEqual(
            call_order,
            ["process", "save"],
            "process_request_before_save must be called before save",
        )


__all__ = [
    "TestIssueTokensOnLogin",
    "TestRevokeTokensOnLogout",
    "TestWrappersSecurityEdgeCases",
]
