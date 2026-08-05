"""
Tests for chowkidar/view.py

Covers:
  - auth_enabled_view wraps and delegates to the view function
  - PERFORM_LOGIN triggers refresh token cookie
  - PERFORM_LOGOUT triggers cookie deletion
  - REFRESHED_ACCESS_TOKEN triggers access token cookie
  - No auth attributes leaves response unchanged
"""

import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from django.http import HttpRequest
from django.http import HttpResponse


class TestAuthEnabledView(unittest.TestCase):
    """Tests for auth_enabled_view() decorator."""

    def _make_request(self, **attrs) -> HttpRequest:
        """Create an HttpRequest with custom attributes."""
        request = HttpRequest()
        for k, v in attrs.items():
            setattr(request, k, v)
        return request

    def test_delegates_to_wrapped_view(self) -> None:
        from chowkidar.view import auth_enabled_view

        response = HttpResponse("ok")
        view_func = MagicMock(return_value=response)
        wrapped = auth_enabled_view(view_func)

        request = self._make_request()
        result = wrapped(request)

        view_func.assert_called_once_with(request)
        self.assertIsInstance(result, HttpResponse)

    def test_no_auth_attributes_passes_through(self) -> None:
        from chowkidar.view import auth_enabled_view

        response = HttpResponse("ok")
        view_func = MagicMock(return_value=response)
        wrapped = auth_enabled_view(view_func)

        request = self._make_request()
        result = wrapped(request)

        self.assertEqual(
            result,
            response,
            "Response should pass through unchanged when no auth attributes set",
        )

    @patch("chowkidar.utils.cookie.set_cookie")
    @patch("chowkidar.utils.jwt.generate_token_from_claims")
    def test_perform_login_sets_refresh_cookie(
        self,
        mock_generate: MagicMock,
        mock_set_cookie: MagicMock,
    ) -> None:
        from chowkidar.view import auth_enabled_view

        mock_rt = MagicMock()
        mock_rt.get_token.return_value = "refresh-token-value"
        mock_rt.get_refresh_token_expiry_delta.return_value = MagicMock()
        mock_generate.return_value = {
            "token": "encoded-jwt",
            "payload": {"exp": 9999999999},
        }

        response = HttpResponse("ok")
        mock_set_cookie.return_value = response
        view_func = MagicMock(return_value=response)
        wrapped = auth_enabled_view(view_func)

        request = self._make_request(
            PERFORM_LOGIN=True,
            NEW_REFRESH_TOKEN=mock_rt,
        )
        wrapped(request)

        mock_generate.assert_called_once()
        mock_set_cookie.assert_called_once()

    @patch("chowkidar.utils.cookie.delete_cookie")
    def test_perform_logout_deletes_cookies(
        self,
        mock_delete_cookie: MagicMock,
    ) -> None:
        from chowkidar.view import auth_enabled_view

        response = HttpResponse("ok")
        mock_delete_cookie.return_value = response
        view_func = MagicMock(return_value=response)
        wrapped = auth_enabled_view(view_func)

        request = self._make_request(PERFORM_LOGOUT=True)
        wrapped(request)

        self.assertEqual(
            mock_delete_cookie.call_count,
            2,
            "Should delete both access and refresh token cookies",
        )

    @patch("chowkidar.utils.cookie.set_cookie")
    def test_refreshed_access_token_sets_cookie(
        self,
        mock_set_cookie: MagicMock,
    ) -> None:
        from chowkidar.view import auth_enabled_view

        response = HttpResponse("ok")
        mock_set_cookie.return_value = response
        view_func = MagicMock(return_value=response)
        wrapped = auth_enabled_view(view_func)

        request = self._make_request(
            REFRESHED_ACCESS_TOKEN={
                "token": "new-access-token",
                "payload": {"exp": 9999999999},
            },
        )
        wrapped(request)

        mock_set_cookie.assert_called_once()

    def test_preserves_function_name(self) -> None:
        from chowkidar.view import auth_enabled_view

        def my_view(request):
            return HttpResponse("ok")

        wrapped = auth_enabled_view(my_view)

        self.assertEqual(
            wrapped.__name__,
            "my_view",
            "Should preserve the original function name via @wraps",
        )

    def test_login_takes_precedence_over_refreshed_token(self) -> None:
        from chowkidar.view import auth_enabled_view

        response = HttpResponse("ok")
        view_func = MagicMock(return_value=response)
        wrapped = auth_enabled_view(view_func)

        mock_rt = MagicMock()
        mock_rt.get_token.return_value = "tok"
        mock_rt.get_refresh_token_expiry_delta.return_value = MagicMock()

        request = self._make_request(
            PERFORM_LOGIN=True,
            NEW_REFRESH_TOKEN=mock_rt,
            REFRESHED_ACCESS_TOKEN={
                "token": "should-not-be-used",
                "payload": {"exp": 0},
            },
        )

        with patch("chowkidar.utils.cookie.set_cookie", return_value=response):
            with patch("chowkidar.utils.jwt.generate_token_from_claims") as mock_gen:
                mock_gen.return_value = {
                    "token": "jwt",
                    "payload": {"exp": 0},
                }
                wrapped(request)

                mock_gen.assert_called_once()


class TestAuthEnabledViewSecurityEdgeCases(unittest.TestCase):
    """Security edge cases for auth_enabled_view."""

    def _make_request(self, **attrs) -> HttpRequest:
        request = HttpRequest()
        for k, v in attrs.items():
            setattr(request, k, v)
        return request

    @patch("chowkidar.utils.cookie.delete_cookie")
    def test_logout_takes_precedence_over_refresh(
        self,
        mock_delete_cookie: MagicMock,
    ) -> None:
        """PERFORM_LOGOUT must take precedence over REFRESHED_ACCESS_TOKEN."""
        from chowkidar.view import auth_enabled_view

        response = HttpResponse("ok")
        mock_delete_cookie.return_value = response
        view_func = MagicMock(return_value=response)
        wrapped = auth_enabled_view(view_func)

        request = self._make_request(
            PERFORM_LOGOUT=True,
            REFRESHED_ACCESS_TOKEN={
                "token": "should-not-be-set",
                "payload": {"exp": 0},
            },
        )
        wrapped(request)

        self.assertEqual(
            mock_delete_cookie.call_count,
            2,
            "Logout must delete cookies even if REFRESHED_ACCESS_TOKEN is present",
        )

    def test_no_attributes_does_not_set_cookies(self) -> None:
        """A clean request must not result in any cookie mutations."""
        from chowkidar.view import auth_enabled_view

        response = HttpResponse("ok")
        view_func = MagicMock(return_value=response)
        wrapped = auth_enabled_view(view_func)

        request = self._make_request()
        result = wrapped(request)

        self.assertEqual(
            len(result.cookies),
            0,
            "No cookies should be set on a clean request",
        )

    def test_view_args_kwargs_passed_through(self) -> None:
        """Extra args/kwargs must reach the wrapped view function."""
        from chowkidar.view import auth_enabled_view

        response = HttpResponse("ok")
        view_func = MagicMock(return_value=response)
        wrapped = auth_enabled_view(view_func)

        request = self._make_request()
        wrapped(request, "extra_arg", key="value")

        view_func.assert_called_once_with(
            request,
            "extra_arg",
            key="value",
        )


__all__ = [
    "TestAuthEnabledView",
    "TestAuthEnabledViewSecurityEdgeCases",
]
