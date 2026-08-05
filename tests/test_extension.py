"""
Tests for chowkidar/extension.py

Covers:
  - JWTAuthExtension.__init__ initializes all state variables
  - JWTAuthExtension can be instantiated without execution_context
  - _init_request_state() resets state correctly
  - is_cookie_in_request() checks cookie presence
  - _get_token_payload_from_cookie() decodes JWT from cookie
  - _get_refresh_token_object() looks up and validates refresh token
  - on_operation() generator processes access/refresh tokens
  - resolve() populates info.context with auth state
"""

from datetime import timedelta
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from strawberry.types import ExecutionContext


def _make_extension(with_execution_context=True):
    """Create a JWTAuthExtension with optional mocked execution context."""
    from chowkidar.extension import JWTAuthExtension

    if with_execution_context:
        mock_ec = MagicMock(spec=ExecutionContext)
        mock_ec.context = {"request": MagicMock()}
        ext = JWTAuthExtension(execution_context=mock_ec)
    else:
        ext = JWTAuthExtension()
    return ext


class TestExtensionInit(unittest.TestCase):
    """Tests for JWTAuthExtension.__init__ state initialization."""

    def test_init_sets_all_state_vars(self) -> None:
        ext = _make_extension()
        self.assertIsNone(ext._request)
        self.assertIsNone(ext.userID)
        self.assertIsNone(ext.refreshToken)
        self.assertIsNone(ext.refreshTokenObj)
        self.assertIsNone(ext._new_JWT_access_token)
        self.assertFalse(ext._remove_auth_cookies)

    def test_init_without_execution_context(self) -> None:
        ext = _make_extension(with_execution_context=False)
        self.assertIsNone(ext._request)
        self.assertIsNone(ext.userID)

    def test_init_with_execution_context_backward_compat(self) -> None:
        from chowkidar.extension import JWTAuthExtension

        mock_ec = MagicMock(spec=ExecutionContext)
        mock_ec.context = {"request": MagicMock()}
        JWTAuthExtension(execution_context=mock_ec)


class TestInitRequestState(unittest.TestCase):
    """Tests for _init_request_state() reset behavior."""

    def test_reset_clears_state(self) -> None:
        ext = _make_extension()
        ext.userID = 99
        ext.refreshToken = "old-token"
        ext._new_JWT_access_token = "jwt"
        ext._remove_auth_cookies = True

        ext._init_request_state()

        self.assertIsNone(ext._request)
        self.assertIsNone(ext.userID)
        self.assertIsNone(ext.refreshToken)
        self.assertIsNone(ext.refreshTokenObj)
        self.assertIsNone(ext._new_JWT_access_token)
        self.assertFalse(ext._remove_auth_cookies)


class TestIsCookieInRequest(unittest.TestCase):
    """Tests for is_cookie_in_request()."""

    def test_cookie_present_and_truthy(self) -> None:
        ext = _make_extension()
        ext._request = MagicMock()
        ext._request.COOKIES = {"token": "abc"}

        self.assertTrue(ext.is_cookie_in_request("token"))

    def test_cookie_missing(self) -> None:
        ext = _make_extension()
        ext._request = MagicMock()
        ext._request.COOKIES = {}

        self.assertFalse(ext.is_cookie_in_request("token"))

    def test_cookie_present_but_empty(self) -> None:
        ext = _make_extension()
        ext._request = MagicMock()
        ext._request.COOKIES = {"token": ""}

        self.assertFalse(ext.is_cookie_in_request("token"))


class TestGetTokenPayloadFromCookie(unittest.TestCase):
    """Tests for _get_token_payload_from_cookie()."""

    def test_returns_payload_for_valid_cookie(self) -> None:
        ext = _make_extension()
        ext._request = MagicMock()
        ext._request.COOKIES = {"JWT_ACCESS_TOKEN": "valid-jwt"}

        with patch(
            "chowkidar.extension.JWTAuthExtension.is_cookie_in_request",
            return_value=True,
        ):
            with patch(
                "chowkidar.utils.jwt.decode_payload_from_token",
                return_value={"userID": 1},
            ):
                result = ext._get_token_payload_from_cookie("JWT_ACCESS_TOKEN")

        self.assertEqual(
            result,
            {"userID": 1},
            "Should return decoded payload",
        )

    def test_returns_none_for_invalid_token(self) -> None:
        from chowkidar.utils.exceptions import AuthError

        ext = _make_extension()
        ext._request = MagicMock()
        ext._request.COOKIES = {"JWT_ACCESS_TOKEN": "bad-jwt"}

        with patch(
            "chowkidar.extension.JWTAuthExtension.is_cookie_in_request",
            return_value=True,
        ):
            with patch(
                "chowkidar.utils.jwt.decode_payload_from_token",
                side_effect=AuthError(message="invalid", code="INVALID_TOKEN"),
            ):
                result = ext._get_token_payload_from_cookie("JWT_ACCESS_TOKEN")

        self.assertIsNone(
            result,
            "Should return None when token is invalid",
        )

    def test_returns_none_when_cookie_missing(self) -> None:
        ext = _make_extension()
        ext._request = MagicMock()
        ext._request.COOKIES = {}

        result = ext._get_token_payload_from_cookie("JWT_ACCESS_TOKEN")

        self.assertIsNone(
            result,
            "Should return None when cookie is not present",
        )


class TestGetRefreshTokenObject(unittest.TestCase):
    """Tests for _get_refresh_token_object()."""

    def test_returns_none_when_refresh_token_is_none(self) -> None:
        ext = _make_extension()
        ext.refreshToken = None

        result = ext._get_refresh_token_object()

        self.assertIsNone(result)

    @patch("chowkidar.extension.apps.get_model")
    def test_returns_token_object_on_success(
        self,
        mock_get_model: MagicMock,
    ) -> None:
        ext = _make_extension()
        ext.refreshToken = "valid-token"

        mock_token_obj = MagicMock()
        mock_model = MagicMock()
        mock_model.objects.get.return_value = mock_token_obj
        mock_model.return_value.get_refresh_token_expiry_delta.return_value = timedelta(days=7)
        mock_get_model.return_value = mock_model

        result = ext._get_refresh_token_object()

        self.assertEqual(
            result,
            mock_token_obj,
            "Should return the refresh token object from DB",
        )

    @patch("chowkidar.extension.apps.get_model")
    def test_returns_none_and_flags_logout_on_does_not_exist(
        self,
        mock_get_model: MagicMock,
    ) -> None:
        ext = _make_extension()
        ext.refreshToken = "expired-token"

        class TokenDoesNotExist(Exception):
            pass

        mock_model = MagicMock()
        mock_model.DoesNotExist = TokenDoesNotExist
        mock_model.objects.get.side_effect = TokenDoesNotExist()
        mock_model.return_value.get_refresh_token_expiry_delta.return_value = timedelta(days=7)
        mock_get_model.return_value = mock_model

        result = ext._get_refresh_token_object()

        self.assertIsNone(
            result,
            "Should return None when token not found",
        )
        self.assertTrue(
            ext._remove_auth_cookies,
            "Should flag _remove_auth_cookies when token not found",
        )


class TestOnOperation(unittest.TestCase):
    """Tests for on_operation() generator hook."""

    def _make_ext_with_cookies(self, cookies):
        from chowkidar.extension import JWTAuthExtension

        mock_request = MagicMock()
        mock_request.COOKIES = cookies
        mock_ec = MagicMock(spec=ExecutionContext)
        mock_ec.context = {"request": mock_request}
        ext = JWTAuthExtension()
        ext.execution_context = mock_ec
        return ext

    def test_on_operation_is_generator_yields_once(self) -> None:
        ext = self._make_ext_with_cookies({})
        gen = ext.on_operation()
        next(gen)
        with self.assertRaises(StopIteration):
            next(gen)

    def test_on_operation_sets_request(self) -> None:
        ext = self._make_ext_with_cookies({})
        gen = ext.on_operation()
        next(gen)
        self.assertIsNotNone(ext._request)

    @patch("chowkidar.extension.JWTAuthExtension._get_token_payload_from_cookie")
    def test_on_operation_with_valid_access_token(
        self,
        mock_get_payload: MagicMock,
    ) -> None:
        ext = self._make_ext_with_cookies({})
        mock_get_payload.side_effect = [
            {"userID": 42},
            None,
        ]

        gen = ext.on_operation()
        next(gen)

        self.assertEqual(
            ext.userID,
            42,
            "Should set userID from access token payload",
        )

    @patch("chowkidar.extension.JWTAuthExtension._get_refresh_token_object")
    @patch("chowkidar.extension.JWTAuthExtension._get_token_payload_from_cookie")
    def test_on_operation_with_refresh_token_only(
        self,
        mock_get_payload: MagicMock,
        mock_get_rt_obj: MagicMock,
    ) -> None:
        ext = self._make_ext_with_cookies({})

        mock_get_payload.side_effect = [
            None,
            {"refreshToken": "rt-123"},
        ]

        mock_user = MagicMock()
        mock_user.id = 7
        mock_rt_obj = MagicMock()
        mock_rt_obj.token = "rt-123"
        mock_rt_obj.user = mock_user
        mock_rt_obj.issued.timestamp.return_value = 1000000
        mock_rt_obj.get_access_token_expiry_delta.return_value = timedelta(minutes=5)
        mock_get_rt_obj.return_value = mock_rt_obj

        with patch("chowkidar.utils.jwt.generate_token_from_claims", return_value="new-access-jwt"):
            gen = ext.on_operation()
            next(gen)

        self.assertEqual(ext.userID, 7)
        self.assertEqual(ext._new_JWT_access_token, "new-access-jwt")
        mock_user.save.assert_called_once()

    @patch("chowkidar.extension.JWTAuthExtension._get_token_payload_from_cookie")
    def test_on_operation_sets_refresh_token_from_payload(
        self,
        mock_get_payload: MagicMock,
    ) -> None:
        ext = self._make_ext_with_cookies({})
        mock_get_payload.side_effect = [
            {"userID": 1},
            {"refreshToken": "rt-abc"},
        ]

        gen = ext.on_operation()
        next(gen)

        self.assertEqual(
            ext.refreshToken,
            "rt-abc",
            "Should set refreshToken from refresh token payload",
        )

    def test_on_operation_flags_logout_on_invalid_cookies(self) -> None:
        ext = self._make_ext_with_cookies(
            {
                "JWT_ACCESS_TOKEN": "bad",
                "JWT_REFRESH_TOKEN": "bad",
            }
        )

        with patch(
            "chowkidar.extension.JWTAuthExtension._get_token_payload_from_cookie",
            return_value=None,
        ):
            gen = ext.on_operation()
            next(gen)

        self.assertTrue(
            ext._remove_auth_cookies,
            "Should flag logout when cookies exist but payloads are None",
        )


class TestResolve(unittest.TestCase):
    """Tests for resolve() context population."""

    def _make_ext_and_call_resolve(self, **ext_attrs):
        ext = _make_extension()
        for k, v in ext_attrs.items():
            setattr(ext, k, v)

        ctx = MagicMock()
        ctx.request = MagicMock()
        mock_info = MagicMock()
        mock_info.context = ctx
        mock_next = MagicMock(return_value="resolved")
        mock_root = MagicMock()

        result = ext.resolve(mock_next, mock_root, mock_info)
        return result, ctx

    def test_resolve_sets_context_attributes(self) -> None:
        result, ctx = self._make_ext_and_call_resolve(
            userID=42,
            refreshToken="tok",
            _request="req",
        )
        self.assertEqual(result, "resolved")
        self.assertEqual(ctx.userID, 42)
        self.assertEqual(ctx.refreshToken, "tok")
        self.assertEqual(ctx.request, "req")

    def test_resolve_sets_refreshed_access_token(self) -> None:
        ext = _make_extension()
        ext._new_JWT_access_token = "new-jwt"
        ext._request = MagicMock()

        original_request = MagicMock()
        ctx = MagicMock()
        ctx.request = original_request
        mock_info = MagicMock()
        mock_info.context = ctx
        mock_next = MagicMock(return_value="resolved")

        ext.resolve(mock_next, MagicMock(), mock_info)

        self.assertEqual(
            original_request.REFRESHED_ACCESS_TOKEN,
            "new-jwt",
            "Should set REFRESHED_ACCESS_TOKEN on the original request",
        )

    def test_resolve_sets_perform_logout(self) -> None:
        ext = _make_extension()
        ext._remove_auth_cookies = True
        ext._request = MagicMock()

        original_request = MagicMock()
        ctx = MagicMock()
        ctx.request = original_request
        mock_info = MagicMock()
        mock_info.context = ctx
        mock_next = MagicMock(return_value="resolved")

        ext.resolve(mock_next, MagicMock(), mock_info)

        self.assertTrue(
            original_request.PERFORM_LOGOUT,
            "Should set PERFORM_LOGOUT on the original request",
        )

    def test_resolve_handles_missing_attributes(self) -> None:
        ext = _make_extension()
        del ext._new_JWT_access_token
        del ext._remove_auth_cookies

        mock_info = MagicMock()
        mock_info.context = MagicMock()
        mock_info.context.request = MagicMock()
        mock_next = MagicMock(return_value="ok")

        result = ext.resolve(mock_next, MagicMock(), mock_info)
        self.assertEqual(result, "ok")


class TestExtensionSecurityEdgeCases(unittest.TestCase):
    """Security edge cases for JWTAuthExtension."""

    def test_on_operation_does_not_leak_state_across_requests(self) -> None:
        """State from one request must not leak into the next."""
        from chowkidar.extension import JWTAuthExtension

        mock_request1 = MagicMock()
        mock_request1.COOKIES = {}
        mock_request2 = MagicMock()
        mock_request2.COOKIES = {}

        mock_ec = MagicMock(spec=ExecutionContext)
        ext = JWTAuthExtension()

        mock_ec.context = {"request": mock_request1}
        ext.execution_context = mock_ec
        ext.userID = 42
        ext.refreshToken = "old-token"
        gen = ext.on_operation()
        next(gen)

        self.assertIsNone(
            ext.userID,
            "userID should be reset between requests",
        )
        self.assertIsNone(
            ext.refreshToken,
            "refreshToken should be reset between requests",
        )

    def test_expired_access_with_no_refresh_does_not_authenticate(self) -> None:
        """Expired access token with no refresh token must not set userID."""
        from chowkidar.extension import JWTAuthExtension

        mock_request = MagicMock()
        mock_request.COOKIES = {}
        mock_ec = MagicMock(spec=ExecutionContext)
        mock_ec.context = {"request": mock_request}
        ext = JWTAuthExtension()
        ext.execution_context = mock_ec

        with patch(
            "chowkidar.extension.JWTAuthExtension._get_token_payload_from_cookie",
            return_value=None,
        ):
            gen = ext.on_operation()
            next(gen)

        self.assertIsNone(
            ext.userID,
            "userID must remain None when both tokens are invalid",
        )

    @patch("chowkidar.extension.JWTAuthExtension._get_refresh_token_object")
    @patch("chowkidar.extension.JWTAuthExtension._get_token_payload_from_cookie")
    def test_revoked_refresh_token_flags_logout(
        self,
        mock_get_payload: MagicMock,
        mock_get_rt_obj: MagicMock,
    ) -> None:
        """A revoked refresh token (not found in DB) must trigger cookie removal."""
        from chowkidar.extension import JWTAuthExtension

        mock_request = MagicMock()
        mock_request.COOKIES = {}
        mock_ec = MagicMock(spec=ExecutionContext)
        mock_ec.context = {"request": mock_request}
        ext = JWTAuthExtension()
        ext.execution_context = mock_ec

        mock_get_payload.side_effect = [
            None,
            {"refreshToken": "revoked-token"},
        ]
        mock_get_rt_obj.return_value = None
        ext._remove_auth_cookies = True

        gen = ext.on_operation()
        next(gen)

        self.assertIsNone(
            ext.userID,
            "userID must not be set for revoked refresh token",
        )

    def test_resolve_does_not_set_access_token_and_logout_simultaneously(self) -> None:
        """REFRESHED_ACCESS_TOKEN and PERFORM_LOGOUT are mutually exclusive paths."""
        ext = _make_extension()
        ext._new_JWT_access_token = "new-jwt"
        ext._remove_auth_cookies = True
        ext._request = MagicMock()

        original_request = MagicMock(spec=[])
        ctx = MagicMock()
        ctx.request = original_request
        mock_info = MagicMock()
        mock_info.context = ctx
        mock_next = MagicMock(return_value="ok")

        ext.resolve(mock_next, MagicMock(), mock_info)

        self.assertTrue(
            hasattr(original_request, "REFRESHED_ACCESS_TOKEN"),
            "New access token branch should take precedence",
        )
        self.assertFalse(
            hasattr(original_request, "PERFORM_LOGOUT"),
            "Logout should not be set when access token is refreshed",
        )


__all__ = [
    "TestExtensionInit",
    "TestInitRequestState",
    "TestIsCookieInRequest",
    "TestGetTokenPayloadFromCookie",
    "TestGetRefreshTokenObject",
    "TestOnOperation",
    "TestResolve",
    "TestExtensionSecurityEdgeCases",
]
