"""
Tests for chowkidar/utils/jwt.py

Covers:
  - generate_token_from_claims produces valid tokens
  - datetime.now(timezone.utc) produces timezone-aware timestamps
  - leeway is correctly applied (typo fix verification)
  - verify_signature works (verify=True replacement)
  - decode_payload_from_token round-trips correctly
  - expired tokens raise AuthError
  - tampered tokens raise AuthError
"""

import time
from datetime import UTC
from datetime import datetime
from datetime import timedelta

import jwt as pyjwt
import pytest

from chowkidar.utils.jwt import decode_payload_from_token
from chowkidar.utils.jwt import generate_token_from_claims
from chowkidar.utils.exceptions import AuthError


class TestGenerateToken:
    """Tests for generate_token_from_claims"""

    def test_returns_token_and_payload(self):
        """Token generation should return a dict with 'token' and 'payload' keys."""
        result = generate_token_from_claims(
            claims={"userID": 42},
            expiration_delta=timedelta(minutes=5),
        )
        assert "token" in result
        assert "payload" in result
        assert isinstance(result["token"], str)
        assert isinstance(result["payload"], dict)

    def test_payload_contains_claims(self):
        """Custom claims should be present in the payload."""
        result = generate_token_from_claims(
            claims={"userID": 42, "role": "admin"},
            expiration_delta=timedelta(minutes=5),
        )
        assert result["payload"]["userID"] == 42
        assert result["payload"]["role"] == "admin"

    def test_payload_has_registered_claims(self):
        """Payload should contain iat, exp, and iss registered claims."""
        result = generate_token_from_claims(
            claims={"userID": 1},
            expiration_delta=timedelta(minutes=5),
        )
        payload = result["payload"]
        assert "iat" in payload
        assert "exp" in payload
        assert "iss" in payload

    def test_timestamps_are_timezone_aware(self):
        """iat and exp should be timezone-aware datetimes (not naive).
        This verifies the datetime.utcnow() -> datetime.now(timezone.utc) fix.
        """
        result = generate_token_from_claims(
            claims={"userID": 1},
            expiration_delta=timedelta(minutes=5),
        )
        iat = result["payload"]["iat"]
        exp = result["payload"]["exp"]

        # Both should be datetime objects with tzinfo set
        assert isinstance(iat, datetime)
        assert isinstance(exp, datetime)
        assert iat.tzinfo is not None, "iat should be timezone-aware, not naive"
        assert exp.tzinfo is not None, "exp should be timezone-aware, not naive"

    def test_exp_is_after_iat(self):
        """exp should be iat + expiration_delta."""
        delta = timedelta(minutes=10)
        result = generate_token_from_claims(
            claims={"userID": 1},
            expiration_delta=delta,
        )
        iat = result["payload"]["iat"]
        exp = result["payload"]["exp"]
        assert exp == iat + delta

    def test_issuer_matches_settings(self):
        """iss claim should match JWT_ISSUER from settings."""
        from chowkidar.settings import JWT_ISSUER

        result = generate_token_from_claims(
            claims={"userID": 1},
            expiration_delta=timedelta(minutes=5),
        )
        assert result["payload"]["iss"] == JWT_ISSUER


class TestDecodeToken:
    """Tests for decode_token and decode_payload_from_token"""

    def _make_token(self, claims=None, delta=timedelta(minutes=5)):
        """Helper to generate a valid token."""
        return generate_token_from_claims(
            claims=claims or {"userID": 1},
            expiration_delta=delta,
        )

    def test_round_trip(self):
        """Encoding then decoding should return the same claims."""
        result = self._make_token(claims={"userID": 42, "refreshToken": "abc123"})
        decoded = decode_payload_from_token(result["token"])
        assert decoded["userID"] == 42
        assert decoded["refreshToken"] == "abc123"

    def test_expired_token_raises_auth_error(self):
        """An expired token should raise AuthError with EXPIRED_TOKEN code."""
        # Create a token that expired 11 seconds ago (bypassing the 10s leeway)
        result = self._make_token(delta=timedelta(seconds=-11))
        with pytest.raises(AuthError) as exc_info:
            decode_payload_from_token(result["token"])
        assert exc_info.value.code == "EXPIRED_TOKEN"

    def test_tampered_token_raises_auth_error(self):
        """A token with a tampered signature should raise AuthError."""
        result = self._make_token()
        # Tamper with the token by changing a character in the signature
        token = result["token"]
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(AuthError) as exc_info:
            decode_payload_from_token(tampered)
        assert exc_info.value.code == "INVALID_TOKEN"

    def test_leeway_allows_recently_expired_token(self):
        """Leeway setting should allow tokens that just expired.
        This verifies the leeyway -> leeway typo fix.
        JWT_LEEWAY is set to 10 seconds in test settings.
        """
        # Create a token that expires in 1 second
        result = self._make_token(delta=timedelta(seconds=1))
        # Wait 2 seconds so it's technically expired
        time.sleep(2)
        # But leeway is 10 seconds, so it should still decode
        decoded = decode_payload_from_token(result["token"])
        assert decoded["userID"] == 1

    def test_wrong_key_raises_auth_error(self):
        """A token signed with a different key should fail verification.
        This verifies the verify_signature: True option works.
        """
        # Create a token with a different secret
        payload = {
            "userID": 1,
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "iss": "chowkidar-tests",
        }
        token = pyjwt.encode(
            payload,
            key="wrong-secret-key-long-enough-for-hs256",
            algorithm="HS256",
        )

        with pytest.raises(AuthError) as exc_info:
            decode_payload_from_token(token)
        assert exc_info.value.code == "INVALID_TOKEN"


class TestJWTSecurityEdgeCases:
    """Security and edge-case tests for JWT encode/decode."""

    def test_empty_token_raises_auth_error(self):
        """An empty string token should raise AuthError."""
        with pytest.raises(AuthError) as exc_info:
            decode_payload_from_token("")
        assert exc_info.value.code == "INVALID_TOKEN"

    def test_none_algorithm_attack(self):
        """A token with alg=none must be rejected."""
        payload = {
            "userID": 1,
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "iss": "chowkidar-tests",
        }
        token = pyjwt.encode(payload, key="", algorithm="none")
        with pytest.raises(AuthError) as exc_info:
            decode_payload_from_token(token)
        assert exc_info.value.code == "INVALID_TOKEN"

    def test_garbage_token_raises_auth_error(self):
        """Completely invalid data should raise AuthError."""
        with pytest.raises(AuthError) as exc_info:
            decode_payload_from_token("not.a.jwt.at.all")
        assert exc_info.value.code == "INVALID_TOKEN"

    def test_wrong_issuer_raises_auth_error(self):
        """A token with a different issuer should be rejected."""
        from chowkidar.settings import JWT_SECRET_KEY

        payload = {
            "userID": 1,
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "iss": "attacker-controlled-issuer",
        }
        token = pyjwt.encode(
            payload,
            key=JWT_SECRET_KEY,
            algorithm="HS256",
        )
        with pytest.raises(AuthError) as exc_info:
            decode_payload_from_token(token)
        assert exc_info.value.code == "INVALID_TOKEN"

    def test_token_with_zero_expiration_delta(self):
        """A token with zero timedelta should expire immediately (within leeway)."""
        result = generate_token_from_claims(
            claims={"userID": 1},
            expiration_delta=timedelta(seconds=0),
        )
        decoded = decode_payload_from_token(result["token"])
        assert decoded["userID"] == 1

    def test_custom_claims_not_overwritten_by_registered(self):
        """Custom claims should not be overwritten by iat/exp/iss."""
        result = generate_token_from_claims(
            claims={"userID": 1, "custom": "value"},
            expiration_delta=timedelta(minutes=5),
        )
        decoded = decode_payload_from_token(result["token"])
        assert decoded["custom"] == "value"
        assert decoded["userID"] == 1

    def test_very_long_expiration_still_valid(self):
        """A token with a very long expiration should still decode."""
        result = generate_token_from_claims(
            claims={"userID": 1},
            expiration_delta=timedelta(days=365 * 10),
        )
        decoded = decode_payload_from_token(result["token"])
        assert decoded["userID"] == 1


class TestTimedeltaSettings:
    """Tests for chowkidar/settings.py timedelta migration"""

    def test_access_token_delta_is_timedelta(self):
        """JWT_ACCESS_TOKEN_EXPIRATION_DELTA should be a timedelta."""
        from chowkidar.settings import JWT_ACCESS_TOKEN_EXPIRATION_DELTA

        assert isinstance(JWT_ACCESS_TOKEN_EXPIRATION_DELTA, timedelta)

    def test_refresh_token_delta_is_timedelta(self):
        """JWT_REFRESH_TOKEN_EXPIRATION_DELTA should be a timedelta."""
        from chowkidar.settings import JWT_REFRESH_TOKEN_EXPIRATION_DELTA

        assert isinstance(JWT_REFRESH_TOKEN_EXPIRATION_DELTA, timedelta)

    def test_access_token_default_is_60_seconds(self):
        """Default access token expiry should be 60 seconds."""
        from chowkidar.settings import JWT_ACCESS_TOKEN_EXPIRATION_DELTA

        assert JWT_ACCESS_TOKEN_EXPIRATION_DELTA == timedelta(seconds=60)

    def test_refresh_token_default_is_7_days(self):
        """Default refresh token expiry should be 7 days."""
        from chowkidar.settings import JWT_REFRESH_TOKEN_EXPIRATION_DELTA

        assert JWT_REFRESH_TOKEN_EXPIRATION_DELTA == timedelta(days=7)


__all__ = [
    "TestGenerateToken",
    "TestDecodeToken",
    "TestJWTSecurityEdgeCases",
    "TestTimedeltaSettings",
]
