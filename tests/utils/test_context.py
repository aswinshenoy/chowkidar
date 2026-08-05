"""
Tests for chowkidar/utils/context.py

Covers:
  - get_context() with Info, GraphQLResolveInfo, StrawberryDjangoContext, HttpRequest
  - edge cases: None context, missing context attribute
"""

import unittest
from unittest.mock import MagicMock


class TestGetContext(unittest.TestCase):
    """Tests for get_context() context extraction logic."""

    def test_get_context_with_strawberry_django_context(self) -> None:
        from strawberry.django.context import StrawberryDjangoContext

        from chowkidar.utils.context import get_context

        mock_request = MagicMock()
        mock_response = MagicMock()
        ctx = StrawberryDjangoContext(
            request=mock_request,
            response=mock_response,
        )
        mock_info = MagicMock()
        mock_info.context = ctx

        result = get_context(mock_info)

        self.assertEqual(
            result,
            mock_request,
            "Should return the request attribute from StrawberryDjangoContext",
        )

    def test_get_context_with_plain_context(self) -> None:
        from chowkidar.utils.context import get_context

        mock_context = MagicMock()
        mock_info = MagicMock()
        mock_info.context = mock_context

        result = get_context(mock_info)

        self.assertEqual(
            result,
            mock_context,
            "Should return the context directly when not StrawberryDjangoContext",
        )

    def test_get_context_with_graphql_resolve_info(self) -> None:
        from chowkidar.utils.context import get_context

        mock_context = {"request": MagicMock()}
        mock_info = MagicMock()
        mock_info.context = mock_context

        result = get_context(mock_info)

        self.assertEqual(
            result,
            mock_context,
            "Should return context from GraphQLResolveInfo-like object",
        )

    def test_get_context_without_context_attribute(self) -> None:
        from django.http import HttpRequest

        from chowkidar.utils.context import get_context

        request = HttpRequest()

        result = get_context(request)

        self.assertEqual(
            result,
            request,
            "Should return the object itself when it has no context attribute",
        )

    def test_get_context_with_none_context(self) -> None:
        from chowkidar.utils.context import get_context

        mock_info = MagicMock()
        mock_info.context = None

        result = get_context(mock_info)

        self.assertIsNone(
            result,
            "Should return None when context is None",
        )


__all__ = ["TestGetContext"]
