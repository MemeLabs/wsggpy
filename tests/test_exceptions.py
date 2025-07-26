"""
Tests for wsggpy exception handling.

Focuses on exception hierarchy, error propagation, and robustness
of error handling in various failure scenarios.
"""

import pytest
from wsggpy.exceptions import (
    AuthenticationError,
    ConnectionError,
    MessageError,
    PermissionError,
    ProtocolError,
    RateLimitError,
    WSGGError,
)


class TestExceptionHierarchy:
    """Test the exception class hierarchy."""

    def test_wsgg_error_base_class(self):
        """Test WSGGError base exception."""
        error = WSGGError("Base error")

        assert isinstance(error, Exception)
        assert str(error) == "Base error"
        assert error.message == "Base error"
        assert error.details is None

    def test_wsgg_error_with_details(self):
        """Test WSGGError with additional details."""
        error = WSGGError("Error message", "Additional details")

        assert error.message == "Error message"
        assert error.details == "Additional details"
        assert str(error) == "Error message"

    def test_connection_error_inheritance(self):
        """Test ConnectionError inherits from WSGGError."""
        error = ConnectionError("Connection failed")

        assert isinstance(error, WSGGError)
        assert isinstance(error, Exception)
        assert str(error) == "Connection failed"

    def test_authentication_error_inheritance(self):
        """Test AuthenticationError inherits from WSGGError."""
        error = AuthenticationError("Auth failed")

        assert isinstance(error, WSGGError)
        assert isinstance(error, Exception)
        assert str(error) == "Auth failed"

    def test_message_error_inheritance(self):
        """Test MessageError inherits from WSGGError."""
        error = MessageError("Message failed")

        assert isinstance(error, WSGGError)
        assert isinstance(error, Exception)
        assert str(error) == "Message failed"

    def test_protocol_error_inheritance(self):
        """Test ProtocolError inherits from WSGGError."""
        error = ProtocolError("Protocol failed")

        assert isinstance(error, WSGGError)
        assert isinstance(error, Exception)
        assert str(error) == "Protocol failed"

    def test_rate_limit_error_inheritance(self):
        """Test RateLimitError inherits from WSGGError."""
        error = RateLimitError("Rate limited")

        assert isinstance(error, WSGGError)
        assert isinstance(error, Exception)
        assert str(error) == "Rate limited"

    def test_permission_error_inheritance(self):
        """Test PermissionError inherits from WSGGError."""
        error = PermissionError("Permission denied")

        assert isinstance(error, WSGGError)
        assert isinstance(error, Exception)
        assert str(error) == "Permission denied"


class TestExceptionCreation:
    """Test exception creation with various parameters."""

    def test_all_exceptions_with_message_only(self):
        """Test creating all exceptions with just a message."""
        exceptions = [
            WSGGError("Base error"),
            ConnectionError("Connection failed"),
            AuthenticationError("Auth failed"),
            MessageError("Message failed"),
            ProtocolError("Protocol failed"),
            RateLimitError("Rate limited"),
            PermissionError("Permission denied"),
        ]

        for error in exceptions:
            assert isinstance(error, WSGGError)
            assert len(str(error)) > 0

    def test_all_exceptions_with_message_and_details(self):
        """Test creating all exceptions with message and details."""
        error_types = [
            WSGGError,
            ConnectionError,
            AuthenticationError,
            MessageError,
            ProtocolError,
            RateLimitError,
            PermissionError,
        ]

        for error_type in error_types:
            error = error_type("Main message", "Additional details")

            assert isinstance(error, WSGGError)
            assert error.message == "Main message"
            assert error.details == "Additional details"

    def test_exception_with_empty_message(self):
        """Test creating exceptions with empty messages."""
        error = WSGGError("")

        assert error.message == ""
        assert str(error) == ""

    def test_exception_with_none_details(self):
        """Test creating exceptions with None details."""
        error = WSGGError("Message", None)

        assert error.message == "Message"
        assert error.details is None

    def test_exception_with_empty_details(self):
        """Test creating exceptions with empty string details."""
        error = WSGGError("Message", "")

        assert error.message == "Message"
        assert error.details == ""


class TestExceptionCatching:
    """Test exception catching and handling."""

    def test_catch_base_exception(self):
        """Test catching base WSGGError catches all derived exceptions."""
        exceptions_to_test = [
            ConnectionError("Connection failed"),
            AuthenticationError("Auth failed"),
            MessageError("Message failed"),
            ProtocolError("Protocol failed"),
            RateLimitError("Rate limited"),
            PermissionError("Permission denied"),
        ]

        for exception in exceptions_to_test:
            with pytest.raises(WSGGError):
                raise exception

    def test_catch_specific_exceptions(self):
        """Test catching specific exception types."""
        with pytest.raises(ConnectionError):
            raise ConnectionError("Connection failed")

        with pytest.raises(AuthenticationError):
            raise AuthenticationError("Auth failed")

        with pytest.raises(MessageError):
            raise MessageError("Message failed")

        with pytest.raises(ProtocolError):
            raise ProtocolError("Protocol failed")

        with pytest.raises(RateLimitError):
            raise RateLimitError("Rate limited")

        with pytest.raises(PermissionError):
            raise PermissionError("Permission denied")

    def test_exception_hierarchy_catching(self):
        """Test that exception catching respects the hierarchy."""
        # Should catch ConnectionError as WSGGError
        try:
            raise ConnectionError("Connection failed")
        except WSGGError as e:
            assert isinstance(e, ConnectionError)
            assert isinstance(e, WSGGError)

        # Should catch specific type before base type
        try:
            raise MessageError("Message failed")
        except MessageError as e:
            assert isinstance(e, MessageError)
        except WSGGError:
            pytest.fail("Should have caught MessageError specifically")


class TestExceptionChaining:
    """Test exception chaining and cause handling."""

    def test_exception_chaining_from_standard_exception(self):
        """Test chaining wsggpy exceptions from standard exceptions."""
        try:
            raise ValueError("Original error")
        except ValueError as e:
            chained_error = ConnectionError("Connection failed due to value error")
            chained_error.__cause__ = e

            assert chained_error.__cause__ is e
            assert isinstance(chained_error.__cause__, ValueError)

    def test_exception_chaining_from_wsgg_exception(self):
        """Test chaining wsggpy exceptions from other wsggpy exceptions."""
        try:
            raise ProtocolError("Protocol parsing failed")
        except ProtocolError as e:
            chained_error = ConnectionError("Connection failed due to protocol error")
            chained_error.__cause__ = e

            assert chained_error.__cause__ is e
            assert isinstance(chained_error.__cause__, ProtocolError)
            assert isinstance(chained_error.__cause__, WSGGError)

    def test_multiple_exception_chaining(self):
        """Test multiple levels of exception chaining."""
        try:
            raise ValueError("Original system error")
        except ValueError as e1:
            try:
                protocol_error = ProtocolError("Protocol error due to value error")
                protocol_error.__cause__ = e1
                raise protocol_error
            except ProtocolError as e2:
                connection_error = ConnectionError(
                    "Connection error due to protocol error"
                )
                connection_error.__cause__ = e2

                assert connection_error.__cause__ is e2
                assert connection_error.__cause__.__cause__ is e1


class TestExceptionInRealWorldScenarios:
    """Test exceptions in realistic usage scenarios."""

    def test_connection_error_scenarios(self):
        """Test various ConnectionError scenarios."""
        scenarios = [
            "WebSocket connection failed",
            "Connection timeout",
            "Connection refused by server",
            "Network unreachable",
            "SSL handshake failed",
        ]

        for scenario in scenarios:
            error = ConnectionError(scenario)
            assert isinstance(error, ConnectionError)
            assert scenario in str(error)

    def test_authentication_error_scenarios(self):
        """Test various AuthenticationError scenarios."""
        scenarios = [
            "Invalid login key",
            "Authentication token expired",
            "Unauthorized access",
            "Invalid credentials",
            "Authentication server unavailable",
        ]

        for scenario in scenarios:
            error = AuthenticationError(scenario)
            assert isinstance(error, AuthenticationError)
            assert scenario in str(error)

    def test_message_error_scenarios(self):
        """Test various MessageError scenarios."""
        scenarios = [
            "Failed to send message",
            "Message too long",
            "Invalid message format",
            "WebSocket send failed",
            "Connection closed during send",
        ]

        for scenario in scenarios:
            error = MessageError(scenario)
            assert isinstance(error, MessageError)
            assert scenario in str(error)

    def test_protocol_error_scenarios(self):
        """Test various ProtocolError scenarios."""
        scenarios = [
            "Invalid JSON received",
            "Unknown message type",
            "Missing required field",
            "Invalid timestamp format",
            "Malformed protocol message",
        ]

        for scenario in scenarios:
            error = ProtocolError(scenario)
            assert isinstance(error, ProtocolError)
            assert scenario in str(error)

    def test_rate_limit_error_scenarios(self):
        """Test various RateLimitError scenarios."""
        scenarios = [
            "Message rate limit exceeded",
            "Connection rate limit exceeded",
            "API rate limit exceeded",
            "Too many requests",
            "Rate limit: 10 messages per minute",
        ]

        for scenario in scenarios:
            error = RateLimitError(scenario)
            assert isinstance(error, RateLimitError)
            assert scenario in str(error)

    def test_permission_error_scenarios(self):
        """Test various PermissionError scenarios."""
        scenarios = [
            "Insufficient privileges",
            "Moderator permission required",
            "Admin permission required",
            "Cannot ban user: insufficient privileges",
            "Cannot mute user: not a moderator",
        ]

        for scenario in scenarios:
            error = PermissionError(scenario)
            assert isinstance(error, PermissionError)
            assert scenario in str(error)


class TestExceptionWithDetails:
    """Test exceptions with detailed error information."""

    def test_connection_error_with_details(self):
        """Test ConnectionError with detailed information."""
        error = ConnectionError(
            "Failed to connect to chat server",
            "Server returned HTTP 503: Service Unavailable",
        )

        assert error.message == "Failed to connect to chat server"
        assert error.details == "Server returned HTTP 503: Service Unavailable"

    def test_authentication_error_with_details(self):
        """Test AuthenticationError with detailed information."""
        error = AuthenticationError(
            "Login failed", "Invalid API key format: expected 32-character hex string"
        )

        assert error.message == "Login failed"
        assert (
            error.details == "Invalid API key format: expected 32-character hex string"
        )

    def test_protocol_error_with_details(self):
        """Test ProtocolError with detailed information."""
        error = ProtocolError(
            "Failed to parse incoming message",
            "JSON decode error at line 1, column 15: Expecting ',' delimiter",
        )

        assert error.message == "Failed to parse incoming message"
        assert "JSON decode error" in error.details

    def test_message_error_with_details(self):
        """Test MessageError with detailed information."""
        error = MessageError(
            "Failed to send private message",
            "Recipient 'nonexistent_user' not found in chat",
        )

        assert error.message == "Failed to send private message"
        assert "nonexistent_user" in error.details

    def test_rate_limit_error_with_details(self):
        """Test RateLimitError with detailed information."""
        error = RateLimitError(
            "Rate limit exceeded",
            "Maximum 5 messages per minute allowed. Try again in 45 seconds.",
        )

        assert error.message == "Rate limit exceeded"
        assert "45 seconds" in error.details

    def test_permission_error_with_details(self):
        """Test PermissionError with detailed information."""
        error = PermissionError(
            "Cannot execute ban command",
            "User 'regular_user' requires MODERATOR or ADMIN privileges",
        )

        assert error.message == "Cannot execute ban command"
        assert "MODERATOR or ADMIN" in error.details


class TestExceptionStringRepresentation:
    """Test string representations of exceptions."""

    def test_exception_str_method(self):
        """Test that str() returns the message."""
        error = WSGGError("Test message")
        assert str(error) == "Test message"

    def test_exception_repr_method(self):
        """Test that repr() includes class name and message."""
        error = ConnectionError("Connection failed")
        repr_str = repr(error)

        assert "ConnectionError" in repr_str
        assert "Connection failed" in repr_str

    def test_exception_with_unicode_characters(self):
        """Test exceptions with unicode characters."""
        error = MessageError("Failed to send message: 'Hello 🌍 café naïve résumé'")

        assert "🌍" in str(error)
        assert "café" in str(error)
        assert "naïve" in str(error)
        assert "résumé" in str(error)

    def test_exception_with_newlines(self):
        """Test exceptions with newline characters."""
        error = ProtocolError("Multi-line error:\nLine 1\nLine 2\nLine 3")

        assert "\n" in str(error)
        assert "Line 1" in str(error)
        assert "Line 3" in str(error)

    def test_exception_with_very_long_message(self):
        """Test exceptions with very long messages."""
        long_message = "Error: " + "A" * 10000
        error = MessageError(long_message)

        assert len(str(error)) > 10000
        assert str(error).startswith("Error: AAA")
        assert str(error).endswith("AAA")


class TestExceptionEquality:
    """Test exception equality and comparison."""

    def test_same_type_same_message_equality(self):
        """Test that exceptions with same type and message are equal."""
        error1 = ConnectionError("Connection failed")
        error2 = ConnectionError("Connection failed")

        # Exception instances are not equal by default in Python
        assert error1 is not error2
        assert type(error1) is type(error2)
        assert str(error1) == str(error2)

    def test_different_type_same_message_inequality(self):
        """Test that exceptions with different types are not equal."""
        error1 = ConnectionError("Failed")
        error2 = MessageError("Failed")

        assert type(error1) is not type(error2)
        assert str(error1) == str(error2)  # Same message
        assert error1 is not error2

    def test_same_type_different_message_inequality(self):
        """Test that exceptions with same type but different messages."""
        error1 = ConnectionError("Connection failed")
        error2 = ConnectionError("Different error")

        assert type(error1) is type(error2)
        assert str(error1) != str(error2)
        assert error1 is not error2
