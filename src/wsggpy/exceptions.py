"""Exception classes for wsggpy.

Provides structured error handling for various failure modes
that can occur when interacting with the chat API.
"""


class WSGGError(Exception):
    """Base exception for all wsggpy errors."""

    def __init__(self, message: str, details: str | None = None) -> None:
        """Initialize WSGGError with message and optional details.

        Args:
            message: Error message.
            details: Optional additional error details.
        """
        self.message = message
        self.details = details
        super().__init__(self.message)


class ConnectionError(WSGGError):
    """Raised when websocket connection fails or is lost."""

    pass


class AuthenticationError(WSGGError):
    """Raised when authentication fails."""

    pass


class MessageError(WSGGError):
    """Raised when message sending fails."""

    pass


class ProtocolError(WSGGError):
    """Raised when protocol parsing fails."""

    pass


class RateLimitError(WSGGError):
    """Raised when rate limit is exceeded."""

    pass


class PermissionError(WSGGError):
    """Raised when user lacks permission for an action."""

    pass
