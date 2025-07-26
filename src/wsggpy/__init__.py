"""wsggpy: Python WebSocket client library for strims.gg chat.

A modern, async-first Python library for connecting to and interacting with
strims.gg chat via WebSocket connections.

Features:
- Synchronous and asynchronous session support
- Type-safe event handling with Pydantic models
- Built-in authentication and message formatting
- Comprehensive error handling and reconnection support
- Easy environment switching (production/dev chat)

Example:
    Basic synchronous usage:

    >>> from wsggpy import Session, ChatEnvironment
    >>> session = Session(
    ...     login_key="your_jwt_token",
    ...     url=ChatEnvironment.PRODUCTION
    ... )
    >>> session.open()
    >>> session.send_message("Hello, chat!")

    Asynchronous usage:

    >>> import asyncio
    >>> from wsggpy import AsyncSession, ChatEnvironment
    >>>
    >>> async def main():
    ...     session = AsyncSession(
    ...         login_key="your_jwt_token",
    ...         url=ChatEnvironment.DEV
    ...     )
    ...     await session.open()
    ...     await session.send_message("Hello, dev chat!")
    ...     await session.close()
    >>>
    >>> asyncio.run(main())
"""

from .async_session import AsyncSession
from .exceptions import ConnectionError, MessageError, ProtocolError, WSGGError
from .models import (
    Ban,
    Broadcast,
    EventType,
    Message,
    Mute,
    Names,
    Ping,
    PrivateMessage,
    RoomAction,
    User,
    UserFeature,
)
from .session import Session


class ChatEnvironment:
    """WebSocket URLs for different strims.gg chat environments."""

    # Production chat environment
    PRODUCTION = "wss://chat.strims.gg/ws"

    # Development chat environment
    DEV = "wss://chat2.strims.gg/ws"

    # Alias for backwards compatibility
    CHAT = PRODUCTION
    CHAT2 = DEV


__version__ = "0.1.0"

__all__ = [
    # Sessions
    "Session",
    "AsyncSession",
    # Environment constants
    "ChatEnvironment",
    # Models
    "EventType",
    "Message",
    "PrivateMessage",
    "User",
    "UserFeature",
    "Ban",
    "Mute",
    "RoomAction",
    "Broadcast",
    "Ping",
    "Names",
    # Exceptions
    "WSGGError",
    "ConnectionError",
    "MessageError",
    "ProtocolError",
]
