"""Asynchronous session for wsggpy.

Provides an asynchronous interface for connecting to and interacting with
strims.gg chat via websockets using asyncio.
"""

import asyncio
import logging
from typing import Any

import aiohttp

from .exceptions import ConnectionError, MessageError, WSGGError
from .handlers import (
    ErrorHandlerFunc,
    EventHandlers,
    HandlerFunc,
    SocketErrorHandlerFunc,
)
from .models import EventType, User
from .protocol import ProtocolHandler

logger = logging.getLogger(__name__)


class AsyncSession:
    """Asynchronous session for strims.gg chat."""

    def __init__(
        self,
        login_key: str | None = None,
        url: str = "wss://chat.strims.gg/ws",
        user_agent: str = "wsggpy/0.1.0",
    ) -> None:
        """Initialize a new async chat session.

        Args:
            login_key: Authentication token for the chat
            url: WebSocket URL for the chat server. Use ChatEnvironment constants:
                 - ChatEnvironment.PRODUCTION: "wss://chat.strims.gg/ws" (default)
                 - ChatEnvironment.DEV: "wss://chat2.strims.gg/ws"
            user_agent: User agent string to use for connection
        """
        self.login_key = login_key
        self.url = url
        self.user_agent = user_agent

        # Internal state
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._session: aiohttp.ClientSession | None = None
        self._connected = False
        self._running = False
        self._users: dict[str, User] = {}
        self._listen_task: asyncio.Task[None] | None = None

        # Protocol and event handling
        self.protocol = ProtocolHandler()
        self.handlers = EventHandlers()

        # Connection configuration
        self._ping_interval = 30.0  # seconds
        self._ping_timeout = 10.0  # seconds
        self._reconnect_attempts = 3
        self._reconnect_delay = 5.0  # seconds

    def set_url(self, url: str) -> None:
        """Set the websocket URL."""
        if self._connected:
            raise WSGGError("Cannot change URL while connected")
        self.url = url

    def set_user_agent(self, user_agent: str) -> None:
        """Set the user agent string."""
        self.user_agent = user_agent

    async def open(self) -> None:
        """Open a connection to the chat server."""
        if self._connected:
            logger.warning("Already connected")
            return

        try:
            # Create aiohttp session
            self._session = aiohttp.ClientSession()

            # Set up headers and cookies
            headers = {"User-Agent": self.user_agent}
            if self.login_key:
                headers["Cookie"] = f"jwt={self.login_key}"

            # Connect
            logger.info(f"Connecting to {self.url}")
            self._ws = await self._session.ws_connect(
                self.url, headers=headers, heartbeat=self._ping_interval
            )

            self._connected = True
            self._running = True

            # Start listening task
            self._listen_task = asyncio.create_task(self._listen_loop())

            logger.info("Connected successfully")

        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            await self._cleanup()
            raise ConnectionError(f"Failed to connect: {e}") from e

    async def close(self) -> None:
        """Close the connection and cleanup resources."""
        if not self._connected:
            return

        logger.info("Closing connection")
        self._running = False

        # Cancel listen task
        if self._listen_task and not self._listen_task.done():
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass

        # Close websocket
        try:
            if self._ws and not self._ws.closed:
                await self._ws.close()
        except Exception as e:
            logger.error(f"Error closing websocket: {e}")

        await self._cleanup()
        logger.info("Connection closed")

    def is_connected(self) -> bool:
        """Check if the session is connected."""
        return self._connected and self._ws is not None and not self._ws.closed

    # User management
    def get_users(self) -> list[User]:
        """Get a list of users currently in the chat."""
        return list(self._users.values())

    def get_user(self, nick: str) -> User | None:
        """Get a specific user by nickname."""
        return self._users.get(nick)

    # Message sending methods
    async def send_message(self, message: str) -> None:
        """Send a chat message."""
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        try:
            formatted_msg = self.protocol.format_message(message)
            await self._ws.send_str(formatted_msg)
            logger.debug(f"Sent message: {message}")
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            raise MessageError(f"Failed to send message: {e}") from e

    async def send_action(self, message: str) -> None:
        """Send an action message (/me command)."""
        action_msg = f"/me {message}"
        await self.send_message(action_msg)

    async def send_private_message(self, nick: str, message: str) -> None:
        """Send a private message to a user."""
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        try:
            formatted_msg = self.protocol.format_private_message(nick, message)
            await self._ws.send_str(formatted_msg)
            logger.debug(f"Sent PM to {nick}: {message}")
        except Exception as e:
            logger.error(f"Failed to send private message: {e}")
            raise MessageError(f"Failed to send private message: {e}") from e

    # Moderation methods
    async def send_ban(
        self, nick: str, reason: str, duration: int | None = None
    ) -> None:
        """Ban a user."""
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        try:
            formatted_msg = self.protocol.format_ban(nick, reason, duration)
            await self._ws.send_str(formatted_msg)
            logger.debug(f"Banned {nick}: {reason}")
        except Exception as e:
            logger.error(f"Failed to ban user: {e}")
            raise MessageError(f"Failed to ban user: {e}") from e

    async def send_permanent_ban(self, nick: str, reason: str) -> None:
        """Permanently ban a user."""
        await self.send_ban(nick, reason, None)

    async def send_unban(self, nick: str) -> None:
        """Unban a user."""
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        try:
            formatted_msg = self.protocol.format_unban(nick)
            await self._ws.send_str(formatted_msg)
            logger.debug(f"Unbanned {nick}")
        except Exception as e:
            logger.error(f"Failed to unban user: {e}")
            raise MessageError(f"Failed to unban user: {e}") from e

    async def send_mute(self, nick: str, duration: int | None = None) -> None:
        """Mute a user."""
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        try:
            formatted_msg = self.protocol.format_mute(nick, duration)
            await self._ws.send_str(formatted_msg)
            logger.debug(f"Muted {nick}")
        except Exception as e:
            logger.error(f"Failed to mute user: {e}")
            raise MessageError(f"Failed to mute user: {e}") from e

    async def send_unmute(self, nick: str) -> None:
        """Unmute a user."""
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        try:
            formatted_msg = self.protocol.format_unmute(nick)
            await self._ws.send_str(formatted_msg)
            logger.debug(f"Unmuted {nick}")
        except Exception as e:
            logger.error(f"Failed to unmute user: {e}")
            raise MessageError(f"Failed to unmute user: {e}") from e

    async def send_ping(self) -> None:
        """Send a ping to the server."""
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        try:
            formatted_msg = self.protocol.format_ping()
            await self._ws.send_str(formatted_msg)
            logger.debug("Sent ping")
        except Exception as e:
            logger.error(f"Failed to send ping: {e}")
            raise MessageError(f"Failed to send ping: {e}") from e

    # Event handler registration methods (same as sync version)
    def add_message_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for chat messages."""
        self.handlers.add_message_handler(handler)

    def add_private_message_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for private messages."""
        self.handlers.add_private_message_handler(handler)

    def add_ban_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for ban events."""
        self.handlers.add_ban_handler(handler)

    def add_unban_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for unban events."""
        self.handlers.add_unban_handler(handler)

    def add_mute_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for mute events."""
        self.handlers.add_mute_handler(handler)

    def add_unmute_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for unmute events."""
        self.handlers.add_unmute_handler(handler)

    def add_join_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for user join events."""
        self.handlers.add_join_handler(handler)

    def add_quit_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for user quit events."""
        self.handlers.add_quit_handler(handler)

    def add_broadcast_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for broadcast messages."""
        self.handlers.add_broadcast_handler(handler)

    def add_ping_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for ping/pong events."""
        self.handlers.add_ping_handler(handler)

    def add_names_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for user list updates."""
        self.handlers.add_names_handler(handler)

    def add_error_handler(self, handler: ErrorHandlerFunc) -> None:
        """Add a handler for chat errors."""
        self.handlers.add_error_handler(handler)

    def add_socket_error_handler(self, handler: SocketErrorHandlerFunc) -> None:
        """Add a handler for websocket errors."""
        self.handlers.add_socket_error_handler(handler)

    def add_generic_handler(self, handler: HandlerFunc) -> None:
        """Add a handler that receives all events."""
        self.handlers.add_generic_handler(handler)

    # Context manager support
    async def __aenter__(self) -> "AsyncSession":
        """Enter the async context manager by opening the connection."""
        await self.open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Exit the async context manager by closing the connection."""
        await self.close()

    # Internal methods
    async def _listen_loop(self) -> None:
        """Main listening loop for incoming messages."""
        logger.debug("Starting async message listen loop")

        try:
            if self._ws is None:
                return

            async for msg in self._ws:
                if not self._running:
                    break

                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        event = self.protocol.parse_message(msg.data)
                        if event:
                            await self._handle_event(event)
                    except Exception as e:
                        logger.error(f"Failed to parse message: {e}")
                        self.handlers.dispatch_error(
                            f"Failed to parse message: {e}", self
                        )

                elif msg.type == aiohttp.WSMsgType.ERROR:
                    if self._ws is not None:
                        ws_exception = self._ws.exception()
                        logger.error(f"WebSocket error: {ws_exception}")
                        if isinstance(ws_exception, Exception):
                            self.handlers.dispatch_socket_error(ws_exception, self)
                    break

                elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING):
                    logger.info("WebSocket connection closed")
                    break

        except asyncio.CancelledError:
            logger.debug("Listen loop cancelled")
        except Exception as e:
            logger.error(f"Error in async listen loop: {e}")
            self.handlers.dispatch_socket_error(e, self)

        logger.debug("Async listen loop ended")
        await self._cleanup()

    async def _handle_event(self, event: EventType) -> None:
        """Handle a parsed event."""
        try:
            # Update user state if applicable
            self._update_user_state(event)

            # Dispatch to handlers
            self.handlers.dispatch_event(event, self)

        except Exception as e:
            logger.error(f"Error handling event: {e}")
            self.handlers.dispatch_socket_error(e, self)

    def _update_user_state(self, event: EventType) -> None:
        """Update internal user state based on events."""
        from .models import Message, Names, PrivateMessage, RoomAction

        if isinstance(event, Message | PrivateMessage):
            self._users[event.sender.nick] = event.sender
        elif isinstance(event, RoomAction):
            # For join events, add user; for quit events, remove user
            # This logic may need refinement based on actual protocol
            self._users[event.user.nick] = event.user
        elif isinstance(event, Names):
            # Update entire user list
            self._users.clear()
            for user in event.users:
                self._users[user.nick] = user

    async def _cleanup(self) -> None:
        """Clean up connection state."""
        self._connected = False
        self._running = False

        if self._session and not self._session.closed:
            await self._session.close()

        self._ws = None
        self._session = None
        self._users.clear()
        self._listen_task = None
