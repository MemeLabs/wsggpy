"""Synchronous session for wsggpy.

Provides a synchronous interface for connecting to and interacting with
strims.gg chat via websockets.
"""

import hashlib
import logging
import threading
import time
from datetime import datetime
from typing import Any

import websocket  # websocket-client package

from .exceptions import ConnectionError, DuplicateMessageError, MessageError, WSGGError
from .handlers import (
    ErrorHandlerFunc,
    EventHandlers,
    HandlerFunc,
    SocketErrorHandlerFunc,
)
from .models import (
    DisconnectEvent,
    EventType,
    ReconnectedEvent,
    ReconnectFailedEvent,
    ReconnectingEvent,
    User,
)
from .protocol import ProtocolHandler

logger = logging.getLogger(__name__)


class Session:
    """Synchronous session for strims.gg chat."""

    def __init__(
        self,
        login_key: str | None = None,
        url: str = "wss://chat.strims.gg/ws",
        user_agent: str = "wsggpy/0.1.0",
    ) -> None:
        """Initialize a new chat session.

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
        self._ws: websocket.WebSocket | None = None
        self._connected = False
        self._running = False
        self._users: dict[str, User] = {}
        self._listen_thread: threading.Thread | None = None

        # Message deduplication
        self._message_cache: dict[str, float] = {}  # hash -> timestamp
        self._cache_ttl = 300.0  # 5 minutes
        self._max_cache_size = 1000

        # Reconnection state
        self._reconnecting = False
        self._current_attempts = 0
        self._last_disconnect_time: float | None = None
        self._auto_reconnect = True
        self._reconnect_thread: threading.Thread | None = None

        # Protocol and event handling
        self.protocol = ProtocolHandler()
        self.handlers = EventHandlers()

        # Connection configuration
        self._ping_interval = 30.0  # seconds
        self._ping_timeout = 10.0  # seconds
        self._reconnect_attempts = 3
        self._reconnect_delay = 5.0  # seconds

    def _calculate_backoff_delay(self, attempt: int) -> float:
        """Calculate exponential backoff delay for reconnection attempts."""
        return float(min(self._reconnect_delay * (2**attempt), 60.0))  # Max 60 seconds

    def set_url(self, url: str) -> None:
        """Set the websocket URL for the chat server.

        Args:
            url: WebSocket URL (e.g., "wss://chat.example.com/ws")

        Raises:
            WSGGError: If called while already connected to a chat server

        Example:
            >>> session = Session()
            >>> session.set_url("wss://chat.example.com/ws")
        """
        if self._connected:
            raise WSGGError("Cannot change URL while connected")
        self.url = url

    def set_user_agent(self, user_agent: str) -> None:
        """Set the user agent string for websocket connections.

        Args:
            user_agent: User agent string to identify the client

        Example:
            >>> session = Session()
            >>> session.set_user_agent("MyBot/1.0")
        """
        self.user_agent = user_agent

    def open(self) -> None:
        """Open a connection to the chat server.

        Establishes a WebSocket connection and starts the message listening loop
        in a background thread. If a login_key was provided during initialization,
        authentication will be attempted automatically.

        Raises:
            ConnectionError: If the connection fails for any reason

        Example:
            >>> session = Session(login_key="your_auth_token")
            >>> session.open()
            >>> # Connection is now active and listening for messages
        """
        if self._connected:
            logger.warning("Already connected")
            return

        try:
            # Create websocket connection
            self._ws = websocket.WebSocket()

            # Set up headers
            headers = {"User-Agent": self.user_agent}
            if self.login_key:
                headers["Cookie"] = f"jwt={self.login_key}"

            # Connect
            logger.info(f"Connecting to {self.url}")
            self._ws.connect(self.url, header=headers)  # type: ignore[no-untyped-call]

            self._connected = True
            self._running = True

            # Reset reconnection state on successful connection
            self._reconnecting = False
            self._current_attempts = 0

            # Start listening thread
            self._listen_thread = threading.Thread(
                target=self._listen_loop, daemon=True
            )
            self._listen_thread.start()

            logger.info("Connected successfully")

        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            self._cleanup()
            raise ConnectionError(f"Failed to connect: {e}") from e

    def close(self) -> None:
        """Close the connection and cleanup resources."""
        if not self._connected:
            return

        logger.info("Closing connection")

        # Disable auto-reconnect on manual close
        self._auto_reconnect = False
        self._running = False

        try:
            if self._ws:
                self._ws.close()
        except Exception as e:
            logger.error(f"Error closing websocket: {e}")

        # Wait for listen thread to finish
        if self._listen_thread and self._listen_thread.is_alive():
            self._listen_thread.join(timeout=5.0)

        # Wait for reconnect thread to finish
        if self._reconnect_thread and self._reconnect_thread.is_alive():
            self._reconnect_thread.join(timeout=2.0)

        self._cleanup()
        logger.info("Connection closed")

    def is_connected(self) -> bool:
        """Check if the session is connected."""
        return self._connected and not self._reconnecting and self._ws is not None

    # User management
    def get_users(self) -> list[User]:
        """Get a list of users currently in the chat."""
        return list(self._users.values())

    def get_user(self, nick: str) -> User | None:
        """Get a specific user by nickname."""
        return self._users.get(nick)

    # Message sending methods
    def send_message(self, message: str) -> None:
        """Send a chat message to the public chat.

        Args:
            message: The message content to send

        Raises:
            ConnectionError: If not connected to the chat server
            MessageError: If the message fails to send

        Example:
            >>> session.send_message("Hello everyone!")
            >>> session.send_message("/me waves")  # Action message
        """
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        # Check for duplicate
        if self._is_duplicate_message(message):
            logger.warning(f"Preventing duplicate message: {message[:50]}...")
            return

        try:
            formatted_msg = self.protocol.format_message(message)
            self._ws.send(formatted_msg)
            logger.debug(f"Sent message: {message}")
        except DuplicateMessageError:
            logger.warning("Server rejected message as duplicate")
            # Don't re-raise, just log and continue
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            raise MessageError(f"Failed to send message: {e}") from e

    def send_action(self, message: str) -> None:
        """Send an action message (/me command) to the chat.

        This is a convenience method that automatically prepends "/me " to the message.

        Args:
            message: The action content (without the /me prefix)

        Example:
            >>> session.send_action("waves at everyone")
            # Sends: "/me waves at everyone"
        """
        action_msg = f"/me {message}"
        self.send_message(action_msg)

    def send_private_message(self, nick: str, message: str) -> None:
        """Send a private message to a specific user.

        Args:
            nick: Target user's nickname
            message: The private message content

        Raises:
            ConnectionError: If not connected to the chat server
            MessageError: If the message fails to send

        Example:
            >>> session.send_private_message("username", "Hello there!")
        """
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        try:
            formatted_msg = self.protocol.format_private_message(nick, message)
            self._ws.send(formatted_msg)
            logger.debug(f"Sent PM to {nick}: {message}")
        except Exception as e:
            logger.error(f"Failed to send private message: {e}")
            raise MessageError(f"Failed to send private message: {e}") from e

    # Moderation methods
    def send_ban(self, nick: str, reason: str, duration: int | None = None) -> None:
        """Ban a user from the chat.

        Requires moderator privileges to execute successfully.

        Args:
            nick: Username to ban
            reason: Reason for the ban (will be visible to other moderators)
            duration: Ban duration in seconds. If None, ban is permanent

        Raises:
            ConnectionError: If not connected to the chat server
            MessageError: If the ban command fails to send

        Example:
            >>> session.send_ban("spammer", "Excessive spam", 3600)  # 1 hour ban
            >>> session.send_ban("troll", "Harassment")  # Permanent ban
        """
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        try:
            formatted_msg = self.protocol.format_ban(nick, reason, duration)
            self._ws.send(formatted_msg)
            logger.debug(f"Banned {nick}: {reason}")
        except Exception as e:
            logger.error(f"Failed to ban user: {e}")
            raise MessageError(f"Failed to ban user: {e}") from e

    def send_permanent_ban(self, nick: str, reason: str) -> None:
        """Permanently ban a user from the chat.

        This is a convenience method equivalent to calling send_ban() with duration=None.
        Requires moderator privileges to execute successfully.

        Args:
            nick: Username to permanently ban
            reason: Reason for the ban

        Example:
            >>> session.send_permanent_ban("persistent_troll", "Repeated harassment")
        """
        self.send_ban(nick, reason, None)

    def send_unban(self, nick: str) -> None:
        """Remove a ban from a user.

        Requires moderator privileges to execute successfully.

        Args:
            nick: Username to unban

        Raises:
            ConnectionError: If not connected to the chat server
            MessageError: If the unban command fails to send

        Example:
            >>> session.send_unban("reformed_user")
        """
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        try:
            formatted_msg = self.protocol.format_unban(nick)
            self._ws.send(formatted_msg)
            logger.debug(f"Unbanned {nick}")
        except Exception as e:
            logger.error(f"Failed to unban user: {e}")
            raise MessageError(f"Failed to unban user: {e}") from e

    def send_mute(self, nick: str, duration: int | None = None) -> None:
        """Mute a user in the chat.

        Muted users can see messages but cannot send them.
        Requires moderator privileges to execute successfully.

        Args:
            nick: Username to mute
            duration: Mute duration in seconds. If None, mute is permanent

        Raises:
            ConnectionError: If not connected to the chat server
            MessageError: If the mute command fails to send

        Example:
            >>> session.send_mute("noisy_user", 300)  # 5 minute mute
            >>> session.send_mute("spam_bot")  # Permanent mute
        """
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        try:
            formatted_msg = self.protocol.format_mute(nick, duration)
            self._ws.send(formatted_msg)
            logger.debug(f"Muted {nick}")
        except Exception as e:
            logger.error(f"Failed to mute user: {e}")
            raise MessageError(f"Failed to mute user: {e}") from e

    def send_unmute(self, nick: str) -> None:
        """Remove a mute from a user.

        Requires moderator privileges to execute successfully.

        Args:
            nick: Username to unmute

        Raises:
            ConnectionError: If not connected to the chat server
            MessageError: If the unmute command fails to send

        Example:
            >>> session.send_unmute("previously_muted_user")
        """
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        try:
            formatted_msg = self.protocol.format_unmute(nick)
            self._ws.send(formatted_msg)
            logger.debug(f"Unmuted {nick}")
        except Exception as e:
            logger.error(f"Failed to unmute user: {e}")
            raise MessageError(f"Failed to unmute user: {e}") from e

    def send_ping(self) -> None:
        """Send a ping message to the server.

        Useful for testing connection latency and keeping the connection alive.
        The server will respond with a PONG message.

        Raises:
            ConnectionError: If not connected to the chat server
            MessageError: If the ping fails to send

        Example:
            >>> session.send_ping()
            # Server will respond with a PONG event
        """
        if not self._connected or not self._ws:
            raise ConnectionError("Not connected")

        try:
            formatted_msg = self.protocol.format_ping()
            self._ws.send(formatted_msg)
            logger.debug("Sent ping")
        except Exception as e:
            logger.error(f"Failed to send ping: {e}")
            raise MessageError(f"Failed to send ping: {e}") from e

    # Event handler registration methods
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

    def add_disconnect_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for disconnection events."""
        self.handlers.add_disconnect_handler(handler)

    def add_reconnecting_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for reconnection attempt events."""
        self.handlers.add_reconnecting_handler(handler)

    def add_reconnected_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for successful reconnection events."""
        self.handlers.add_reconnected_handler(handler)

    def add_reconnect_failed_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for failed reconnection events."""
        self.handlers.add_reconnect_failed_handler(handler)

    # Configuration methods
    def set_auto_reconnect(self, enabled: bool) -> None:
        """Enable or disable automatic reconnection.

        Args:
            enabled: Whether to automatically reconnect on disconnection
        """
        self._auto_reconnect = enabled

    def set_reconnect_config(self, attempts: int, delay: float) -> None:
        """Configure reconnection behavior.

        Args:
            attempts: Maximum number of reconnection attempts
            delay: Base delay between attempts in seconds (will use exponential backoff)
        """
        if attempts < 0:
            raise ValueError("Reconnect attempts must be non-negative")
        if delay < 0:
            raise ValueError("Reconnect delay must be non-negative")

        self._reconnect_attempts = attempts
        self._reconnect_delay = delay

    def is_reconnecting(self) -> bool:
        """Check if currently attempting to reconnect."""
        return self._reconnecting

    def get_connection_info(self) -> dict[str, Any]:
        """Get detailed connection state information."""
        return {
            "connected": self._connected,
            "reconnecting": self._reconnecting,
            "attempts": self._current_attempts,
            "last_disconnect": self._last_disconnect_time,
            "auto_reconnect": self._auto_reconnect,
        }

    def force_reconnect(self) -> None:
        """Manually trigger a reconnection attempt."""
        if self._connected:
            logger.info("Forcing reconnection - closing current connection")
            self.close()

        self._current_attempts = 0
        self._attempt_reconnection()

    def _handle_disconnect(self, reason: str = "unknown") -> None:
        """Handle disconnection and attempt reconnection if enabled."""
        if self._reconnecting:
            # Already handling disconnection
            return

        self._last_disconnect_time = time.time()
        logger.warning(f"Disconnected from chat: {reason}")

        # Create and dispatch disconnect event
        disconnect_event = DisconnectEvent(reason=reason, timestamp=datetime.now())
        self.handlers.dispatch_event(disconnect_event, self)

        # Attempt reconnection if enabled
        if self._auto_reconnect and self._current_attempts < self._reconnect_attempts:
            self._reconnect_thread = threading.Thread(
                target=self._attempt_reconnection, daemon=True
            )
            self._reconnect_thread.start()
        else:
            # Final cleanup if no more attempts
            self._cleanup()

            # Dispatch reconnect failed event
            if self._current_attempts >= self._reconnect_attempts:
                failed_event = ReconnectFailedEvent(
                    total_attempts=self._current_attempts, timestamp=datetime.now()
                )
                self.handlers.dispatch_event(failed_event, self)

    def _attempt_reconnection(self) -> None:
        """Attempt to reconnect with exponential backoff."""
        self._reconnecting = True
        self._current_attempts += 1

        # Calculate delay with exponential backoff
        delay = self._calculate_backoff_delay(self._current_attempts - 1)

        logger.info(
            f"Attempting reconnection {self._current_attempts}/{self._reconnect_attempts} in {delay:.1f}s"
        )

        # Create and dispatch reconnecting event
        reconnecting_event = ReconnectingEvent(
            attempt=self._current_attempts, delay=delay, timestamp=datetime.now()
        )
        self.handlers.dispatch_event(reconnecting_event, self)

        # Wait before attempting
        time.sleep(delay)

        try:
            # Attempt to reopen connection
            self.open()

            # Create and dispatch successful reconnection event
            reconnected_event = ReconnectedEvent(
                attempts_taken=self._current_attempts, timestamp=datetime.now()
            )
            self.handlers.dispatch_event(reconnected_event, self)

            logger.info(
                f"Reconnected successfully after {self._current_attempts} attempts"
            )

        except Exception as e:
            logger.error(f"Reconnection attempt {self._current_attempts} failed: {e}")

            # Try again or give up
            if self._current_attempts < self._reconnect_attempts:
                self._attempt_reconnection()
            else:
                self._reconnecting = False
                self._cleanup()

                # Dispatch final failure event
                failed_event = ReconnectFailedEvent(
                    total_attempts=self._current_attempts, timestamp=datetime.now()
                )
                self.handlers.dispatch_event(failed_event, self)

    # Internal methods
    def _generate_message_hash(self, message: str) -> str:
        """Generate a hash for message deduplication."""
        return hashlib.sha256(message.encode("utf-8")).hexdigest()[:16]

    def _cleanup_message_cache(self) -> None:
        """Remove expired messages from cache."""
        current_time = time.time()
        expired_hashes = [
            msg_hash
            for msg_hash, timestamp in self._message_cache.items()
            if current_time - timestamp > self._cache_ttl
        ]
        for msg_hash in expired_hashes:
            del self._message_cache[msg_hash]

        # Limit cache size
        if len(self._message_cache) > self._max_cache_size:
            # Remove oldest entries
            sorted_items = sorted(self._message_cache.items(), key=lambda x: x[1])
            excess_count = len(self._message_cache) - self._max_cache_size + 100
            for msg_hash, _ in sorted_items[:excess_count]:
                del self._message_cache[msg_hash]

    def _is_duplicate_message(self, message: str) -> bool:
        """Check if message is a recent duplicate."""
        msg_hash = self._generate_message_hash(message)
        current_time = time.time()

        if msg_hash in self._message_cache:
            # Check if message is within duplicate time window
            time_diff = current_time - self._message_cache[msg_hash]
            if time_diff < self._cache_ttl:
                return True

        # Add to cache
        self._message_cache[msg_hash] = current_time
        self._cleanup_message_cache()
        return False

    def _listen_loop(self) -> None:
        """Main listening loop for incoming messages."""
        logger.debug("Starting message listen loop")

        while self._running:
            try:
                if not self._ws:
                    break

                # Receive message with timeout
                self._ws.settimeout(1.0)  # 1 second timeout
                try:
                    raw_message = self._ws.recv()
                except websocket.WebSocketTimeoutException:
                    continue  # Timeout is normal, continue loop

                if not raw_message:
                    logger.warning("Received empty message")
                    continue

                # Parse and handle message
                try:
                    # Ensure message is a string
                    message_str = (
                        raw_message
                        if isinstance(raw_message, str)
                        else raw_message.decode("utf-8")
                    )
                    event = self.protocol.parse_message(message_str)
                    if event:
                        self._handle_event(event)
                except DuplicateMessageError:
                    # Duplicate messages are expected, just log and continue
                    logger.debug("Received duplicate message from server")
                except Exception as e:
                    logger.error(f"Failed to parse message: {e}")
                    self.handlers.dispatch_error(f"Failed to parse message: {e}", self)

            except websocket.WebSocketConnectionClosedException:
                self._handle_disconnect("server closed connection")
                break
            except Exception as e:
                logger.error(f"Error in listen loop: {e}")
                self.handlers.dispatch_socket_error(e, self)
                self._handle_disconnect(f"listen loop error: {e}")
                break

        logger.debug("Listen loop ended")
        if not self._reconnecting:
            self._cleanup()

    def _handle_event(self, event: EventType) -> None:
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

    def _cleanup(self) -> None:
        """Clean up connection state."""
        self._connected = False
        self._running = False
        self._ws = None
        self._users.clear()
        self._listen_thread = None

        # Only reset reconnection state if not currently reconnecting
        if not self._reconnecting:
            self._current_attempts = 0
