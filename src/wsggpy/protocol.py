"""Protocol handling for wsggpy.

Handles parsing of incoming websocket messages and formatting of outgoing messages
according to the strims.gg chat protocol.
"""

import json
import logging
from datetime import datetime
from typing import Any, TypeVar

from .exceptions import DuplicateMessageError, ProtocolError
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

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=EventType)


class ProtocolHandler:
    """Handles chat protocol parsing and formatting."""

    def __init__(self) -> None:
        """Initialize ProtocolHandler with message parsers."""
        from collections.abc import Callable

        self.message_parsers: dict[str, Callable[[dict[str, Any]], Any]] = {
            "MSG": self._parse_message,
            "PRIVMSG": self._parse_private_message,
            "BAN": self._parse_ban,
            "UNBAN": self._parse_unban,
            "MUTE": self._parse_mute,
            "UNMUTE": self._parse_unmute,
            "JOIN": self._parse_join,
            "QUIT": self._parse_quit,
            "BROADCAST": self._parse_broadcast,
            "PONG": self._parse_pong,
            "NAMES": self._parse_names,
            "ERR": self._parse_error,
        }

    def parse_message(self, raw_message: str) -> EventType | None:
        """Parse a raw websocket message into an event object."""
        try:
            if not raw_message.strip():
                return None

            # Handle ERR messages that may not be JSON (e.g., 'ERR "duplicate"')
            if raw_message.startswith("ERR "):
                self._handle_error_message(raw_message)
                return None

            # Check for prefix-based messages first (e.g., "NAMES {...}", "MSG {...}", "JOIN {...}")
            parts = raw_message.split(" ", 1)
            if len(parts) == 2:
                prefix, json_part = parts

                # Handle all known prefix-based message types
                if prefix == "NAMES":
                    try:
                        data = json.loads(json_part)
                        return self._parse_names_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in NAMES message: {raw_message}")
                        raise ProtocolError(
                            f"Invalid JSON in NAMES message: {e}"
                        ) from e

                elif prefix == "MSG":
                    try:
                        data = json.loads(json_part)
                        return self._parse_msg_prefix_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in MSG message: {raw_message}")
                        raise ProtocolError(f"Invalid JSON in MSG message: {e}") from e

                elif prefix == "PRIVMSG":
                    try:
                        data = json.loads(json_part)
                        return self._parse_privmsg_prefix_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in PRIVMSG message: {raw_message}")
                        raise ProtocolError(
                            f"Invalid JSON in PRIVMSG message: {e}"
                        ) from e

                elif prefix == "JOIN":
                    try:
                        data = json.loads(json_part)
                        return self._parse_join_prefix_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in JOIN message: {raw_message}")
                        raise ProtocolError(f"Invalid JSON in JOIN message: {e}") from e

                elif prefix == "QUIT":
                    try:
                        data = json.loads(json_part)
                        return self._parse_quit_prefix_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in QUIT message: {raw_message}")
                        raise ProtocolError(f"Invalid JSON in QUIT message: {e}") from e

                elif prefix == "VIEWERSTATE":
                    try:
                        data = json.loads(json_part)
                        return self._parse_viewerstate_prefix_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(
                            f"Invalid JSON in VIEWERSTATE message: {raw_message}"
                        )
                        raise ProtocolError(
                            f"Invalid JSON in VIEWERSTATE message: {e}"
                        ) from e

                elif prefix == "BAN":
                    try:
                        data = json.loads(json_part)
                        return self._parse_ban_prefix_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in BAN message: {raw_message}")
                        raise ProtocolError(f"Invalid JSON in BAN message: {e}") from e

                elif prefix == "UNBAN":
                    try:
                        data = json.loads(json_part)
                        return self._parse_unban_prefix_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in UNBAN message: {raw_message}")
                        raise ProtocolError(
                            f"Invalid JSON in UNBAN message: {e}"
                        ) from e

                elif prefix == "MUTE":
                    try:
                        data = json.loads(json_part)
                        return self._parse_mute_prefix_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in MUTE message: {raw_message}")
                        raise ProtocolError(f"Invalid JSON in MUTE message: {e}") from e

                elif prefix == "UNMUTE":
                    try:
                        data = json.loads(json_part)
                        return self._parse_unmute_prefix_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in UNMUTE message: {raw_message}")
                        raise ProtocolError(
                            f"Invalid JSON in UNMUTE message: {e}"
                        ) from e

                elif prefix == "BROADCAST":
                    try:
                        data = json.loads(json_part)
                        return self._parse_broadcast_prefix_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(
                            f"Invalid JSON in BROADCAST message: {raw_message}"
                        )
                        raise ProtocolError(
                            f"Invalid JSON in BROADCAST message: {e}"
                        ) from e

                elif prefix == "PONG":
                    try:
                        data = json.loads(json_part)
                        return self._parse_pong_prefix_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in PONG message: {raw_message}")
                        raise ProtocolError(f"Invalid JSON in PONG message: {e}") from e

            # Parse standard JSON message (fallback for non-prefix messages)
            try:
                data = json.loads(raw_message)
            except json.JSONDecodeError as e:
                # Handle non-JSON messages (legacy format)
                logger.error(f"Invalid JSON message: {raw_message}")
                raise ProtocolError(f"Invalid JSON: {e}") from e

            msg_type = data.get("type")
            if not msg_type:
                logger.warning(f"Message missing type field: {data}")
                return None

            parser = self.message_parsers.get(msg_type)
            if not parser:
                logger.warning(f"Unknown message type: {msg_type}")
                return None

            result = parser(data)
            return (
                result
                if isinstance(
                    result,
                    Message
                    | PrivateMessage
                    | Ban
                    | Mute
                    | RoomAction
                    | Broadcast
                    | Ping
                    | Names,
                )
                else None
            )

        except Exception as e:
            logger.error(f"Failed to parse message '{raw_message}': {e}")
            raise ProtocolError(f"Failed to parse message: {e}") from e

    def _handle_error_message(self, raw_message: str) -> None:
        """Handle ERR messages that may not be in JSON format.

        Args:
            raw_message: Raw message starting with "ERR "

        Raises:
            DuplicateMessageError: If the error is about duplicate messages
            ProtocolError: For other types of errors
        """
        # Extract the error content after "ERR "
        error_content = raw_message[4:].strip()

        # Handle specific error types
        if error_content == '"duplicate"' or error_content == "duplicate":
            logger.warning("Server rejected duplicate message")
            raise DuplicateMessageError("Message was rejected as duplicate")
        else:
            logger.error(f"Server error: {error_content}")
            raise ProtocolError(f"Server error: {error_content}")

    def format_message(self, message: str) -> str:
        """Format an outgoing chat message for transmission.

        Args:
            message: The message content to send to the chat

        Returns:
            Prefix-formatted string ready for websocket transmission

        Example:
            >>> handler.format_message("Hello world!")
            'MSG {"data": "Hello world!"}'
        """
        data = {"data": message}
        return f"MSG {json.dumps(data)}"

    def format_private_message(self, nick: str, message: str) -> str:
        """Format an outgoing private message for transmission.

        Args:
            nick: Target user's nickname to send the private message to
            message: The private message content

        Returns:
            Prefix-formatted string ready for websocket transmission

        Example:
            >>> handler.format_private_message("user123", "Hello!")
            'PRIVMSG {"data": {"nick": "user123", "message": "Hello!"}}'
        """
        data = {"data": {"nick": nick, "message": message}}
        return f"PRIVMSG {json.dumps(data)}"

    def format_ban(self, nick: str, reason: str, duration: int | None = None) -> str:
        """Format a ban command for transmission.

        Args:
            nick: Username to ban
            reason: Reason for the ban
            duration: Ban duration in seconds. If None, ban is permanent

        Returns:
            JSON-formatted string ready for websocket transmission

        Example:
            >>> handler.format_ban("spammer", "Excessive spam", 3600)
            '{"type": "BAN", "data": {"nick": "spammer", "reason": "Excessive spam", "duration": 3600}}'

            >>> handler.format_ban("troll", "Harassment")  # Permanent ban
            '{"type": "BAN", "data": {"nick": "troll", "reason": "Harassment"}}'
        """
        data: dict[str, Any] = {"nick": nick, "reason": reason}
        if duration is not None:
            data["duration"] = duration

        return json.dumps({"type": "BAN", "data": data})

    def format_mute(self, nick: str, duration: int | None = None) -> str:
        """Format a mute command for transmission.

        Args:
            nick: Username to mute
            duration: Mute duration in seconds. If None, mute is permanent

        Returns:
            JSON-formatted string ready for websocket transmission

        Example:
            >>> handler.format_mute("noisy_user", 300)  # 5 minute mute
            '{"type": "MUTE", "data": {"nick": "noisy_user", "duration": 300}}'
        """
        data: dict[str, Any] = {"nick": nick}
        if duration is not None:
            data["duration"] = duration

        return json.dumps({"type": "MUTE", "data": data})

    def format_unban(self, nick: str) -> str:
        """Format an unban command for transmission.

        Args:
            nick: Username to unban

        Returns:
            JSON-formatted string ready for websocket transmission

        Example:
            >>> handler.format_unban("user123")
            '{"type": "UNBAN", "data": {"nick": "user123"}}'
        """
        return json.dumps({"type": "UNBAN", "data": {"nick": nick}})

    def format_unmute(self, nick: str) -> str:
        """Format an unmute command for transmission.

        Args:
            nick: Username to unmute

        Returns:
            JSON-formatted string ready for websocket transmission

        Example:
            >>> handler.format_unmute("user123")
            '{"type": "UNMUTE", "data": {"nick": "user123"}}'
        """
        return json.dumps({"type": "UNMUTE", "data": {"nick": nick}})

    def format_ping(self) -> str:
        """Format a ping message for transmission.

        Used to maintain connection with the server and measure latency.

        Returns:
            JSON-formatted ping message ready for websocket transmission

        Example:
            >>> handler.format_ping()
            '{"type": "PING"}'
        """
        return json.dumps(
            {"type": "PING", "data": int(datetime.now().timestamp() * 1000)}
        )

    def _parse_user(self, user_data: dict[str, Any]) -> User:
        """Parse user data from message."""
        features = []
        for feature_str in user_data.get("features", []):
            try:
                features.append(UserFeature(feature_str))
            except ValueError:
                logger.warning(f"Unknown user feature: {feature_str}")

        return User(
            id=user_data.get("id", 0), nick=user_data.get("nick", ""), features=features
        )

    def _parse_timestamp(self, timestamp: str | int | float | None) -> datetime | None:
        """Parse timestamp from various formats."""
        if timestamp is None:
            return None

        try:
            if isinstance(timestamp, str):
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            elif isinstance(timestamp, int | float):
                return datetime.fromtimestamp(timestamp / 1000)  # Assume milliseconds
        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse timestamp {timestamp}: {e}")

        return None

    def _parse_message(self, data: dict[str, Any]) -> Message:
        """Parse MSG event."""
        user_data = data.get("user", {})
        return Message(
            sender=self._parse_user(user_data),
            message=data.get("data", ""),
            timestamp=self._parse_timestamp(data.get("timestamp")) or datetime.now(),
        )

    def _parse_private_message(self, data: dict[str, Any]) -> PrivateMessage:
        """Parse PRIVMSG event."""
        user_data = data.get("user", {})
        target_data = data.get("target", {})
        msg_data = data.get("data", {})

        return PrivateMessage(
            sender=self._parse_user(user_data),
            recipient=self._parse_user(target_data),
            message=msg_data.get("message", ""),
            timestamp=self._parse_timestamp(data.get("timestamp")) or datetime.now(),
        )

    def _parse_ban(self, data: dict[str, Any]) -> Ban:
        """Parse BAN event."""
        user_data = data.get("user", {})
        target_data = data.get("target", {})
        ban_data = data.get("data", {})

        return Ban(
            sender=self._parse_user(user_data),
            target=self._parse_user(target_data),
            reason=ban_data.get("reason", ""),
            duration=ban_data.get("duration"),
            timestamp=self._parse_timestamp(data.get("timestamp")) or datetime.now(),
        )

    def _parse_unban(self, data: dict[str, Any]) -> Ban:
        """Parse UNBAN event (represented as Ban with duration=0)."""
        return self._parse_ban(data)

    def _parse_mute(self, data: dict[str, Any]) -> Mute:
        """Parse MUTE event."""
        user_data = data.get("user", {})
        target_data = data.get("target", {})
        mute_data = data.get("data", {})

        return Mute(
            sender=self._parse_user(user_data),
            target=self._parse_user(target_data),
            duration=mute_data.get("duration"),
            timestamp=self._parse_timestamp(data.get("timestamp")) or datetime.now(),
        )

    def _parse_unmute(self, data: dict[str, Any]) -> Mute:
        """Parse UNMUTE event (represented as Mute with duration=0)."""
        return self._parse_mute(data)

    def _parse_join(self, data: dict[str, Any]) -> RoomAction:
        """Parse JOIN event."""
        user_data = data.get("user", {})
        return RoomAction(
            user=self._parse_user(user_data),
            timestamp=self._parse_timestamp(data.get("timestamp")) or datetime.now(),
        )

    def _parse_quit(self, data: dict[str, Any]) -> RoomAction:
        """Parse QUIT event."""
        return self._parse_join(data)  # Same structure

    def _parse_broadcast(self, data: dict[str, Any]) -> Broadcast:
        """Parse BROADCAST event."""
        user_data = data.get("user", {})
        return Broadcast(
            sender=self._parse_user(user_data),
            message=data.get("data", ""),
            timestamp=self._parse_timestamp(data.get("timestamp")) or datetime.now(),
        )

    def _parse_pong(self, data: dict[str, Any]) -> Ping:
        """Parse PONG event."""
        return Ping(
            timestamp=self._parse_timestamp(data.get("timestamp")) or datetime.now()
        )

    def _parse_msg_prefix_message(self, data: dict[str, Any]) -> Message:
        """Parse MSG prefix message format."""
        # Transform the prefix format to standard format expected by _parse_message
        user_data = {
            "nick": data.get("nick", ""),
            "features": data.get("features", []),
            "id": data.get("id", 0),  # Use default if not present
        }

        transformed_data = {
            "user": user_data,
            "data": data.get("data", ""),
            "timestamp": data.get("timestamp"),
        }

        return self._parse_message(transformed_data)

    def _parse_privmsg_prefix_message(self, data: dict[str, Any]) -> PrivateMessage:
        """Parse PRIVMSG prefix message format."""
        # The PRIVMSG prefix format should match the output of format_private_message
        msg_data = data.get("data", {})

        # For prefix format, we need to construct the user and target from context
        # This might need adjustment based on actual protocol specification
        user_data = {
            "nick": data.get("nick", ""),
            "features": data.get("features", []),
            "id": data.get("id", 0),
        }

        target_data = {"nick": msg_data.get("nick", ""), "features": [], "id": 0}

        transformed_data = {
            "user": user_data,
            "target": target_data,
            "data": {"message": msg_data.get("message", "")},
            "timestamp": data.get("timestamp"),
        }

        return self._parse_private_message(transformed_data)

    def _parse_names_message(self, data: dict[str, Any]) -> Names:
        """Parse NAMES prefix message format."""
        users_data = data.get("users", [])
        users = [self._parse_user(user_data) for user_data in users_data]

        return Names(
            users=users,
            connectioncount=data.get("connectioncount", 0),
            timestamp=datetime.now(),
        )

    def _parse_names(self, data: dict[str, Any]) -> Names:
        """Parse NAMES event (standard JSON format)."""
        users_data = data.get("data", [])
        users = [self._parse_user(user_data) for user_data in users_data]

        return Names(
            users=users,
            connectioncount=data.get("connectioncount", 0),
            timestamp=self._parse_timestamp(data.get("timestamp")) or datetime.now(),
        )

    def _parse_error(self, data: dict[str, Any]) -> None:
        """Parse ERR event."""
        error_msg = data.get("data", "Unknown error")
        logger.error(f"Chat error: {error_msg}")
        raise ProtocolError(f"Chat error: {error_msg}")

    def _parse_legacy_message(self, raw_message: str) -> EventType | None:
        """Parse legacy non-JSON message format."""
        # This would handle older message formats if needed
        logger.warning(f"Legacy message format not supported: {raw_message}")
        return None

    def _parse_join_prefix_message(self, data: dict[str, Any]) -> RoomAction:
        """Parse JOIN prefix message format."""
        # Transform prefix format to standard format
        user_data = {
            "nick": data.get("nick", ""),
            "features": data.get("features", []),
            "id": data.get("id", 0),
        }

        transformed_data = {"user": user_data, "timestamp": data.get("timestamp")}

        return self._parse_join(transformed_data)

    def _parse_quit_prefix_message(self, data: dict[str, Any]) -> RoomAction:
        """Parse QUIT prefix message format."""
        # Transform prefix format to standard format
        user_data = {
            "nick": data.get("nick", ""),
            "features": data.get("features", []),
            "id": data.get("id", 0),
        }

        transformed_data = {"user": user_data, "timestamp": data.get("timestamp")}

        return self._parse_quit(transformed_data)

    def _parse_viewerstate_prefix_message(self, data: dict[str, Any]) -> RoomAction:
        """Parse VIEWERSTATE prefix message format."""
        # VIEWERSTATE appears to be a user state change (online/offline)
        # We'll treat it as a RoomAction for now
        user_data = {
            "nick": data.get("nick", ""),
            "features": data.get("features", []),
            "id": data.get("id", 0),
        }

        transformed_data = {"user": user_data, "timestamp": data.get("timestamp")}

        # Use JOIN parser for online=true, QUIT parser for online=false
        if data.get("online", True):
            return self._parse_join(transformed_data)
        else:
            return self._parse_quit(transformed_data)

    def _parse_ban_prefix_message(self, data: dict[str, Any]) -> Ban:
        """Parse BAN prefix message format."""
        # Transform prefix format to standard format
        user_data = {
            "nick": data.get("nick", ""),
            "features": data.get("features", []),
            "id": data.get("id", 0),
        }

        target_data = {"nick": data.get("target", ""), "features": [], "id": 0}

        transformed_data = {
            "user": user_data,
            "target": target_data,
            "data": {
                "reason": data.get("reason", ""),
                "duration": data.get("duration"),
            },
            "timestamp": data.get("timestamp"),
        }

        return self._parse_ban(transformed_data)

    def _parse_unban_prefix_message(self, data: dict[str, Any]) -> Ban:
        """Parse UNBAN prefix message format."""
        return self._parse_ban_prefix_message(data)

    def _parse_mute_prefix_message(self, data: dict[str, Any]) -> Mute:
        """Parse MUTE prefix message format."""
        # Transform prefix format to standard format
        user_data = {
            "nick": data.get("nick", ""),
            "features": data.get("features", []),
            "id": data.get("id", 0),
        }

        target_data = {"nick": data.get("target", ""), "features": [], "id": 0}

        transformed_data = {
            "user": user_data,
            "target": target_data,
            "data": {"duration": data.get("duration")},
            "timestamp": data.get("timestamp"),
        }

        return self._parse_mute(transformed_data)

    def _parse_unmute_prefix_message(self, data: dict[str, Any]) -> Mute:
        """Parse UNMUTE prefix message format."""
        return self._parse_mute_prefix_message(data)

    def _parse_broadcast_prefix_message(self, data: dict[str, Any]) -> Broadcast:
        """Parse BROADCAST prefix message format."""
        # Transform prefix format to standard format
        user_data = {
            "nick": data.get("nick", ""),
            "features": data.get("features", []),
            "id": data.get("id", 0),
        }

        transformed_data = {
            "user": user_data,
            "data": data.get("data", ""),
            "timestamp": data.get("timestamp"),
        }

        return self._parse_broadcast(transformed_data)

    def _parse_pong_prefix_message(self, data: dict[str, Any]) -> Ping:
        """Parse PONG prefix message format."""
        transformed_data = {"timestamp": data.get("timestamp")}

        return self._parse_pong(transformed_data)
