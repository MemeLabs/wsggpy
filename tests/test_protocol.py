"""
Tests for wsggpy protocol handling.
"""

import json
from datetime import datetime

import pytest
from wsggpy.exceptions import ProtocolError
from wsggpy.models import Ban, Message, PrivateMessage, UserFeature
from wsggpy.protocol import ProtocolHandler


class TestProtocolHandler:
    """Test ProtocolHandler class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.handler = ProtocolHandler()

    def test_format_message(self):
        """Test message formatting."""
        formatted = self.handler.format_message("Hello, world!")

        assert formatted.startswith("MSG ")
        json_part = formatted[4:]  # Remove "MSG " prefix
        data = json.loads(json_part)
        assert data["data"] == "Hello, world!"

    def test_format_private_message(self):
        """Test private message formatting."""
        formatted = self.handler.format_private_message("testuser", "Secret message")

        assert formatted.startswith("PRIVMSG ")
        json_part = formatted[8:]  # Remove "PRIVMSG " prefix
        data = json.loads(json_part)
        assert data["data"]["nick"] == "testuser"
        assert data["data"]["message"] == "Secret message"

    def test_format_ban(self):
        """Test ban command formatting."""
        formatted = self.handler.format_ban("baduser", "Spam", 3600)
        data = json.loads(formatted)

        assert data["type"] == "BAN"
        assert data["data"]["nick"] == "baduser"
        assert data["data"]["reason"] == "Spam"
        assert data["data"]["duration"] == 3600

    def test_format_ban_no_duration(self):
        """Test permanent ban formatting."""
        formatted = self.handler.format_ban("baduser", "Serious violation")
        data = json.loads(formatted)

        assert data["type"] == "BAN"
        assert data["data"]["nick"] == "baduser"
        assert data["data"]["reason"] == "Serious violation"
        assert "duration" not in data["data"]

    def test_format_mute(self):
        """Test mute command formatting."""
        formatted = self.handler.format_mute("chattyuser", 1800)
        data = json.loads(formatted)

        assert data["type"] == "MUTE"
        assert data["data"]["nick"] == "chattyuser"
        assert data["data"]["duration"] == 1800

    def test_format_ping(self):
        """Test ping formatting."""
        formatted = self.handler.format_ping()
        data = json.loads(formatted)

        assert data["type"] == "PING"
        assert isinstance(data["data"], int)
        assert data["data"] > 0

    def test_parse_message(self):
        """Test message parsing."""
        raw_msg = json.dumps(
            {
                "type": "MSG",
                "user": {"id": 123, "nick": "testuser", "features": ["moderator"]},
                "data": "Hello, chat!",
                "timestamp": 1609459200000,  # 2021-01-01 00:00:00 UTC
            }
        )

        event = self.handler.parse_message(raw_msg)

        assert isinstance(event, Message)
        assert event.sender.id == 123
        assert event.sender.nick == "testuser"
        assert UserFeature.MODERATOR in event.sender.features
        assert event.message == "Hello, chat!"
        assert isinstance(event.timestamp, datetime)

    def test_parse_ban(self):
        """Test ban event parsing."""
        raw_msg = json.dumps(
            {
                "type": "BAN",
                "user": {"id": 1, "nick": "moderator", "features": ["moderator"]},
                "target": {"id": 123, "nick": "baduser", "features": []},
                "data": {"reason": "Spam", "duration": 3600},
                "timestamp": 1609459200000,
            }
        )

        event = self.handler.parse_message(raw_msg)

        assert isinstance(event, Ban)
        assert event.sender.nick == "moderator"
        assert event.target.nick == "baduser"
        assert event.reason == "Spam"
        assert event.duration == 3600

    def test_parse_unknown_message_type(self):
        """Test parsing unknown message type."""
        raw_msg = json.dumps({"type": "UNKNOWN_TYPE", "data": "test"})

        event = self.handler.parse_message(raw_msg)
        assert event is None

    def test_parse_invalid_json(self):
        """Test parsing invalid JSON."""
        with pytest.raises(ProtocolError):
            self.handler.parse_message("invalid json {")

    def test_parse_empty_message(self):
        """Test parsing empty message."""
        event = self.handler.parse_message("")
        assert event is None

        event = self.handler.parse_message("   ")
        assert event is None

    def test_parse_missing_type(self):
        """Test parsing message without type field."""
        raw_msg = json.dumps({"data": "test"})

        event = self.handler.parse_message(raw_msg)
        assert event is None

    def test_parse_user_unknown_features(self):
        """Test parsing user with unknown features."""
        raw_msg = json.dumps(
            {
                "type": "MSG",
                "user": {
                    "id": 123,
                    "nick": "testuser",
                    "features": ["moderator", "unknown_feature", "bot"],
                },
                "data": "Hello!",
                "timestamp": 1609459200000,
            }
        )

        event = self.handler.parse_message(raw_msg)

        assert isinstance(event, Message)
        assert UserFeature.MODERATOR in event.sender.features
        assert UserFeature.BOT in event.sender.features
        # Unknown features should be filtered out
        assert (
            len([f for f in event.sender.features if f.value == "unknown_feature"]) == 0
        )

    def test_parse_timestamp_formats(self):
        """Test parsing different timestamp formats."""
        # Millisecond timestamp
        raw_msg1 = json.dumps(
            {
                "type": "MSG",
                "user": {"id": 123, "nick": "test"},
                "data": "test",
                "timestamp": 1609459200000,
            }
        )
        event1 = self.handler.parse_message(raw_msg1)
        assert isinstance(event1.timestamp, datetime)

        # ISO format
        raw_msg2 = json.dumps(
            {
                "type": "MSG",
                "user": {"id": 123, "nick": "test"},
                "data": "test",
                "timestamp": "2021-01-01T00:00:00Z",
            }
        )
        event2 = self.handler.parse_message(raw_msg2)
        assert isinstance(event2.timestamp, datetime)

        # No timestamp
        raw_msg3 = json.dumps(
            {"type": "MSG", "user": {"id": 123, "nick": "test"}, "data": "test"}
        )
        event3 = self.handler.parse_message(raw_msg3)
        assert isinstance(event3.timestamp, datetime)

    def test_parse_msg_prefix_format(self):
        """Test parsing MSG prefix format messages."""
        # Test the exact format that was failing in the demo
        raw_message = 'MSG {"nick":"whenis","features":["bot"],"timestamp":1753533173822,"data":"1 Hours and 27 Minutes until F1: Qualifying (Belgian Grand Prix)","entities":{}}'

        event = self.handler.parse_message(raw_message)

        assert isinstance(event, Message)
        assert event.sender.nick == "whenis"
        assert UserFeature.BOT in event.sender.features
        assert (
            event.message
            == "1 Hours and 27 Minutes until F1: Qualifying (Belgian Grand Prix)"
        )
        assert isinstance(event.timestamp, datetime)

    def test_parse_msg_prefix_with_id(self):
        """Test parsing MSG prefix format with user ID."""
        raw_message = 'MSG {"nick":"testuser","id":12345,"features":["moderator"],"timestamp":1609459200000,"data":"Hello world!","entities":{}}'

        event = self.handler.parse_message(raw_message)

        assert isinstance(event, Message)
        assert event.sender.nick == "testuser"
        assert event.sender.id == 12345
        assert UserFeature.MODERATOR in event.sender.features
        assert event.message == "Hello world!"
        assert isinstance(event.timestamp, datetime)

    def test_parse_msg_prefix_invalid_json(self):
        """Test handling of invalid JSON in MSG prefix format."""
        raw_message = 'MSG {"invalid":"json"'

        with pytest.raises(ProtocolError) as exc_info:
            self.handler.parse_message(raw_message)

        assert "Invalid JSON in MSG message" in str(exc_info.value)

    def test_parse_privmsg_prefix_format(self):
        """Test parsing PRIVMSG prefix format messages."""
        raw_message = 'PRIVMSG {"data": {"nick": "targetuser", "message": "Hello there!"}, "nick": "sender", "features": ["moderator"], "timestamp": 1609459200000}'

        event = self.handler.parse_message(raw_message)

        assert isinstance(event, PrivateMessage)
        assert event.sender.nick == "sender"
        assert UserFeature.MODERATOR in event.sender.features
        assert event.recipient.nick == "targetuser"
        assert event.message == "Hello there!"
        assert isinstance(event.timestamp, datetime)

    def test_parse_privmsg_prefix_invalid_json(self):
        """Test handling of invalid JSON in PRIVMSG prefix format."""
        raw_message = 'PRIVMSG {"invalid":"json"'

        with pytest.raises(ProtocolError) as exc_info:
            self.handler.parse_message(raw_message)

        assert "Invalid JSON in PRIVMSG message" in str(exc_info.value)
