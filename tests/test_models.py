"""
Tests for wsggpy data models.
"""

from datetime import datetime

import pytest
from wsggpy.models import (
    Ban,
    Message,
    Names,
    PrivateMessage,
    User,
    UserFeature,
)


class TestUser:
    """Test User model."""

    def test_user_creation(self):
        """Test basic user creation."""
        user = User(
            id=123, nick="testuser", features=[UserFeature.MODERATOR, UserFeature.BOT]
        )

        assert user.id == 123
        assert user.nick == "testuser"
        assert UserFeature.MODERATOR in user.features
        assert UserFeature.BOT in user.features

    def test_user_has_feature(self):
        """Test has_feature method."""
        user = User(id=123, nick="testuser", features=[UserFeature.MODERATOR])

        assert user.has_feature(UserFeature.MODERATOR)
        assert not user.has_feature(UserFeature.ADMIN)
        assert not user.has_feature(UserFeature.BOT)

    def test_user_immutable(self):
        """Test that user is immutable."""
        user = User(id=123, nick="testuser")

        with pytest.raises(
            ValueError
        ):  # Should raise validation error for frozen model
            user.nick = "newname"


class TestMessage:
    """Test Message model."""

    def test_message_creation(self):
        """Test basic message creation."""
        user = User(id=123, nick="testuser")
        message = Message(sender=user, message="Hello, world!")

        assert message.sender == user
        assert message.message == "Hello, world!"
        assert isinstance(message.timestamp, datetime)

    def test_is_action(self):
        """Test is_action method."""
        user = User(id=123, nick="testuser")

        # Regular message
        regular_msg = Message(sender=user, message="Hello!")
        assert not regular_msg.is_action()

        # Action message
        action_msg = Message(sender=user, message="/me waves")
        assert action_msg.is_action()


class TestPrivateMessage:
    """Test PrivateMessage model."""

    def test_private_message_creation(self):
        """Test basic private message creation."""
        sender = User(id=123, nick="sender")
        recipient = User(id=456, nick="recipient")

        pm = PrivateMessage(
            sender=sender, recipient=recipient, message="Secret message"
        )

        assert pm.sender == sender
        assert pm.recipient == recipient
        assert pm.message == "Secret message"
        assert isinstance(pm.timestamp, datetime)


class TestBan:
    """Test Ban model."""

    def test_ban_creation(self):
        """Test basic ban creation."""
        moderator = User(id=123, nick="mod", features=[UserFeature.MODERATOR])
        target = User(id=456, nick="baduser")

        ban = Ban(
            sender=moderator,
            target=target,
            reason="Spam",
            duration=3600,  # 1 hour
        )

        assert ban.sender == moderator
        assert ban.target == target
        assert ban.reason == "Spam"
        assert ban.duration == 3600
        assert isinstance(ban.timestamp, datetime)

    def test_permanent_ban(self):
        """Test permanent ban (no duration)."""
        moderator = User(id=123, nick="mod", features=[UserFeature.MODERATOR])
        target = User(id=456, nick="baduser")

        ban = Ban(sender=moderator, target=target, reason="Serious violation")

        assert ban.duration is None  # Permanent ban


class TestNames:
    """Test Names model."""

    def test_names_creation(self):
        """Test user list creation."""
        users = [
            User(id=1, nick="user1"),
            User(id=2, nick="user2"),
            User(id=3, nick="user3"),
        ]

        names = Names(users=users, connectioncount=3)

        assert len(names.users) == 3
        assert names.users[0].nick == "user1"
        assert names.users[1].nick == "user2"
        assert names.users[2].nick == "user3"
        assert isinstance(names.timestamp, datetime)
