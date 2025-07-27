"""Data models for wsggpy.

Defines Pydantic models for chat events and user data structures.
All models are immutable and provide type-safe representations of
chat protocol messages.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class UserFeature(Enum):
    """User feature flags."""

    ADMIN = "admin"
    MODERATOR = "moderator"
    BOT = "bot"
    PROTECTED = "protected"


class User(BaseModel):
    """A chat user."""

    id: int = Field(description="Unique user ID")
    nick: str = Field(description="User's display name")
    features: list[UserFeature] = Field(
        default_factory=list, description="User features/permissions"
    )

    def has_feature(self, feature: UserFeature) -> bool:
        """Check if user has a specific feature."""
        return feature in self.features

    def is_admin(self) -> bool:
        """Check if user is an admin."""
        return self.has_feature(UserFeature.ADMIN)

    def is_moderator(self) -> bool:
        """Check if user is a moderator."""
        return self.has_feature(UserFeature.MODERATOR)

    def is_bot(self) -> bool:
        """Check if user is a bot."""
        return self.has_feature(UserFeature.BOT)

    def is_protected(self) -> bool:
        """Check if user is protected."""
        return self.has_feature(UserFeature.PROTECTED)


class Message(BaseModel):
    """A chat message."""

    sender: User = Field(description="User who sent the message")
    message: str = Field(description="Message content")
    timestamp: datetime = Field(description="When the message was sent")

    def is_action(self) -> bool:
        """Check if this is an action message (/me command)."""
        return self.message.startswith("/me ")

    def get_action_text(self) -> str | None:
        """Get action text if this is an action message."""
        if self.is_action():
            return self.message[4:]  # Remove "/me " prefix
        return None


class PrivateMessage(BaseModel):
    """A private message between users."""

    sender: User = Field(description="User who sent the message")
    recipient: User = Field(description="User who received the message")
    message: str = Field(description="Message content")
    timestamp: datetime = Field(description="When the message was sent")


class Ban(BaseModel):
    """A ban event."""

    sender: User = Field(description="User who issued the ban")
    target: User = Field(description="User who was banned")
    reason: str = Field(description="Reason for the ban")
    duration: int | None = Field(
        description="Ban duration in seconds, None for permanent"
    )
    timestamp: datetime = Field(description="When the ban was issued")

    def is_permanent(self) -> bool:
        """Check if this is a permanent ban."""
        return self.duration is None


class Mute(BaseModel):
    """A mute event."""

    sender: User = Field(description="User who issued the mute")
    target: User = Field(description="User who was muted")
    duration: int | None = Field(
        description="Mute duration in seconds, None for permanent"
    )
    timestamp: datetime = Field(description="When the mute was issued")

    def is_permanent(self) -> bool:
        """Check if this is a permanent mute."""
        return self.duration is None


class RoomAction(BaseModel):
    """A user join/quit event."""

    user: User = Field(description="User who joined or left")
    timestamp: datetime = Field(description="When the action occurred")


class Broadcast(BaseModel):
    """A broadcast message from the server."""

    sender: User = Field(description="User who sent the broadcast")
    message: str = Field(description="Broadcast content")
    timestamp: datetime = Field(description="When the broadcast was sent")


class Ping(BaseModel):
    """A ping/pong event."""

    timestamp: datetime = Field(description="When the ping was sent/received")


class Names(BaseModel):
    """User list update event."""

    users: list[User] = Field(description="List of users in the chat")
    connectioncount: int = Field(description="Total connection count")
    timestamp: datetime = Field(description="When the user list was updated")


class DisconnectEvent(BaseModel):
    """A disconnection event."""

    reason: str = Field(description="Reason for disconnection")
    timestamp: datetime = Field(description="When the disconnection occurred")


class ReconnectingEvent(BaseModel):
    """A reconnection attempt event."""

    attempt: int = Field(description="Current attempt number")
    delay: float = Field(description="Delay before this attempt in seconds")
    timestamp: datetime = Field(description="When the reconnection attempt started")


class ReconnectedEvent(BaseModel):
    """A successful reconnection event."""

    attempts_taken: int = Field(description="Number of attempts it took to reconnect")
    timestamp: datetime = Field(description="When reconnection succeeded")


class ReconnectFailedEvent(BaseModel):
    """A failed reconnection event (all attempts exhausted)."""

    total_attempts: int = Field(description="Total number of attempts made")
    timestamp: datetime = Field(description="When reconnection finally failed")


# Type alias for all event types
EventType = (
    Message
    | PrivateMessage
    | Ban
    | Mute
    | RoomAction
    | Broadcast
    | Ping
    | Names
    | DisconnectEvent
    | ReconnectingEvent
    | ReconnectedEvent
    | ReconnectFailedEvent
)
