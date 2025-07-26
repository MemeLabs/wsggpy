"""Data models for wsggpy chat events and objects.

These models represent all the different types of events and objects
that can be received from or sent to the strims.gg chat API.
"""

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field


class UserFeature(str, Enum):
    """User feature flags."""

    ADMIN = "admin"
    MODERATOR = "moderator"
    BOT = "bot"
    PROTECTED = "protected"


class User(BaseModel):
    """Represents a chat user."""

    model_config = ConfigDict(frozen=True)

    id: int = Field(..., description="Unique user ID")
    nick: str = Field(..., description="Username/nickname")
    features: list[UserFeature] = Field(
        default_factory=list, description="User feature flags"
    )

    def has_feature(self, feature: UserFeature) -> bool:
        """Check if user has a specific feature."""
        return feature in self.features


class Message(BaseModel):
    """Represents a chat message."""

    model_config = ConfigDict(frozen=True)

    sender: User = Field(..., description="Message sender")
    message: str = Field(..., description="Message content")
    timestamp: datetime = Field(
        default_factory=datetime.now, description="Message timestamp"
    )

    def is_action(self) -> bool:
        """Check if message is an action (/me command)."""
        return self.message.startswith("/me ")


class PrivateMessage(BaseModel):
    """Represents a private message."""

    model_config = ConfigDict(frozen=True)

    sender: User = Field(..., description="Message sender")
    recipient: User = Field(..., description="Message recipient")
    message: str = Field(..., description="Message content")
    timestamp: datetime = Field(
        default_factory=datetime.now, description="Message timestamp"
    )


class Ban(BaseModel):
    """Represents a ban event."""

    model_config = ConfigDict(frozen=True)

    sender: User = Field(..., description="Moderator who issued the ban")
    target: User = Field(..., description="User being banned")
    reason: str = Field(..., description="Ban reason")
    timestamp: datetime = Field(
        default_factory=datetime.now, description="Ban timestamp"
    )
    duration: int | None = Field(
        None, description="Ban duration in seconds (None for permanent)"
    )


class Mute(BaseModel):
    """Represents a mute event."""

    model_config = ConfigDict(frozen=True)

    sender: User = Field(..., description="Moderator who issued the mute")
    target: User = Field(..., description="User being muted")
    timestamp: datetime = Field(
        default_factory=datetime.now, description="Mute timestamp"
    )
    duration: int | None = Field(None, description="Mute duration in seconds")


class RoomAction(BaseModel):
    """Represents a user joining/leaving the chat."""

    model_config = ConfigDict(frozen=True)

    user: User = Field(..., description="User performing the action")
    timestamp: datetime = Field(
        default_factory=datetime.now, description="Action timestamp"
    )


class Broadcast(BaseModel):
    """Represents a broadcast message."""

    model_config = ConfigDict(frozen=True)

    sender: User = Field(..., description="Broadcast sender")
    message: str = Field(..., description="Broadcast content")
    timestamp: datetime = Field(
        default_factory=datetime.now, description="Broadcast timestamp"
    )


class Ping(BaseModel):
    """Represents a ping/pong event."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime = Field(
        default_factory=datetime.now, description="Ping timestamp"
    )


class Names(BaseModel):
    """Represents a user list update."""

    model_config = ConfigDict(frozen=True)

    users: list[User] = Field(..., description="List of users in chat")
    connectioncount: int = Field(..., description="Total number of connected users")
    timestamp: datetime = Field(
        default_factory=datetime.now, description="Update timestamp"
    )


# Union type for all possible events
if TYPE_CHECKING:
    EventType = (
        Message | PrivateMessage | Ban | Mute | RoomAction | Broadcast | Ping | Names
    )
else:
    EventType = (
        Message | PrivateMessage | Ban | Mute | RoomAction | Broadcast | Ping | Names
    )
