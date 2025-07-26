# wsggpy

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Python WebSocket client library for [strims.gg](https://strims.gg) chat with synchronous and asynchronous support.

## Features

- Synchronous and asynchronous APIs
- Type-safe Pydantic models
- Event-driven message handling
- Built-in authentication
- Comprehensive error handling

## Installation

```bash
pip install wsggpy
```

Development installation:

```bash
git clone https://github.com/user/wsggpy.git
cd wsggpy
pip install -e .[dev]
```

## Usage

### Synchronous

```python
from wsggpy import Session, ChatEnvironment

session = Session(
    login_key="your_jwt_token",
    url=ChatEnvironment.PRODUCTION
)

@session.add_message_handler
def on_message(message, session):
    print(f"{message.sender.nick}: {message.message}")

session.open()
session.send_message("Hello, chat!")
session.close()
```

### Asynchronous

```python
import asyncio
from wsggpy import AsyncSession, ChatEnvironment

async def main():
    session = AsyncSession(
        login_key="your_jwt_token",
        url=ChatEnvironment.PRODUCTION
    )

    @session.add_message_handler
    def on_message(message, session):
        print(f"{message.sender.nick}: {message.message}")

    await session.open()
    await session.send_message("Hello from async!")
    await session.close()

asyncio.run(main())
```

## API Reference

### Session Classes

```python
# Synchronous
session = wsggpy.Session(
    login_key="token",           # Optional JWT token
    url="wss://chat.strims.gg/ws", # WebSocket URL
    user_agent="wsggpy/0.1.0"    # User agent
)

# Asynchronous
session = wsggpy.AsyncSession(
    login_key="token",
    url="wss://chat.strims.gg/ws",
    user_agent="wsggpy/0.1.0"
)
```

### Connection Management

```python
# Synchronous
session.open()
session.close()
session.is_connected()

# Asynchronous
await session.open()
await session.close()
session.is_connected()

# Context manager (async only)
async with session:
    await session.send_message("Hello!")
```

### Message Operations

```python
# Basic messaging
session.send_message("Hello!")
session.send_action("waves")  # /me waves
session.send_private_message("username", "Private message")

# Moderation (requires permissions)
session.send_ban("username", "reason", duration=3600)
session.send_permanent_ban("username", "reason")
session.send_unban("username")
session.send_mute("username", duration=1800)
session.send_unmute("username")

# Utilities
session.send_ping()
```

### Event Handlers

```python
session.add_message_handler(callback)
session.add_private_message_handler(callback)
session.add_ban_handler(callback)
session.add_unban_handler(callback)
session.add_mute_handler(callback)
session.add_unmute_handler(callback)
session.add_join_handler(callback)
session.add_quit_handler(callback)
session.add_broadcast_handler(callback)
session.add_ping_handler(callback)
session.add_names_handler(callback)
session.add_error_handler(callback)
session.add_socket_error_handler(callback)
session.add_generic_handler(callback)  # All events
```

### User Management

```python
users = session.get_users()  # List[User]
user = session.get_user("username")  # Optional[User]

# Check user features
if user and user.has_feature(wsggpy.UserFeature.MODERATOR):
    print("User is a moderator")
```

## Data Models

All models are immutable Pydantic models:

- `User` - Chat user with features and metadata
- `Message` - Chat message with sender and timestamp
- `PrivateMessage` - Direct message between users
- `Ban/Mute` - Moderation events with duration
- `RoomAction` - User join/quit events
- `Broadcast` - System broadcast messages
- `Ping` - Heartbeat events
- `Names` - User list updates

### User Features

```python
wsggpy.UserFeature.ADMIN
wsggpy.UserFeature.MODERATOR
wsggpy.UserFeature.BOT
wsggpy.UserFeature.PROTECTED
```

## Environments

```python
from wsggpy import ChatEnvironment

# Production chat
ChatEnvironment.PRODUCTION  # "wss://chat.strims.gg/ws"

# Development chat
ChatEnvironment.DEV         # "wss://chat2.strims.gg/ws"
```

## Error Handling

```python
from wsggpy.exceptions import (
    WSGGError,           # Base exception
    ConnectionError,     # Connection failures
    AuthenticationError, # Auth failures
    MessageError,        # Message send failures
    ProtocolError,       # Protocol parsing errors
    RateLimitError,      # Rate limiting
    PermissionError      # Insufficient permissions
)

try:
    session.open()
    session.send_message("Hello!")
except wsggpy.ConnectionError as e:
    print(f"Connection failed: {e}")
except wsggpy.MessageError as e:
    print(f"Message failed: {e}")
```

## Development

### Setup

```bash
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -e .[dev]
```

### Code Quality

```bash
# Lint and format
ruff check --fix src/ tests/ examples/
ruff format src/ tests/ examples/

# Type checking
mypy src/

# Tests
pytest --cov=src/wsggpy --cov-report=html
```

### Project Structure

```
wsggpy/
├── src/wsggpy/           # Main package
│   ├── __init__.py       # Public API exports
│   ├── models.py         # Pydantic data models
│   ├── session.py        # Synchronous session
│   ├── async_session.py  # Asynchronous session
│   ├── protocol.py       # WebSocket protocol handling
│   ├── handlers.py       # Event handler management
│   └── exceptions.py     # Exception hierarchy
├── tests/                # Test suite
├── examples/             # Usage examples
└── pyproject.toml        # Project configuration
```

## License

MIT License - see [LICENSE](LICENSE) file for details.
