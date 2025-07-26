#!/usr/bin/env python3
"""
wsggpy - Python websocket chat library for strims.gg chat

This file serves as a demo of the library capabilities.
For real usage, see the examples/ directory.
"""

import asyncio
import logging
import sys

import wsggpy

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


def sync_demo(login_key: str | None = None) -> None:
    """Demonstrate synchronous API usage."""
    print("\n=== Synchronous Demo ===")

    def on_message(message: wsggpy.Message, session: wsggpy.Session) -> None:
        print(f"📝 [{message.sender.nick}]: {message.message}")

        # Demo auto-responses
        if message.message.lower() == "hello":
            session.send_message("Hello back! 👋")
        elif message.message == "!info":
            users_count = len(session.get_users())
            session.send_message(
                f"wsggpy v{wsggpy.__version__} - {users_count} users online"
            )

    def on_join(join: wsggpy.RoomAction, session: wsggpy.Session) -> None:
        print(f"👋 {join.user.nick} joined the chat")

    def on_error(error: str, session: wsggpy.Session) -> None:
        print(f"❌ Error: {error}")

    # Create session
    session = wsggpy.Session(
        login_key=login_key,
        url=wsggpy.ChatEnvironment.DEV,
    )
    session.add_message_handler(on_message)
    session.add_join_handler(on_join)
    session.add_error_handler(on_error)

    try:
        print("🔗 Connecting to chat...")
        session.open()
        print("✅ Connected! Sending demo message...")

        session.send_message("wsggpy sync demo started! Type 'hello' or '!info'")

        # Run for a short time
        import time

        for i in range(10):
            if not session.is_connected():
                break
            time.sleep(1)
            if i == 5:
                session.send_message("Demo ending in 5 seconds...")

    except Exception as e:
        print(f"❌ Demo failed: {e}")
    finally:
        session.close()
        print("🔌 Disconnected")


async def async_demo(login_key: str | None = None) -> None:
    """Demonstrate asynchronous API usage."""
    print("\n=== Asynchronous Demo ===")

    async def on_message(message: wsggpy.Message, session: wsggpy.AsyncSession) -> None:
        print(f"📝 [{message.sender.nick}]: {message.message}")

        # Demo async responses with delays
        if message.message.lower() == "ping":
            await asyncio.sleep(0.5)  # Async delay
            await session.send_message("pong! 🏓")
        elif message.message == "!async":
            await session.send_message("This is async wsggpy! ⚡")

    def on_error(error: str, session: wsggpy.AsyncSession) -> None:
        print(f"❌ Async Error: {error}")

    # Create async session
    session = wsggpy.AsyncSession(
        login_key=login_key,
        url=wsggpy.ChatEnvironment.DEV,
    )
    session.add_message_handler(on_message)
    session.add_error_handler(on_error)

    try:
        print("🔗 Connecting to chat (async)...")
        async with session:  # Context manager auto-handles connection
            print("✅ Connected! Sending demo message...")

            await session.send_message(
                "wsggpy async demo started! Type 'ping' or '!async'"
            )

            # Demo periodic pings
            for i in range(10):
                if not session.is_connected():
                    break
                await asyncio.sleep(1)
                if i == 3:
                    await session.send_ping()
                    print("📡 Sent ping")
                elif i == 7:
                    await session.send_message("Demo ending soon...")

        print("🔌 Disconnected (auto-closed by context manager)")

    except Exception as e:
        print(f"❌ Async demo failed: {e}")


def show_library_info() -> None:
    """Show library information and capabilities."""
    print(
        f"""
🚀 wsggpy v{wsggpy.__version__}
   Python websocket chat library for strims.gg

📦 Available Models:
   • User, Message, PrivateMessage
   • Ban, Mute, RoomAction, Broadcast
   • Ping, Names

🎯 Features:
   • Sync & Async APIs
   • Type-safe with Pydantic
   • Event-driven architecture
   • Full moderation support
   • Comprehensive error handling

📖 Examples available in examples/ directory
🧪 Run tests with: pytest
"""
    )


def main() -> None:
    """Main demo function."""
    login_key = None
    if len(sys.argv) > 1:
        login_key = sys.argv[1]

    show_library_info()

    # Show available user features
    print("👤 User Features:")
    for feature in wsggpy.UserFeature:
        print(f"   • {feature.value}")

    if login_key:
        print("\n🔑 Using provided login key")

        # Run both demos
        try:
            sync_demo(login_key)
            asyncio.run(async_demo(login_key))
        except KeyboardInterrupt:
            print("\n⏹️  Demos interrupted by user")
    else:
        print(
            """
ℹ️  To run interactive demos, provide a login key:
   python main.py YOUR_LOGIN_KEY

   You can get a login key from strims.gg chat settings.

🔧 For development:
   pip install -e .[dev]
   pytest                    # Run tests
   python examples/simple_sync.py KEY    # Sync example
   python examples/simple_async.py KEY   # Async example
"""
        )


if __name__ == "__main__":
    main()
