#!/usr/bin/env python3
"""
Simple asynchronous wsggpy example.

This example demonstrates basic usage of the asynchronous AsyncSession class
for connecting to strims.gg chat and sending messages.
"""

import asyncio

from wsggpy import AsyncSession, ChatEnvironment


async def main():
    """Main async function demonstrating asynchronous chat usage."""

    # Create an async session for production chat
    # For dev chat, use: url=ChatEnvironment.DEV
    session = AsyncSession(
        login_key="your_jwt_token_here",  # Replace with your actual JWT token
        url=ChatEnvironment.PRODUCTION,  # or ChatEnvironment.DEV for dev chat
        user_agent="wsggpy-async-example/1.0",
    )

    # Set up event handlers
    @session.add_message_handler
    def on_message(message, session):
        print(f"{message.sender.nick}: {message.message}")

    @session.add_error_handler
    def on_error(error, session):
        print(f"Error: {error}")

    try:
        print(f"Connecting to {session.url}...")
        await session.open()
        print("Connected!")

        # Send a test message
        await session.send_message("Hello from wsggpy async!")

        # Keep the connection alive for a bit
        await asyncio.sleep(10)

        # Send another message
        await session.send_message("Goodbye from wsggpy!")

    except KeyboardInterrupt:
        print("\nGracefully shutting down...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await session.close()
        print("Disconnected.")


if __name__ == "__main__":
    asyncio.run(main())
