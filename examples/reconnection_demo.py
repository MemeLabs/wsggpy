#!/usr/bin/env python3
"""Demonstration of reconnection features in wsggpy.

This script shows how to use the new connection event handlers and
reconnection configuration to handle network issues gracefully.
"""

import asyncio
import logging

from wsggpy import AsyncSession

# Set up logging to see reconnection events
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


async def main():
    """Demonstrate reconnection features."""
    # Create session with reconnection enabled
    session = AsyncSession(
        # url=ChatEnvironment.DEV,  # Use dev chat for testing
        url="wss://echo.websocket.org",  # Use echo server for demo
        user_agent="wsggpy-reconnection-demo/1.0",
    )

    # Configure reconnection behavior
    session.set_reconnect_config(attempts=3, delay=2.0)  # 3 attempts, 2s base delay
    session.set_auto_reconnect(True)

    # Set up connection event handlers
    @session.add_disconnect_handler
    def on_disconnect(event, session_ref):
        logger.warning(f"🔌 DISCONNECTED: {event.reason}")

    @session.add_reconnecting_handler
    def on_reconnecting(event, session_ref):
        logger.info(f"🔄 RECONNECTING: Attempt {event.attempt} in {event.delay:.1f}s")

    @session.add_reconnected_handler
    def on_reconnected(event, session_ref):
        logger.info(f"✅ RECONNECTED: Took {event.attempts_taken} attempts")

    @session.add_reconnect_failed_handler
    def on_reconnect_failed(event, session_ref):
        logger.error(f"❌ RECONNECTION FAILED: After {event.total_attempts} attempts")

    # Connect and show connection info
    logger.info("📡 Connecting to server...")
    await session.open()

    logger.info(f"📊 Connection info: {session.get_connection_info()}")
    logger.info(f"🔗 Connected: {session.is_connected()}")
    logger.info(f"🔄 Reconnecting: {session.is_reconnecting()}")

    # Send a test message
    try:
        await session.send_message("Hello from wsggpy reconnection demo!")
        logger.info("📤 Test message sent")
    except Exception as e:
        logger.error(f"Failed to send test message: {e}")

    # Wait a bit to see any events
    logger.info("⏳ Waiting 10 seconds... (you can try disconnecting your network)")
    await asyncio.sleep(10)

    # Force a reconnection to demonstrate the feature
    logger.info("🔧 Forcing reconnection to demonstrate feature...")
    await session.force_reconnect()

    # Wait a bit more
    await asyncio.sleep(5)

    # Clean up
    logger.info("🛑 Closing connection...")
    await session.close()
    logger.info("✨ Demo complete!")


if __name__ == "__main__":
    print("🚀 wsggpy Reconnection Demo")
    print("This demo shows the new automatic reconnection features.")
    print("Watch the logs to see connection events in action!")
    print("-" * 50)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Demo interrupted by user")
    except Exception as e:
        print(f"❌ Demo failed: {e}")
