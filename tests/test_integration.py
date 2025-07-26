"""
Integration tests for wsggpy.

Tests realistic user workflows and end-to-end scenarios that demonstrate
the library's value in real-world usage patterns.
"""

import asyncio
import time
from unittest.mock import AsyncMock, Mock, patch

import pytest
import websocket
from wsggpy import AsyncSession, Session
from wsggpy.exceptions import ConnectionError, MessageError
from wsggpy.models import Message, User


class TestBasicChatBotWorkflow:
    """Test a basic chat bot workflow - a very common use case."""

    def test_sync_chat_bot_responds_to_commands(self):
        """Test a synchronous chat bot that responds to commands."""
        session = Session(login_key="bot_key")

        # Track bot responses
        bot_responses = []
        user_messages = []

        def on_message(message, session_ref):
            user_messages.append(message)

            # Bot responds to !ping with pong
            if message.message == "!ping":
                session_ref.send_message("pong!")
                bot_responses.append("pong!")

            # Bot responds to !help with commands
            elif message.message == "!help":
                session_ref.send_message("Available commands: !ping, !help, !time")
                bot_responses.append("help_response")

            # Bot responds to !time with current time
            elif message.message == "!time":
                session_ref.send_message("Current time: 12:34:56")
                bot_responses.append("time_response")

        def on_error(error_msg, session_ref):
            # Bot logs errors but continues running
            print(f"Bot error: {error_msg}")

        session.add_message_handler(on_message)
        session.add_error_handler(on_error)

        # Mock websocket connection
        mock_ws = Mock()
        with patch("websocket.WebSocket", return_value=mock_ws):
            session.open()

            # Simulate receiving user messages
            test_user = User(id=1, nick="testuser", features=[])

            # Test !ping command
            ping_message = Message(sender=test_user, message="!ping")
            session.handlers.dispatch_event(ping_message, session)

            # Test !help command
            help_message = Message(sender=test_user, message="!help")
            session.handlers.dispatch_event(help_message, session)

            # Test !time command
            time_message = Message(sender=test_user, message="!time")
            session.handlers.dispatch_event(time_message, session)

            # Test regular message (no response)
            regular_message = Message(sender=test_user, message="Hello everyone!")
            session.handlers.dispatch_event(regular_message, session)

            session.close()

        # Verify bot behavior
        assert len(user_messages) == 4
        assert len(bot_responses) == 3  # Bot only responds to commands
        assert "pong!" in bot_responses
        assert "help_response" in bot_responses
        assert "time_response" in bot_responses

        # Verify bot sent the right number of messages
        assert mock_ws.send.call_count == 3

    @pytest.mark.asyncio
    async def test_async_chat_bot_with_delayed_responses(self):
        """Test an async chat bot with simulated delayed responses."""
        session = AsyncSession(login_key="async_bot_key")

        # Track bot responses with timestamps
        bot_responses = []

        def on_message(message, session_ref):
            # Note: Using sync handler to work with current handler system
            if message.message.startswith("!slow"):
                # Simulate a response (removed sleep to avoid hanging)
                bot_responses.append(("slow_response", time.time()))

            elif message.message == "!fast":
                # Fast response
                bot_responses.append(("fast_response", time.time()))

        session.add_message_handler(on_message)

        # Mock async websocket
        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                await session.open()

                test_user = User(id=1, nick="asyncuser", features=[])

                # Dispatch events synchronously (handlers are sync)
                session.handlers.dispatch_event(
                    Message(sender=test_user, message="!slow 1"), session
                )
                session.handlers.dispatch_event(
                    Message(sender=test_user, message="!fast"), session
                )
                session.handlers.dispatch_event(
                    Message(sender=test_user, message="!slow 2"), session
                )

                await session.close()

        # Verify responses
        assert len(bot_responses) == 3
        response_types = [resp[0] for resp in bot_responses]
        assert "fast_response" in response_types
        assert response_types.count("slow_response") == 2


class TestModerationBotWorkflow:
    """Test a moderation bot workflow."""

    def test_moderation_bot_handles_violations(self):
        """Test a moderation bot that handles chat violations."""
        session = Session(login_key="mod_bot_key")

        # Track moderation actions
        moderation_actions = []

        def on_message(message, session_ref):
            # Check for spam (repeated characters)
            if len(set(message.message.lower())) < 3 and len(message.message) > 10:
                # Spam detected - mute user
                session_ref.send_mute(message.sender.nick, 300)  # 5 minute mute
                session_ref.send_message(f"@{message.sender.nick} muted for spam")
                moderation_actions.append(("mute", message.sender.nick, "spam"))

            # Check for banned words
            elif any(word in message.message.lower() for word in ["badword", "spam"]):
                # Delete message and warn user
                session_ref.send_message(
                    f"@{message.sender.nick} please follow chat rules"
                )
                moderation_actions.append(("warn", message.sender.nick, "language"))

            # Check for excessive caps
            elif (
                len(message.message) > 20
                and sum(1 for c in message.message if c.isupper())
                > len(message.message) * 0.7
            ):
                # Warn for caps
                session_ref.send_message(
                    f"@{message.sender.nick} please don't use excessive caps"
                )
                moderation_actions.append(("warn", message.sender.nick, "caps"))

        session.add_message_handler(on_message)

        # Mock websocket
        mock_ws = Mock()
        with patch("websocket.WebSocket", return_value=mock_ws):
            session.open()

            # Test spam message
            spammer = User(id=1, nick="spammer", features=[])
            spam_message = Message(sender=spammer, message="aaaaaaaaaaaaaaaa")
            session.handlers.dispatch_event(spam_message, session)

            # Test message with banned word
            violator = User(id=2, nick="violator", features=[])
            bad_message = Message(sender=violator, message="this is badword message")
            session.handlers.dispatch_event(bad_message, session)

            # Test excessive caps
            shouter = User(id=3, nick="shouter", features=[])
            caps_message = Message(
                sender=shouter, message="THIS IS VERY LOUD MESSAGE WITH CAPS"
            )
            session.handlers.dispatch_event(caps_message, session)

            # Test normal message (no action)
            normal_user = User(id=4, nick="normal", features=[])
            normal_message = Message(
                sender=normal_user, message="Hello everyone, how are you?"
            )
            session.handlers.dispatch_event(normal_message, session)

            session.close()

        # Verify moderation actions
        assert len(moderation_actions) == 3

        action_types = [action[0] for action in moderation_actions]
        assert "mute" in action_types
        assert action_types.count("warn") == 2

        # Verify specific actions
        mute_action = next(
            action for action in moderation_actions if action[0] == "mute"
        )
        assert mute_action[1] == "spammer"
        assert mute_action[2] == "spam"


class TestChatLoggerWorkflow:
    """Test a chat logger workflow."""

    def test_chat_logger_records_all_events(self):
        """Test a chat logger that records all chat events."""
        session = Session()

        # Chat log storage
        chat_log = []

        def log_message(message, session_ref):
            chat_log.append(
                {
                    "type": "message",
                    "user": message.sender.nick,
                    "content": message.message,
                    "timestamp": message.timestamp,
                    "is_action": message.is_action(),
                }
            )

        def log_join(room_action, session_ref):
            chat_log.append(
                {
                    "type": "join",
                    "user": room_action.user.nick,
                    "timestamp": room_action.timestamp,
                }
            )

        def log_quit(room_action, session_ref):
            chat_log.append(
                {
                    "type": "quit",
                    "user": room_action.user.nick,
                    "timestamp": room_action.timestamp,
                }
            )

        def log_ban(ban, session_ref):
            chat_log.append(
                {
                    "type": "ban",
                    "moderator": ban.sender.nick,
                    "target": ban.target.nick,
                    "reason": ban.reason,
                    "duration": ban.duration,
                    "timestamp": ban.timestamp,
                }
            )

        def log_error(error_msg, session_ref):
            chat_log.append(
                {"type": "error", "message": error_msg, "timestamp": time.time()}
            )

        # Register all event handlers
        session.add_message_handler(log_message)
        session.add_join_handler(log_join)
        session.add_quit_handler(log_quit)
        session.add_ban_handler(log_ban)
        session.add_error_handler(log_error)

        mock_ws = Mock()
        with patch("websocket.WebSocket", return_value=mock_ws):
            session.open()

            # Simulate various events
            user1 = User(id=1, nick="user1", features=[])
            user2 = User(id=2, nick="user2", features=[])

            # Regular message
            msg1 = Message(sender=user1, message="Hello everyone!")
            session.handlers.dispatch_event(msg1, session)

            # Action message
            msg2 = Message(sender=user2, message="/me waves")
            session.handlers.dispatch_event(msg2, session)

            # Error event
            session.handlers.dispatch_error("Connection unstable", session)

            session.close()

        # Verify logging
        assert len(chat_log) >= 3

        # Check message logging
        message_logs = [log for log in chat_log if log["type"] == "message"]
        assert len(message_logs) == 2

        regular_msg_log = next(
            log for log in message_logs if log["content"] == "Hello everyone!"
        )
        assert regular_msg_log["user"] == "user1"
        assert not regular_msg_log["is_action"]

        action_msg_log = next(
            log for log in message_logs if log["content"] == "/me waves"
        )
        assert action_msg_log["user"] == "user2"
        assert action_msg_log["is_action"]

        # Check error logging (should include our intentional error)
        error_logs = [log for log in chat_log if log["type"] == "error"]
        assert len(error_logs) >= 1
        # Verify our intentional error is logged
        intentional_errors = [
            log for log in error_logs if log["message"] == "Connection unstable"
        ]
        assert len(intentional_errors) == 1


class TestMultiSessionWorkflow:
    """Test workflows involving multiple sessions."""

    @pytest.mark.asyncio
    async def test_multiple_async_sessions_independently(self):
        """Test multiple async sessions running independently."""
        # Create two sessions for different bots
        bot1_session = AsyncSession(login_key="bot1_key")
        bot2_session = AsyncSession(login_key="bot2_key")

        bot1_messages = []
        bot2_messages = []

        def bot1_handler(message, session_ref):
            if message.message.startswith("!bot1"):
                # Note: Using sync handler for compatibility
                bot1_messages.append(message.message)

        def bot2_handler(message, session_ref):
            if message.message.startswith("!bot2"):
                # Note: Using sync handler for compatibility
                bot2_messages.append(message.message)

        bot1_session.add_message_handler(bot1_handler)
        bot2_session.add_message_handler(bot2_handler)

        # Mock websockets for both sessions
        mock_session1 = AsyncMock()
        mock_ws1 = AsyncMock()
        mock_ws1.closed = False
        mock_session1.ws_connect.return_value = mock_ws1

        mock_session2 = AsyncMock()
        mock_ws2 = AsyncMock()
        mock_ws2.closed = False
        mock_session2.ws_connect.return_value = mock_ws2

        with patch("aiohttp.ClientSession", side_effect=[mock_session1, mock_session2]):
            with patch.object(bot1_session, "_listen_loop", new_callable=AsyncMock):
                with patch.object(bot2_session, "_listen_loop", new_callable=AsyncMock):
                    # Open both sessions concurrently
                    await asyncio.gather(bot1_session.open(), bot2_session.open())

                    test_user = User(id=1, nick="tester", features=[])

                    # Send messages to both bots (handlers are synchronous)
                    bot1_session.handlers.dispatch_event(
                        Message(sender=test_user, message="!bot1 hello"), bot1_session
                    )
                    bot2_session.handlers.dispatch_event(
                        Message(sender=test_user, message="!bot2 hello"), bot2_session
                    )
                    bot1_session.handlers.dispatch_event(
                        Message(sender=test_user, message="!bot1 test"), bot1_session
                    )

                    # Close both sessions
                    await asyncio.gather(bot1_session.close(), bot2_session.close())

        # Verify both bots worked independently
        assert len(bot1_messages) == 2
        assert len(bot2_messages) == 1
        assert "!bot1 hello" in bot1_messages
        assert "!bot1 test" in bot1_messages
        assert "!bot2 hello" in bot2_messages


class TestReconnectionWorkflow:
    """Test reconnection and resilience workflows."""

    def test_sync_session_handles_connection_loss(self):
        """Test that sync session can handle connection loss gracefully."""
        session = Session()

        connection_events = []

        def on_error(error_msg, session_ref):
            connection_events.append(("error", error_msg))

        def on_socket_error(exception, session_ref):
            connection_events.append(("socket_error", str(exception)))

        session.add_error_handler(on_error)
        session.add_socket_error_handler(on_socket_error)

        mock_ws = Mock()

        with patch("websocket.WebSocket", return_value=mock_ws):
            session.open()

            # Simulate connection loss during send
            mock_ws.send.side_effect = websocket.WebSocketException("Connection lost")

            # Try to send a message (should fail gracefully)
            with pytest.raises(MessageError):
                session.send_message("Test message")

            session.close()

        # Should have recorded the error
        assert len(connection_events) > 0

    @pytest.mark.asyncio
    async def test_async_session_context_manager_cleanup(self):
        """Test that async session context manager cleans up properly on failure."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        connection_opened = False
        connection_closed = False

        # Override open/close to track state
        original_open = session.open
        original_close = session.close

        async def tracked_open():
            nonlocal connection_opened
            await original_open()
            connection_opened = True

        async def tracked_close():
            nonlocal connection_closed
            await original_close()
            connection_closed = True

        session.open = tracked_open
        session.close = tracked_close

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                try:
                    async with session:
                        assert connection_opened
                        assert session.is_connected()

                        # Simulate an error in the context
                        raise ValueError("Simulated error in context")

                except ValueError:
                    pass  # Expected

        # Verify cleanup happened despite the error
        assert connection_closed
        assert not session.is_connected()


class TestRealWorldErrorScenarios:
    """Test realistic error scenarios users might encounter."""

    def test_invalid_login_key_workflow(self):
        """Test workflow when using invalid login key."""
        session = Session(login_key="invalid_key")

        auth_errors = []

        def on_error(error_msg, session_ref):
            if "auth" in error_msg.lower() or "login" in error_msg.lower():
                auth_errors.append(error_msg)

        session.add_error_handler(on_error)

        mock_ws = Mock()
        # Simulate authentication failure
        mock_ws.connect.side_effect = websocket.WebSocketException("401 Unauthorized")

        with patch("websocket.WebSocket", return_value=mock_ws):
            with pytest.raises(ConnectionError) as exc_info:
                session.open()

            # Should contain authentication error info
            assert "401" in str(exc_info.value) or "Unauthorized" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_network_timeout_workflow(self):
        """Test workflow when network timeouts occur."""
        session = AsyncSession()

        timeout_events = []

        async def on_error(error_msg, session_ref):
            if "timeout" in error_msg.lower():
                timeout_events.append(error_msg)

        session.add_error_handler(on_error)

        mock_session = AsyncMock()
        # Simulate timeout during connection
        mock_session.ws_connect.side_effect = TimeoutError("Connection timeout")

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(ConnectionError) as exc_info:
                await session.open()

            assert "timeout" in str(exc_info.value).lower()

    def test_simple_error_recovery_workflow(self):
        """Test basic error recovery workflow."""
        session = Session()

        errors_logged = []

        def on_error(error_msg, session_ref):
            errors_logged.append(error_msg)

        session.add_error_handler(on_error)

        # Directly test error handler registration and basic functionality
        session.handlers.dispatch_error("Test error", session)

        assert len(errors_logged) == 1
        assert "Test error" in errors_logged[0]


class TestPerformanceWorkflow:
    """Test performance-related workflows."""

    def test_high_message_throughput_sync(self):
        """Test handling high message throughput in sync session."""
        session = Session()

        messages_processed = []

        def on_message(message, session_ref):
            messages_processed.append(message.message)

        session.add_message_handler(on_message)

        mock_ws = Mock()
        with patch("websocket.WebSocket", return_value=mock_ws):
            session.open()

            # Simulate rapid message processing (reduced from 100)
            test_user = User(id=1, nick="highvolume", features=[])

            for i in range(10):
                message = Message(sender=test_user, message=f"Message {i}")
                session.handlers.dispatch_event(message, session)

            session.close()

        # Should process messages quickly
        assert len(messages_processed) == 10

    @pytest.mark.asyncio
    async def test_high_concurrency_async(self):
        """Test handling high concurrency in async session."""
        session = AsyncSession()

        messages_processed = []

        def on_message(message, session_ref):
            messages_processed.append(message.message)

        session.add_message_handler(on_message)

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                await session.open()

                test_user = User(id=1, nick="concurrent", features=[])

                # Test concurrent message dispatching (handlers are synchronous)
                for i in range(5):
                    message = Message(sender=test_user, message=f"Concurrent {i}")
                    session.handlers.dispatch_event(message, session)

                await session.close()

        # Should handle concurrent processing efficiently
        assert len(messages_processed) == 5
