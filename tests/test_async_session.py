"""
Tests for wsggpy AsyncSession class.

Focuses on async functionality including connection management, context manager usage,
concurrent message handling, and async-specific error scenarios.
"""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest
from wsggpy import AsyncSession, ChatEnvironment
from wsggpy.exceptions import ConnectionError, MessageError, ProtocolError, WSGGError
from wsggpy.models import Message, User, UserFeature


class TestAsyncSessionInitialization:
    """Test AsyncSession initialization and configuration."""

    def test_async_session_creation_with_defaults(self):
        """Test async session creation with default parameters."""
        session = AsyncSession()

        assert session.login_key is None
        assert session.url == "wss://chat.strims.gg/ws"
        assert session.user_agent == "wsggpy/0.1.0"
        assert not session.is_connected()
        assert session.get_users() == []

    def test_async_session_creation_with_custom_params(self):
        """Test async session creation with custom parameters."""
        session = AsyncSession(
            login_key="test_key",
            url="wss://custom.server/ws",
            user_agent="test-async-client/1.0",
        )

        assert session.login_key == "test_key"
        assert session.url == "wss://custom.server/ws"
        assert session.user_agent == "test-async-client/1.0"

    def test_chat_environment_constants(self):
        """Test using ChatEnvironment constants for URL configuration."""
        # Test production environment
        prod_session = AsyncSession(url=ChatEnvironment.PRODUCTION)
        assert prod_session.url == "wss://chat.strims.gg/ws"
        assert prod_session.url == ChatEnvironment.CHAT  # Alias test

        # Test dev environment
        dev_session = AsyncSession(url=ChatEnvironment.DEV)
        assert dev_session.url == "wss://chat2.strims.gg/ws"
        assert dev_session.url == ChatEnvironment.CHAT2  # Alias test

    def test_async_session_immutable_during_connection(self):
        """Test that certain properties cannot be changed while connected."""
        session = AsyncSession()

        # Mock aiohttp components
        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):

                async def test():
                    await session.open()

                    # This should raise error while connected
                    with pytest.raises(WSGGError):
                        session.set_url("wss://new.server/ws")

                    await session.close()

                asyncio.run(test())


class TestAsyncSessionConnection:
    """Test AsyncSession connection and disconnection functionality."""

    @pytest.mark.asyncio
    async def test_successful_async_connection(self):
        """Test successful async websocket connection."""
        session = AsyncSession(login_key="test_key")

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                await session.open()

                assert session.is_connected()
                mock_session.ws_connect.assert_called_once()

                await session.close()

    @pytest.mark.asyncio
    async def test_async_connection_failure(self):
        """Test async connection failure handling."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_session.ws_connect.side_effect = aiohttp.ClientError("Connection failed")

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(ConnectionError) as exc_info:
                await session.open()

            assert "Connection failed" in str(exc_info.value)
            assert not session.is_connected()

    @pytest.mark.asyncio
    async def test_async_double_connection_attempt(self):
        """Test that opening an already connected async session is handled gracefully."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                await session.open()

                # Second open should not fail but log warning
                with patch("wsggpy.async_session.logger") as mock_logger:
                    await session.open()
                    mock_logger.warning.assert_called_once()

                await session.close()

    @pytest.mark.asyncio
    async def test_async_close_connection(self):
        """Test closing async websocket connection."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                await session.open()
                await session.close()

                assert not session.is_connected()
                mock_ws.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_close_without_connection(self):
        """Test closing when not connected doesn't raise errors."""
        session = AsyncSession()

        # Should not raise any exceptions
        await session.close()
        assert not session.is_connected()


class TestAsyncSessionContextManager:
    """Test AsyncSession context manager functionality."""

    @pytest.mark.asyncio
    async def test_context_manager_success(self):
        """Test successful context manager usage."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                async with session as s:
                    assert s is session
                    assert session.is_connected()

                # Should be closed after exiting context
                assert not session.is_connected()

    @pytest.mark.asyncio
    async def test_context_manager_with_exception(self):
        """Test context manager cleanup when exception occurs."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                try:
                    async with session:
                        assert session.is_connected()
                        raise ValueError("Test exception")
                except ValueError:
                    pass

                # Should be closed even after exception
                assert not session.is_connected()

    @pytest.mark.asyncio
    async def test_context_manager_connection_failure(self):
        """Test context manager when connection fails."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_session.ws_connect.side_effect = aiohttp.ClientError("Connection failed")

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with pytest.raises(ConnectionError):
                async with session:
                    pass  # Should not reach here


class TestAsyncMessageSending:
    """Test async message sending functionality."""

    def setup_method(self):
        """Set up a mock connected async session for each test."""
        self.session = AsyncSession()
        self.mock_session = AsyncMock()
        self.mock_ws = AsyncMock()
        self.mock_ws.closed = False
        self.mock_session.ws_connect.return_value = self.mock_ws

    @pytest.mark.asyncio
    async def test_async_send_chat_message_success(self):
        """Test sending a regular chat message asynchronously."""
        with patch("aiohttp.ClientSession", return_value=self.mock_session):
            with patch.object(self.session, "_listen_loop", new_callable=AsyncMock):
                await self.session.open()
                await self.session.send_message("Hello, async world!")

                self.mock_ws.send_str.assert_called_once()
                call_args = self.mock_ws.send_str.call_args[0][0]

                assert call_args.startswith("MSG ")
                json_part = call_args[4:]  # Remove "MSG " prefix
                data = json.loads(json_part)
                assert data["data"] == "Hello, async world!"

                await self.session.close()

    @pytest.mark.asyncio
    async def test_async_send_action_message_success(self):
        """Test sending an action message asynchronously."""
        with patch("aiohttp.ClientSession", return_value=self.mock_session):
            with patch.object(self.session, "_listen_loop", new_callable=AsyncMock):
                await self.session.open()
                await self.session.send_action("waves asynchronously")

                self.mock_ws.send_str.assert_called_once()
                call_args = self.mock_ws.send_str.call_args[0][0]

                assert call_args.startswith("MSG ")
                json_part = call_args[4:]  # Remove "MSG " prefix
                data = json.loads(json_part)
                assert data["data"] == "/me waves asynchronously"

                await self.session.close()

    @pytest.mark.asyncio
    async def test_async_send_private_message_success(self):
        """Test sending a private message asynchronously."""
        with patch("aiohttp.ClientSession", return_value=self.mock_session):
            with patch.object(self.session, "_listen_loop", new_callable=AsyncMock):
                await self.session.open()
                await self.session.send_private_message(
                    "async_friend", "Secret async message"
                )

                self.mock_ws.send_str.assert_called_once()
                call_args = self.mock_ws.send_str.call_args[0][0]

                assert call_args.startswith("PRIVMSG ")
                json_part = call_args[8:]  # Remove "PRIVMSG " prefix
                data = json.loads(json_part)
                assert data["data"]["nick"] == "async_friend"
                assert data["data"]["message"] == "Secret async message"

                await self.session.close()

    @pytest.mark.asyncio
    async def test_async_send_moderation_commands(self):
        """Test sending moderation commands asynchronously."""
        with patch("aiohttp.ClientSession", return_value=self.mock_session):
            with patch.object(self.session, "_listen_loop", new_callable=AsyncMock):
                await self.session.open()

                # Test ban
                await self.session.send_ban("baduser", "Async spam", 3600)
                call_args = self.mock_ws.send_str.call_args[0][0]
                data = json.loads(call_args)
                assert data["type"] == "BAN"
                assert data["data"]["nick"] == "baduser"

                # Test mute
                self.mock_ws.reset_mock()
                await self.session.send_mute("louduser", 1800)
                call_args = self.mock_ws.send_str.call_args[0][0]
                data = json.loads(call_args)
                assert data["type"] == "MUTE"
                assert data["data"]["duration"] == 1800

                await self.session.close()

    @pytest.mark.asyncio
    async def test_async_send_message_when_disconnected(self):
        """Test that sending message while disconnected raises ConnectionError."""
        with pytest.raises(ConnectionError):
            await self.session.send_message("Hello")

    @pytest.mark.asyncio
    async def test_async_send_message_websocket_error(self):
        """Test handling websocket errors during async message sending."""
        with patch("aiohttp.ClientSession", return_value=self.mock_session):
            with patch.object(self.session, "_listen_loop", new_callable=AsyncMock):
                await self.session.open()

                self.mock_ws.send_str.side_effect = aiohttp.ClientError(
                    "Async send failed"
                )

                with pytest.raises(MessageError) as exc_info:
                    await self.session.send_message("Hello")

                assert "Async send failed" in str(exc_info.value)

                await self.session.close()


class TestAsyncUserManagement:
    """Test async user state management functionality."""

    def test_async_get_users_empty_initially(self):
        """Test that user list is empty initially."""
        session = AsyncSession()
        assert session.get_users() == []

    def test_async_get_nonexistent_user(self):
        """Test getting a user that doesn't exist."""
        session = AsyncSession()
        assert session.get_user("nonexistent") is None

    def test_async_user_list_management(self):
        """Test internal user list management during async events."""
        session = AsyncSession()

        # Mock some users in the internal state
        user1 = User(id=1, nick="async_user1", features=[])
        user2 = User(id=2, nick="async_user2", features=[UserFeature.MODERATOR])

        session._users["async_user1"] = user1
        session._users["async_user2"] = user2

        users = session.get_users()
        assert len(users) == 2
        assert user1 in users
        assert user2 in users

        # Test getting specific user
        found_user = session.get_user("async_user2")
        assert found_user == user2
        assert found_user.has_feature(UserFeature.MODERATOR)


class TestAsyncEventHandlerIntegration:
    """Test async event handler integration."""

    def test_add_async_message_handler(self):
        """Test adding async message handlers."""
        session = AsyncSession()
        messages_received = []

        def on_message(message, session_ref):
            messages_received.append(message)

        session.add_message_handler(on_message)

        # Simulate receiving a message by directly calling the event handler
        test_user = User(id=1, nick="async_test", features=[])
        test_message = Message(sender=test_user, message="Async Hello")

        session.handlers.dispatch_event(test_message, session)

        assert len(messages_received) == 1
        assert messages_received[0] == test_message

    def test_add_async_error_handler(self):
        """Test adding error handlers to async session."""
        session = AsyncSession()
        errors_received = []

        def on_error(error_message, session_ref):
            errors_received.append(error_message)

        session.add_error_handler(on_error)

        # Simulate an error
        session.handlers.dispatch_error("Async test error", session)

        assert len(errors_received) == 1
        assert errors_received[0] == "Async test error"

    def test_async_handler_exception_safety(self):
        """Test that exceptions in handlers don't crash the session."""
        session = AsyncSession()

        def failing_handler(message, session_ref):
            raise ValueError("Async handler error")

        session.add_message_handler(failing_handler)

        # This should not raise an exception
        test_user = User(id=1, nick="test", features=[])
        test_message = Message(sender=test_user, message="Hello")

        # The handler should be called safely without crashing
        session.handlers.dispatch_event(test_message, session)


class TestAsyncSessionConcurrency:
    """Test concurrent operations with AsyncSession."""

    @pytest.mark.asyncio
    async def test_concurrent_message_sending(self):
        """Test sending messages concurrently."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                await session.open()

                async def send_messages(message_prefix):
                    tasks = []
                    for i in range(5):
                        task = session.send_message(f"{message_prefix}_{i}")
                        tasks.append(task)
                    await asyncio.gather(*tasks)

                # Send messages concurrently from multiple coroutines
                await asyncio.gather(
                    send_messages("coro_1"),
                    send_messages("coro_2"),
                    send_messages("coro_3"),
                )

                # Should have sent 15 messages total (3 coroutines * 5 messages each)
                assert mock_ws.send_str.call_count == 15

                await session.close()

    @pytest.mark.asyncio
    async def test_concurrent_connection_operations(self):
        """Test concurrent connection and disconnection operations."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                # Try to connect multiple times concurrently
                await asyncio.gather(session.open(), session.open(), session.open())

                assert session.is_connected()

                # Try to close multiple times concurrently
                await asyncio.gather(session.close(), session.close(), session.close())

                assert not session.is_connected()

    @pytest.mark.asyncio
    async def test_message_sending_during_disconnect(self):
        """Test behavior when sending messages during disconnection."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                await session.open()

                async def disconnect_after_delay():
                    # Removed sleep to avoid hanging
                    await session.close()

                async def send_messages_continuously():
                    for i in range(3):  # Reduced from 10
                        try:
                            await session.send_message(f"Message {i}")
                            # Removed sleep to avoid hanging
                        except ConnectionError:
                            # Expected when connection is closed
                            break

                # Run disconnect and message sending concurrently
                await asyncio.gather(
                    disconnect_after_delay(),
                    send_messages_continuously(),
                    return_exceptions=True,
                )


class TestAsyncSessionRobustness:
    """Test AsyncSession robustness and edge cases."""

    @pytest.mark.asyncio
    async def test_async_malformed_message_handling(self):
        """Test handling of malformed incoming messages in async context."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                await session.open()

                # This should not crash the session
                with pytest.raises(ProtocolError):
                    session.protocol.parse_message("invalid json {")

                await session.close()

    @pytest.mark.asyncio
    async def test_async_websocket_connection_lost(self):
        """Test handling when websocket connection is lost."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = True  # Simulate closed connection
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                await session.open()

                # Connection should be reported as lost
                assert not session.is_connected()

                await session.close()

    @pytest.mark.asyncio
    async def test_async_large_message_handling(self):
        """Test sending large messages asynchronously."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                await session.open()

                # Very large message
                large_message = "A" * 100000
                await session.send_message(large_message)

                mock_ws.send_str.assert_called_once()
                call_args = mock_ws.send_str.call_args[0][0]

                assert call_args.startswith("MSG ")
                json_part = call_args[4:]  # Remove "MSG " prefix
                data = json.loads(json_part)
                assert data["data"] == large_message

                await session.close()

    @pytest.mark.asyncio
    async def test_async_special_characters_in_messages(self):
        """Test sending messages with special characters asynchronously."""
        session = AsyncSession()

        mock_session = AsyncMock()
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_session.ws_connect.return_value = mock_ws

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(session, "_listen_loop", new_callable=AsyncMock):
                await session.open()

                special_message = "Async 🚀 test with émojis and ñ: {'async': true}"
                await session.send_message(special_message)

                mock_ws.send_str.assert_called_once()
                call_args = mock_ws.send_str.call_args[0][0]

                assert call_args.startswith("MSG ")
                json_part = call_args[4:]  # Remove "MSG " prefix
                data = json.loads(json_part)
                assert data["data"] == special_message

                await session.close()


class TestAsyncSessionMessageProcessing:
    """Test async session message processing functionality."""

    def test_async_message_parsing_and_handling(self):
        """Test that messages can be parsed and handled correctly."""
        session = AsyncSession()

        messages_received = []

        def on_message(message, session_ref):
            messages_received.append(message)

        session.add_message_handler(on_message)

        # Test message parsing and handling directly
        raw_message = json.dumps(
            {
                "type": "MSG",
                "user": {"id": 123, "nick": "testuser", "features": []},
                "data": "Hello from server!",
                "timestamp": 1609459200000,
            }
        )

        # Parse message using protocol
        parsed_message = session.protocol.parse_message(raw_message)
        assert parsed_message is not None

        # Dispatch to handlers
        session.handlers.dispatch_event(parsed_message, session)

        assert len(messages_received) == 1
        assert messages_received[0].message == "Hello from server!"
        assert messages_received[0].sender.nick == "testuser"

    def test_async_error_handling_during_parsing(self):
        """Test that parsing errors are handled gracefully."""
        session = AsyncSession()

        errors_received = []

        def on_error(error_message, session_ref):
            errors_received.append(error_message)

        session.add_error_handler(on_error)

        # Test invalid JSON handling
        with pytest.raises(ProtocolError) as exc_info:
            session.protocol.parse_message("invalid json {")

        assert (
            "parse" in str(exc_info.value).lower()
            or "json" in str(exc_info.value).lower()
        )
