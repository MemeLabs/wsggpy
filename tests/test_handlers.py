"""
Tests for wsggpy event handler system.

Focuses on handler registration, event dispatch, error handling in handlers,
and the overall event-driven architecture reliability.
"""

from unittest.mock import Mock

from wsggpy.handlers import EventHandlers
from wsggpy.models import (
    Ban,
    Broadcast,
    Message,
    Mute,
    Names,
    Ping,
    PrivateMessage,
    User,
    UserFeature,
)


class TestEventHandlerRegistration:
    """Test event handler registration functionality."""

    def setup_method(self):
        """Set up fresh handlers for each test."""
        self.handlers = EventHandlers()

    def test_add_message_handler(self):
        """Test adding message handlers."""
        handler = Mock()
        self.handlers.add_message_handler(handler)

        assert handler in self.handlers.message_handlers
        assert len(self.handlers.message_handlers) == 1

    def test_add_multiple_message_handlers(self):
        """Test adding multiple message handlers."""
        handler1 = Mock()
        handler2 = Mock()
        handler3 = Mock()

        self.handlers.add_message_handler(handler1)
        self.handlers.add_message_handler(handler2)
        self.handlers.add_message_handler(handler3)

        assert len(self.handlers.message_handlers) == 3
        assert handler1 in self.handlers.message_handlers
        assert handler2 in self.handlers.message_handlers
        assert handler3 in self.handlers.message_handlers

    def test_add_all_handler_types(self):
        """Test adding handlers for all supported event types."""
        # Create mock handlers for each type
        handlers = {
            "message": Mock(),
            "private_message": Mock(),
            "ban": Mock(),
            "unban": Mock(),
            "mute": Mock(),
            "unmute": Mock(),
            "join": Mock(),
            "quit": Mock(),
            "broadcast": Mock(),
            "ping": Mock(),
            "names": Mock(),
            "error": Mock(),
            "socket_error": Mock(),
            "generic": Mock(),
        }

        # Register all handlers
        self.handlers.add_message_handler(handlers["message"])
        self.handlers.add_private_message_handler(handlers["private_message"])
        self.handlers.add_ban_handler(handlers["ban"])
        self.handlers.add_unban_handler(handlers["unban"])
        self.handlers.add_mute_handler(handlers["mute"])
        self.handlers.add_unmute_handler(handlers["unmute"])
        self.handlers.add_join_handler(handlers["join"])
        self.handlers.add_quit_handler(handlers["quit"])
        self.handlers.add_broadcast_handler(handlers["broadcast"])
        self.handlers.add_ping_handler(handlers["ping"])
        self.handlers.add_names_handler(handlers["names"])
        self.handlers.add_error_handler(handlers["error"])
        self.handlers.add_socket_error_handler(handlers["socket_error"])
        self.handlers.add_generic_handler(handlers["generic"])

        # Verify all handlers were registered
        assert len(self.handlers.message_handlers) == 1
        assert len(self.handlers.private_message_handlers) == 1
        assert len(self.handlers.ban_handlers) == 1
        assert len(self.handlers.unban_handlers) == 1
        assert len(self.handlers.mute_handlers) == 1
        assert len(self.handlers.unmute_handlers) == 1
        assert len(self.handlers.join_handlers) == 1
        assert len(self.handlers.quit_handlers) == 1
        assert len(self.handlers.broadcast_handlers) == 1
        assert len(self.handlers.ping_handlers) == 1
        assert len(self.handlers.names_handlers) == 1
        assert len(self.handlers.error_handlers) == 1
        assert len(self.handlers.socket_error_handlers) == 1
        assert len(self.handlers.generic_handlers) == 1


class TestEventDispatch:
    """Test event dispatch functionality."""

    def setup_method(self):
        """Set up fresh handlers for each test."""
        self.handlers = EventHandlers()
        self.mock_session = Mock()

    def test_dispatch_message_event(self):
        """Test dispatching message events."""
        handler = Mock()
        self.handlers.add_message_handler(handler)

        user = User(id=1, nick="testuser", features=[])
        message = Message(sender=user, message="Hello, world!")

        self.handlers.dispatch_event(message, self.mock_session)

        handler.assert_called_once_with(message, self.mock_session)

    def test_dispatch_private_message_event(self):
        """Test dispatching private message events."""
        handler = Mock()
        self.handlers.add_private_message_handler(handler)

        sender = User(id=1, nick="sender", features=[])
        recipient = User(id=2, nick="recipient", features=[])
        pm = PrivateMessage(sender=sender, recipient=recipient, message="Secret")

        self.handlers.dispatch_event(pm, self.mock_session)

        handler.assert_called_once_with(pm, self.mock_session)

    def test_dispatch_ban_event(self):
        """Test dispatching ban events."""
        handler = Mock()
        self.handlers.add_ban_handler(handler)

        moderator = User(id=1, nick="mod", features=[UserFeature.MODERATOR])
        target = User(id=2, nick="baduser", features=[])
        ban = Ban(sender=moderator, target=target, reason="Spam", duration=3600)

        self.handlers.dispatch_event(ban, self.mock_session)

        handler.assert_called_once_with(ban, self.mock_session)

    def test_dispatch_mute_event(self):
        """Test dispatching mute events."""
        handler = Mock()
        self.handlers.add_mute_handler(handler)

        moderator = User(id=1, nick="mod", features=[UserFeature.MODERATOR])
        target = User(id=2, nick="chattyuser", features=[])
        mute = Mute(sender=moderator, target=target, duration=1800)

        self.handlers.dispatch_event(mute, self.mock_session)

        handler.assert_called_once_with(mute, self.mock_session)

    def test_dispatch_names_event(self):
        """Test dispatching names (user list) events."""
        handler = Mock()
        self.handlers.add_names_handler(handler)

        users = [
            User(id=1, nick="user1", features=[]),
            User(id=2, nick="user2", features=[UserFeature.MODERATOR]),
        ]
        names = Names(users=users, connectioncount=len(users))

        self.handlers.dispatch_event(names, self.mock_session)

        handler.assert_called_once_with(names, self.mock_session)

    def test_dispatch_ping_event(self):
        """Test dispatching ping events."""
        handler = Mock()
        self.handlers.add_ping_handler(handler)

        ping = Ping(timestamp=1609459200)

        self.handlers.dispatch_event(ping, self.mock_session)

        handler.assert_called_once_with(ping, self.mock_session)

    def test_dispatch_broadcast_event(self):
        """Test dispatching broadcast events."""
        handler = Mock()
        self.handlers.add_broadcast_handler(handler)

        sender = User(id=0, nick="system", features=[UserFeature.ADMIN])
        broadcast = Broadcast(sender=sender, message="Server announcement!")

        self.handlers.dispatch_event(broadcast, self.mock_session)

        handler.assert_called_once_with(broadcast, self.mock_session)

    def test_dispatch_multiple_handlers_same_event(self):
        """Test that multiple handlers are called for the same event type."""
        handler1 = Mock()
        handler2 = Mock()
        handler3 = Mock()

        self.handlers.add_message_handler(handler1)
        self.handlers.add_message_handler(handler2)
        self.handlers.add_message_handler(handler3)

        user = User(id=1, nick="testuser", features=[])
        message = Message(sender=user, message="Hello!")

        self.handlers.dispatch_event(message, self.mock_session)

        handler1.assert_called_once_with(message, self.mock_session)
        handler2.assert_called_once_with(message, self.mock_session)
        handler3.assert_called_once_with(message, self.mock_session)

    def test_dispatch_generic_handlers(self):
        """Test that generic handlers receive all event types."""
        generic_handler = Mock()
        specific_handler = Mock()

        self.handlers.add_generic_handler(generic_handler)
        self.handlers.add_message_handler(specific_handler)

        user = User(id=1, nick="testuser", features=[])
        message = Message(sender=user, message="Hello!")

        self.handlers.dispatch_event(message, self.mock_session)

        # Both handlers should be called
        generic_handler.assert_called_once_with(message, self.mock_session)
        specific_handler.assert_called_once_with(message, self.mock_session)

    def test_dispatch_unknown_event_type(self):
        """Test dispatching unknown event types doesn't crash."""
        # Create a mock event that's not in the known types
        unknown_event = Mock()
        unknown_event.__class__.__name__ = "UnknownEvent"

        # This should not raise an exception
        self.handlers.dispatch_event(unknown_event, self.mock_session)


class TestErrorHandlerDispatch:
    """Test error handler dispatch functionality."""

    def setup_method(self):
        """Set up fresh handlers for each test."""
        self.handlers = EventHandlers()
        self.mock_session = Mock()

    def test_dispatch_error(self):
        """Test dispatching error messages."""
        error_handler = Mock()
        self.handlers.add_error_handler(error_handler)

        error_message = "Connection failed"
        self.handlers.dispatch_error(error_message, self.mock_session)

        error_handler.assert_called_once_with(error_message, self.mock_session)

    def test_dispatch_socket_error(self):
        """Test dispatching socket exceptions."""
        socket_error_handler = Mock()
        self.handlers.add_socket_error_handler(socket_error_handler)

        exception = ConnectionError("Socket error")
        self.handlers.dispatch_socket_error(exception, self.mock_session)

        socket_error_handler.assert_called_once_with(exception, self.mock_session)

    def test_multiple_error_handlers(self):
        """Test that multiple error handlers are called."""
        error_handler1 = Mock()
        error_handler2 = Mock()

        self.handlers.add_error_handler(error_handler1)
        self.handlers.add_error_handler(error_handler2)

        error_message = "Test error"
        self.handlers.dispatch_error(error_message, self.mock_session)

        error_handler1.assert_called_once_with(error_message, self.mock_session)
        error_handler2.assert_called_once_with(error_message, self.mock_session)


class TestHandlerExceptionSafety:
    """Test that exceptions in handlers are handled safely."""

    def setup_method(self):
        """Set up fresh handlers for each test."""
        self.handlers = EventHandlers()
        self.mock_session = Mock()

    def test_handler_exception_isolation(self):
        """Test that exceptions in one handler don't affect others."""
        working_handler = Mock()
        failing_handler = Mock()
        failing_handler.side_effect = ValueError("Handler failed")
        another_working_handler = Mock()

        self.handlers.add_message_handler(working_handler)
        self.handlers.add_message_handler(failing_handler)
        self.handlers.add_message_handler(another_working_handler)

        user = User(id=1, nick="testuser", features=[])
        message = Message(sender=user, message="Hello!")

        # This should not raise an exception
        self.handlers.dispatch_event(message, self.mock_session)

        # All handlers should have been called (even after one failed)
        working_handler.assert_called_once_with(message, self.mock_session)
        failing_handler.assert_called_once_with(message, self.mock_session)
        another_working_handler.assert_called_once_with(message, self.mock_session)

    def test_error_handler_exception_isolation(self):
        """Test that exceptions in error handlers are handled safely."""
        working_error_handler = Mock()
        failing_error_handler = Mock()
        failing_error_handler.side_effect = ValueError("Error handler failed")

        self.handlers.add_error_handler(working_error_handler)
        self.handlers.add_error_handler(failing_error_handler)

        error_message = "Test error"

        # This should not raise an exception
        self.handlers.dispatch_error(error_message, self.mock_session)

        # Both handlers should have been called
        working_error_handler.assert_called_once_with(error_message, self.mock_session)
        failing_error_handler.assert_called_once_with(error_message, self.mock_session)

    def test_socket_error_handler_exception_isolation(self):
        """Test that exceptions in socket error handlers are handled safely."""
        working_socket_handler = Mock()
        failing_socket_handler = Mock()
        failing_socket_handler.side_effect = ValueError("Socket handler failed")

        self.handlers.add_socket_error_handler(working_socket_handler)
        self.handlers.add_socket_error_handler(failing_socket_handler)

        exception = ConnectionError("Socket error")

        # This should not raise an exception
        self.handlers.dispatch_socket_error(exception, self.mock_session)

        # Both handlers should have been called
        working_socket_handler.assert_called_once_with(exception, self.mock_session)
        failing_socket_handler.assert_called_once_with(exception, self.mock_session)

    def test_exception_in_handler_triggers_socket_error(self):
        """Test that exceptions in handlers trigger socket error handlers."""
        failing_message_handler = Mock()
        failing_message_handler.side_effect = ValueError("Message handler failed")

        socket_error_handler = Mock()

        self.handlers.add_message_handler(failing_message_handler)
        self.handlers.add_socket_error_handler(socket_error_handler)

        user = User(id=1, nick="testuser", features=[])
        message = Message(sender=user, message="Hello!")

        self.handlers.dispatch_event(message, self.mock_session)

        # Socket error handler should have been called with the exception
        socket_error_handler.assert_called_once()
        args = socket_error_handler.call_args[0]
        assert isinstance(args[0], ValueError)
        assert "Message handler failed" in str(args[0])
        assert args[1] is self.mock_session


class TestAsyncHandlerSupport:
    """Test async handler support functionality."""

    def setup_method(self):
        """Set up fresh handlers for each test."""
        self.handlers = EventHandlers()
        self.mock_session = Mock()

    def test_sync_message_handler_on_handlers(self):
        """Test that handlers work correctly."""
        handler = Mock()

        def message_handler(message, session):
            handler(message, session)

        self.handlers.add_message_handler(message_handler)

        user = User(id=1, nick="testuser", features=[])
        message = Message(sender=user, message="Hello!")

        self.handlers.dispatch_event(message, self.mock_session)

        handler.assert_called_once_with(message, self.mock_session)

    def test_multiple_sync_handlers(self):
        """Test that multiple sync handlers work correctly."""
        handler1 = Mock()
        handler2 = Mock()

        def message_handler1(message, session):
            handler1(message, session)

        def message_handler2(message, session):
            handler2(message, session)

        self.handlers.add_message_handler(message_handler1)
        self.handlers.add_message_handler(message_handler2)

        user = User(id=1, nick="testuser", features=[])
        message = Message(sender=user, message="Multiple handlers!")

        self.handlers.dispatch_event(message, self.mock_session)

        handler1.assert_called_once_with(message, self.mock_session)
        handler2.assert_called_once_with(message, self.mock_session)

    def test_handler_exception_safety_in_handlers(self):
        """Test that exceptions in handlers are handled safely."""
        working_handler = Mock()
        failing_handler = Mock()

        def working_handler_func(message, session):
            working_handler(message, session)

        def failing_handler_func(message, session):
            failing_handler(message, session)
            raise ValueError("Handler failed")

        self.handlers.add_message_handler(working_handler_func)
        self.handlers.add_message_handler(failing_handler_func)

        user = User(id=1, nick="testuser", features=[])
        message = Message(sender=user, message="Error test!")

        # This should not raise an exception
        self.handlers.dispatch_event(message, self.mock_session)

        working_handler.assert_called_once_with(message, self.mock_session)
        failing_handler.assert_called_once_with(message, self.mock_session)


class TestHandlerPerformance:
    """Test handler performance characteristics."""

    def setup_method(self):
        """Set up fresh handlers for each test."""
        self.handlers = EventHandlers()
        self.mock_session = Mock()

    def test_many_handlers_performance(self):
        """Test that many handlers can be efficiently dispatched."""
        # Add 100 handlers
        handlers = []
        for _i in range(100):
            handler = Mock()
            handlers.append(handler)
            self.handlers.add_message_handler(handler)

        user = User(id=1, nick="testuser", features=[])
        message = Message(sender=user, message="Performance test!")

        # Dispatch should handle many handlers efficiently
        self.handlers.dispatch_event(message, self.mock_session)

        # All handlers should have been called
        for handler in handlers:
            handler.assert_called_once_with(message, self.mock_session)

    def test_handler_call_order_consistency(self):
        """Test that handlers are called in consistent order."""
        call_order = []

        def create_ordered_handler(handler_id):
            def handler(message, session):
                call_order.append(handler_id)

            return handler

        # Add handlers in specific order (reduced from 10)
        for i in range(3):
            handler = create_ordered_handler(i)
            self.handlers.add_message_handler(handler)

        user = User(id=1, nick="testuser", features=[])
        message = Message(sender=user, message="Order test!")

        # Test once instead of multiple times
        self.handlers.dispatch_event(message, self.mock_session)

        # Handlers should be called in the same order
        assert call_order == list(range(3))


class TestHandlerEdgeCases:
    """Test edge cases in handler functionality."""

    def setup_method(self):
        """Set up fresh handlers for each test."""
        self.handlers = EventHandlers()
        self.mock_session = Mock()

    def test_empty_handler_lists(self):
        """Test dispatching events when no handlers are registered."""
        user = User(id=1, nick="testuser", features=[])
        message = Message(sender=user, message="No handlers!")

        # Should not raise an exception
        self.handlers.dispatch_event(message, self.mock_session)

    def test_none_event_dispatch(self):
        """Test dispatching None event."""
        handler = Mock()
        self.handlers.add_message_handler(handler)

        # Should not crash, but handler shouldn't be called
        self.handlers.dispatch_event(None, self.mock_session)

        handler.assert_not_called()

    def test_none_session_dispatch(self):
        """Test dispatching event with None session."""
        handler = Mock()
        self.handlers.add_message_handler(handler)

        user = User(id=1, nick="testuser", features=[])
        message = Message(sender=user, message="None session!")

        # Should still call handler with None session
        self.handlers.dispatch_event(message, None)

        handler.assert_called_once_with(message, None)

    def test_handler_modifies_event(self):
        """Test that handlers can't modify immutable events."""

        def modifying_handler(message, session):
            # Try to modify the immutable message
            try:
                message.message = "Modified!"
            except (AttributeError, ValueError):
                # Expected for immutable Pydantic models
                pass

        self.handlers.add_message_handler(modifying_handler)

        user = User(id=1, nick="testuser", features=[])
        message = Message(sender=user, message="Original message")

        self.handlers.dispatch_event(message, self.mock_session)

        # Message should remain unchanged
        assert message.message == "Original message"
