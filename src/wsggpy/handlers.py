"""Event handler management for wsggpy.

Provides a flexible system for registering and managing event callbacks
for different types of chat events.
"""

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from .models import EventType

logger = logging.getLogger(__name__)

# Type hints for handlers - can be either sync or async
HandlerFunc = (
    Callable[[EventType, Any], None]  # Sync: (event, session) -> None
    | Callable[
        [EventType, Any], Awaitable[None]
    ]  # Async: (event, session) -> Awaitable[None]
)

ErrorHandlerFunc = (
    Callable[[str, Any], None]  # Sync: (error_message, session) -> None
    | Callable[
        [str, Any], Awaitable[None]
    ]  # Async: (error_message, session) -> Awaitable[None]
)

SocketErrorHandlerFunc = (
    Callable[[Exception, Any], None]  # Sync: (exception, session) -> None
    | Callable[
        [Exception, Any], Awaitable[None]
    ]  # Async: (exception, session) -> Awaitable[None]
)


class EventHandlers:
    """Manages event handler registration and dispatch."""

    def __init__(self) -> None:
        """Initialize EventHandlers with empty handler lists."""
        # Type-specific handlers
        self.message_handlers: list[HandlerFunc] = []
        self.private_message_handlers: list[HandlerFunc] = []
        self.ban_handlers: list[HandlerFunc] = []
        self.unban_handlers: list[HandlerFunc] = []
        self.mute_handlers: list[HandlerFunc] = []
        self.unmute_handlers: list[HandlerFunc] = []
        self.join_handlers: list[HandlerFunc] = []
        self.quit_handlers: list[HandlerFunc] = []
        self.broadcast_handlers: list[HandlerFunc] = []
        self.ping_handlers: list[HandlerFunc] = []
        self.names_handlers: list[HandlerFunc] = []

        # Connection event handlers
        self.disconnect_handlers: list[HandlerFunc] = []
        self.reconnecting_handlers: list[HandlerFunc] = []
        self.reconnected_handlers: list[HandlerFunc] = []
        self.reconnect_failed_handlers: list[HandlerFunc] = []

        # Error handlers
        self.error_handlers: list[ErrorHandlerFunc] = []
        self.socket_error_handlers: list[SocketErrorHandlerFunc] = []

        # Generic event handlers (called for all events)
        self.generic_handlers: list[HandlerFunc] = []

    # Handler registration methods
    def add_message_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for chat messages."""
        self.message_handlers.append(handler)

    def add_private_message_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for private messages."""
        self.private_message_handlers.append(handler)

    def add_ban_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for ban events."""
        self.ban_handlers.append(handler)

    def add_unban_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for unban events."""
        self.unban_handlers.append(handler)

    def add_mute_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for mute events."""
        self.mute_handlers.append(handler)

    def add_unmute_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for unmute events."""
        self.unmute_handlers.append(handler)

    def add_join_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for user join events."""
        self.join_handlers.append(handler)

    def add_quit_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for user quit events."""
        self.quit_handlers.append(handler)

    def add_broadcast_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for broadcast messages."""
        self.broadcast_handlers.append(handler)

    def add_ping_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for ping/pong events."""
        self.ping_handlers.append(handler)

    def add_names_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for user list updates."""
        self.names_handlers.append(handler)

    def add_disconnect_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for disconnection events."""
        self.disconnect_handlers.append(handler)

    def add_reconnecting_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for reconnection attempt events."""
        self.reconnecting_handlers.append(handler)

    def add_reconnected_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for successful reconnection events."""
        self.reconnected_handlers.append(handler)

    def add_reconnect_failed_handler(self, handler: HandlerFunc) -> None:
        """Add a handler for failed reconnection events."""
        self.reconnect_failed_handlers.append(handler)

    def add_error_handler(self, handler: ErrorHandlerFunc) -> None:
        """Add a handler for chat errors."""
        self.error_handlers.append(handler)

    def add_socket_error_handler(self, handler: SocketErrorHandlerFunc) -> None:
        """Add a handler for websocket errors."""
        self.socket_error_handlers.append(handler)

    def add_generic_handler(self, handler: HandlerFunc) -> None:
        """Add a handler that receives all events."""
        self.generic_handlers.append(handler)

    # Handler removal methods
    def remove_message_handler(self, handler: HandlerFunc) -> bool:
        """Remove a message handler. Returns True if found and removed."""
        try:
            self.message_handlers.remove(handler)
            return True
        except ValueError:
            return False

    def remove_error_handler(self, handler: ErrorHandlerFunc) -> bool:
        """Remove an error handler. Returns True if found and removed."""
        try:
            self.error_handlers.remove(handler)
            return True
        except ValueError:
            return False

    def clear_handlers(self) -> None:
        """Remove all registered handlers."""
        self.message_handlers.clear()
        self.private_message_handlers.clear()
        self.ban_handlers.clear()
        self.unban_handlers.clear()
        self.mute_handlers.clear()
        self.unmute_handlers.clear()
        self.join_handlers.clear()
        self.quit_handlers.clear()
        self.broadcast_handlers.clear()
        self.ping_handlers.clear()
        self.names_handlers.clear()
        self.disconnect_handlers.clear()
        self.reconnecting_handlers.clear()
        self.reconnected_handlers.clear()
        self.reconnect_failed_handlers.clear()
        self.error_handlers.clear()
        self.socket_error_handlers.clear()
        self.generic_handlers.clear()

    # Event dispatching
    def dispatch_event(self, event: EventType, session: Any) -> None:
        """Dispatch an event to the appropriate handlers."""
        from .models import (
            Ban,
            Broadcast,
            DisconnectEvent,
            Message,
            Mute,
            Names,
            Ping,
            PrivateMessage,
            ReconnectedEvent,
            ReconnectFailedEvent,
            ReconnectingEvent,
            RoomAction,
        )

        # Always call generic handlers first
        self._call_handlers(self.generic_handlers, event, session)

        # Call type-specific handlers
        if isinstance(event, Message):
            self._call_handlers(self.message_handlers, event, session)
        elif isinstance(event, PrivateMessage):
            self._call_handlers(self.private_message_handlers, event, session)
        elif isinstance(event, Ban):
            # Check if it's an unban (duration == 0 or special flag)
            if hasattr(event, "duration") and event.duration == 0:
                self._call_handlers(self.unban_handlers, event, session)
            else:
                self._call_handlers(self.ban_handlers, event, session)
        elif isinstance(event, Mute):
            # Check if it's an unmute
            if hasattr(event, "duration") and event.duration == 0:
                self._call_handlers(self.unmute_handlers, event, session)
            else:
                self._call_handlers(self.mute_handlers, event, session)
        elif isinstance(event, RoomAction):
            # Determine if it's a join or quit based on context
            # This might need additional logic based on the actual protocol
            self._call_handlers(self.join_handlers, event, session)
        elif isinstance(event, Broadcast):
            self._call_handlers(self.broadcast_handlers, event, session)
        elif isinstance(event, Ping):
            self._call_handlers(self.ping_handlers, event, session)
        elif isinstance(event, Names):
            self._call_handlers(self.names_handlers, event, session)
        elif isinstance(event, DisconnectEvent):
            self._call_handlers(self.disconnect_handlers, event, session)
        elif isinstance(event, ReconnectingEvent):
            self._call_handlers(self.reconnecting_handlers, event, session)
        elif isinstance(event, ReconnectedEvent):
            self._call_handlers(self.reconnected_handlers, event, session)
        elif isinstance(event, ReconnectFailedEvent):
            self._call_handlers(self.reconnect_failed_handlers, event, session)

    def dispatch_error(self, error_message: str, session: Any) -> None:
        """Dispatch an error to error handlers."""
        self._call_error_handlers(self.error_handlers, error_message, session)

    def dispatch_socket_error(self, exception: Exception, session: Any) -> None:
        """Dispatch a socket error to socket error handlers."""
        self._call_socket_error_handlers(self.socket_error_handlers, exception, session)

    def _call_handlers(
        self, handlers: list[HandlerFunc], event: EventType, session: Any
    ) -> None:
        """Safely call a list of event handlers."""
        for handler in handlers:
            try:
                # Check if handler is a coroutine function (async def)
                if inspect.iscoroutinefunction(handler):
                    # For async handlers, we need to run them in the event loop
                    try:
                        # Get the current event loop
                        loop = asyncio.get_running_loop()
                        # Create a task to run the coroutine
                        task: asyncio.Task[None] = loop.create_task(
                            handler(event, session)
                        )

                        # Don't await here to avoid blocking, just let it run
                        # Add error handling for the task with proper closure
                        def make_callback(
                            h: HandlerFunc, s: Any
                        ) -> Callable[[asyncio.Task[None]], None]:
                            return lambda t: self._handle_async_handler_error(t, h, s)

                        task.add_done_callback(make_callback(handler, session))
                    except RuntimeError:
                        # No event loop running, this shouldn't happen in async context
                        logger.warning(
                            f"Async handler {handler} called outside event loop context"
                        )
                        # Try to run it anyway (will create the coroutine but not execute)
                        result = handler(event, session)
                        if inspect.iscoroutine(result):
                            logger.error(
                                f"Async handler {handler} returned coroutine but no event loop available"
                            )
                            result.close()  # Clean up the coroutine
                else:
                    # Synchronous handler
                    handler(event, session)
            except Exception as e:
                logger.error(f"Error in event handler {handler}: {e}", exc_info=True)
                # Optionally dispatch this as a socket error
                self.dispatch_socket_error(e, session)

    def _handle_async_handler_error(
        self, task: asyncio.Task[None], handler: HandlerFunc, session: Any
    ) -> None:
        """Handle errors from async handler tasks."""
        try:
            task.result()  # This will raise any exception that occurred
        except Exception as e:
            logger.error(f"Error in async event handler {handler}: {e}", exc_info=True)
            # Optionally dispatch this as a socket error
            self.dispatch_socket_error(e, session)

    def _call_error_handlers(
        self, handlers: list[ErrorHandlerFunc], error_message: str, session: Any
    ) -> None:
        """Safely call a list of error handlers."""
        for handler in handlers:
            try:
                # Check if handler is a coroutine function (async def)
                if inspect.iscoroutinefunction(handler):
                    try:
                        # Get the current event loop
                        loop = asyncio.get_running_loop()
                        # Create a task to run the coroutine
                        task: asyncio.Task[None] = loop.create_task(
                            handler(error_message, session)
                        )

                        # Add error handling for the task with proper closure
                        def make_callback(
                            h: ErrorHandlerFunc,
                        ) -> Callable[[asyncio.Task[None]], None]:
                            return lambda t: self._handle_async_error_handler_error(
                                t, h
                            )

                        task.add_done_callback(make_callback(handler))
                    except RuntimeError:
                        # No event loop running
                        logger.warning(
                            f"Async error handler {handler} called outside event loop context"
                        )
                        result = handler(error_message, session)
                        if inspect.iscoroutine(result):
                            logger.error(
                                f"Async error handler {handler} returned coroutine but no event loop available"
                            )
                            result.close()  # Clean up the coroutine
                else:
                    # Synchronous handler
                    handler(error_message, session)
            except Exception as e:
                logger.error(f"Error in error handler {handler}: {e}", exc_info=True)

    def _call_socket_error_handlers(
        self, handlers: list[SocketErrorHandlerFunc], exception: Exception, session: Any
    ) -> None:
        """Safely call a list of socket error handlers."""
        for handler in handlers:
            try:
                # Check if handler is a coroutine function (async def)
                if inspect.iscoroutinefunction(handler):
                    try:
                        # Get the current event loop
                        loop = asyncio.get_running_loop()
                        # Create a task to run the coroutine
                        task: asyncio.Task[None] = loop.create_task(
                            handler(exception, session)
                        )

                        # Add error handling for the task with proper closure
                        def make_callback(
                            h: SocketErrorHandlerFunc,
                        ) -> Callable[[asyncio.Task[None]], None]:
                            return (
                                lambda t: self._handle_async_socket_error_handler_error(
                                    t, h
                                )
                            )

                        task.add_done_callback(make_callback(handler))
                    except RuntimeError:
                        # No event loop running
                        logger.warning(
                            f"Async socket error handler {handler} called outside event loop context"
                        )
                        result = handler(exception, session)
                        if inspect.iscoroutine(result):
                            logger.error(
                                f"Async socket error handler {handler} returned coroutine but no event loop available"
                            )
                            result.close()  # Clean up the coroutine
                else:
                    # Synchronous handler
                    handler(exception, session)
            except Exception as e:
                logger.error(
                    f"Error in socket error handler {handler}: {e}", exc_info=True
                )

    def _handle_async_error_handler_error(
        self, task: asyncio.Task[None], handler: ErrorHandlerFunc
    ) -> None:
        """Handle errors from async error handler tasks."""
        try:
            task.result()  # This will raise any exception that occurred
        except Exception as e:
            logger.error(f"Error in async error handler {handler}: {e}", exc_info=True)

    def _handle_async_socket_error_handler_error(
        self, task: asyncio.Task[None], handler: SocketErrorHandlerFunc
    ) -> None:
        """Handle errors from async socket error handler tasks."""
        try:
            task.result()  # This will raise any exception that occurred
        except Exception as e:
            logger.error(
                f"Error in async socket error handler {handler}: {e}", exc_info=True
            )
