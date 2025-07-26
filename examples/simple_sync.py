#!/usr/bin/env python3
"""
Simple synchronous wsggpy example.

This example demonstrates basic usage of the synchronous Session class
for connecting to strims.gg chat and sending messages.
"""

from wsggpy import ChatEnvironment, Session


def main():
    """Main function demonstrating synchronous chat usage."""

    # Create a session for production chat
    # For dev chat, use: url=ChatEnvironment.DEV
    session = Session(
        login_key="your_jwt_token_here",  # Replace with your actual JWT token
        url=ChatEnvironment.PRODUCTION,  # or ChatEnvironment.DEV for dev chat
        user_agent="wsggpy-example/1.0",
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
        session.open()
        print("Connected! Type 'quit' to exit.")

        # Send a test message
        session.send_message("Hello from wsggpy!")

        # Keep the connection alive and handle user input
        while True:
            user_input = input("> ")
            if user_input.lower() == "quit":
                break
            elif user_input.strip():
                session.send_message(user_input)

    except KeyboardInterrupt:
        print("\nGracefully shutting down...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        session.close()
        print("Disconnected.")


if __name__ == "__main__":
    main()
