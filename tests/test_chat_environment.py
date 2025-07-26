"""Tests for ChatEnvironment constants."""

from wsggpy import AsyncSession, ChatEnvironment, Session


class TestChatEnvironment:
    """Test ChatEnvironment constants and integration."""

    def test_chat_environment_constants(self):
        """Test that ChatEnvironment has the correct constants."""
        assert ChatEnvironment.PRODUCTION == "wss://chat.strims.gg/ws"
        assert ChatEnvironment.DEV == "wss://chat2.strims.gg/ws"

        # Test aliases
        assert ChatEnvironment.CHAT == ChatEnvironment.PRODUCTION
        assert ChatEnvironment.CHAT2 == ChatEnvironment.DEV

    def test_sync_session_with_environments(self):
        """Test Session with different ChatEnvironment constants."""
        # Production environment
        prod_session = Session(url=ChatEnvironment.PRODUCTION)
        assert prod_session.url == "wss://chat.strims.gg/ws"

        # Dev environment
        dev_session = Session(url=ChatEnvironment.DEV)
        assert dev_session.url == "wss://chat2.strims.gg/ws"

        # Aliases
        chat_session = Session(url=ChatEnvironment.CHAT)
        assert chat_session.url == "wss://chat.strims.gg/ws"

        chat2_session = Session(url=ChatEnvironment.CHAT2)
        assert chat2_session.url == "wss://chat2.strims.gg/ws"

    def test_async_session_with_environments(self):
        """Test AsyncSession with different ChatEnvironment constants."""
        # Production environment
        prod_session = AsyncSession(url=ChatEnvironment.PRODUCTION)
        assert prod_session.url == "wss://chat.strims.gg/ws"

        # Dev environment
        dev_session = AsyncSession(url=ChatEnvironment.DEV)
        assert dev_session.url == "wss://chat2.strims.gg/ws"

        # Aliases
        chat_session = AsyncSession(url=ChatEnvironment.CHAT)
        assert chat_session.url == "wss://chat.strims.gg/ws"

        chat2_session = AsyncSession(url=ChatEnvironment.CHAT2)
        assert chat2_session.url == "wss://chat2.strims.gg/ws"

    def test_environment_constants_are_strings(self):
        """Test that all environment constants are strings."""
        assert isinstance(ChatEnvironment.PRODUCTION, str)
        assert isinstance(ChatEnvironment.DEV, str)
        assert isinstance(ChatEnvironment.CHAT, str)
        assert isinstance(ChatEnvironment.CHAT2, str)

    def test_environment_constants_are_websocket_urls(self):
        """Test that all environment constants are valid WebSocket URLs."""
        for env_url in [
            ChatEnvironment.PRODUCTION,
            ChatEnvironment.DEV,
            ChatEnvironment.CHAT,
            ChatEnvironment.CHAT2,
        ]:
            assert env_url.startswith("wss://")
            assert "strims.gg" in env_url
            assert env_url.endswith("/ws")

    def test_default_session_urls(self):
        """Test that sessions default to production environment."""
        sync_session = Session()
        async_session = AsyncSession()

        assert sync_session.url == ChatEnvironment.PRODUCTION
        assert async_session.url == ChatEnvironment.PRODUCTION

        # Both should be the same
        assert sync_session.url == async_session.url
