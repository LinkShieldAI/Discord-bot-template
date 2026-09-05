import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import main


class StartupTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_credentials_fail_before_creating_clients(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(main, "load_dotenv"),
            patch.object(main, "AsyncLinkShieldAI") as scanner,
        ):
            with self.assertRaisesRegex(ValueError, "DISCORD_TOKEN and LINKSHIELDAI_API_KEY"):
                await main.main()
        scanner.assert_not_called()

    async def test_invalid_mode_fails_before_creating_clients(self):
        environment = {
            "DISCORD_TOKEN": "test-token",
            "LINKSHIELDAI_API_KEY": "test-key",
            "SCAN_MODE": "invalid",
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(main, "load_dotenv"),
            patch.object(main, "AsyncLinkShieldAI") as scanner,
        ):
            with self.assertRaisesRegex(ValueError, "SCAN_MODE"):
                await main.main()
        scanner.assert_not_called()

    async def test_dotenv_paths_default_mode_environment_precedence_and_shutdown(self):
        # Exercises configuration from a directory different from the working directory.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text(
                "DISCORD_TOKEN=file-token\nLINKSHIELDAI_API_KEY=file-key\n",
                encoding="utf-8",
            )
            (root / "common_safe_domains.txt").write_text("example.com\n", encoding="utf-8")
            with (
                patch.dict(os.environ, {"DISCORD_TOKEN": "environment-token"}, clear=True),
                patch.object(main, "ROOT", root),
                patch.object(main, "AsyncLinkShieldAI") as scanner_factory,
                patch.object(main, "LinkShieldBot") as bot_factory,
            ):
                scanner = AsyncMock()
                scanner_factory.return_value = scanner
                bot_context = AsyncMock()
                bot_factory.return_value = bot_context
                bot = bot_context.__aenter__.return_value
                bot.start.side_effect = RuntimeError("simulated disconnect")
                with self.assertRaisesRegex(RuntimeError, "simulated disconnect"):
                    await main.main()
                scanner_factory.assert_called_once_with(
                    api_key="file-key", timeout=10, max_retries=2
                )
                bot_factory.assert_called_once_with(
                    scanner.__aenter__.return_value, {"example.com"}, "deep"
                )
                bot.start.assert_awaited_once_with("environment-token")
                bot_context.__aexit__.assert_awaited_once()
                scanner.__aexit__.assert_awaited_once()
