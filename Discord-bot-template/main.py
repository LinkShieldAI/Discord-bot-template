"""A small Discord moderation example using the LinkShieldAI Python SDK."""

import asyncio
import logging
import os
from collections import OrderedDict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from time import monotonic

import discord
from dotenv import load_dotenv
from linkshieldai import AsyncLinkShieldAI, LinkShieldAIError, ScanResult

from utils import extract_links, is_allowlisted, load_safe_domains

ROOT = Path(__file__).resolve().parent
logger = logging.getLogger(__name__)
MAX_PENDING_MESSAGES = 32  # Includes active moderation and messages waiting for a scan.
MAX_CONCURRENT_SCANS = 4
SCAN_TIMEOUT = 35  # Includes waiting for a scan slot and the API request/retries.
MALICIOUS_CACHE_TTL = 6 * 60 * 60  # Six hours from the completed scan, never from a hit.
MALICIOUS_CACHE_MAX_ENTRIES = 1000


class LinkShieldBot(discord.Client):
    def __init__(
        self,
        scanner: AsyncLinkShieldAI,
        safe_domains: set[str],
        scan_mode: str = "deep",
    ) -> None:
        intents = discord.Intents(guilds=True, guild_messages=True, message_content=True)
        super().__init__(intents=intents, allowed_mentions=discord.AllowedMentions.none())
        self.scanner = scanner
        self.safe_domains = safe_domains
        self.scan_mode = scan_mode
        # Share one SDK client and limit concurrent API calls across messages.
        self.scan_slots = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        self.pending_messages = 0
        # Exact (URL, mode) -> (expiry, result); oldest access is first for eviction.
        self.malicious_cache: OrderedDict[tuple[str, str], tuple[float, ScanResult]] = OrderedDict()

    def cached_result(self, url: str, mode: str) -> ScanResult | None:
        """Return an unexpired malicious result without extending its lifetime."""
        key = (url, mode)
        entry = self.malicious_cache.get(key)
        if entry is None:
            return None
        expires_at, result = entry
        if expires_at <= monotonic():
            del self.malicious_cache[key]
            return None
        self.malicious_cache.move_to_end(key)
        return result

    def cache_result(self, url: str, mode: str, result: ScanResult) -> None:
        """Keep only confirmed malicious results, with fixed expiry and bounded storage."""
        key = (url, mode)
        if result.verdict == "SAFE":
            # A concurrent scan may finish with a newer, corrected verdict.
            self.malicious_cache.pop(key, None)
        if result.verdict != "MALICIOUS":
            return
        now = monotonic()
        expired = [key for key, (expiry, _) in self.malicious_cache.items() if expiry <= now]
        for expired_key in expired:
            del self.malicious_cache[expired_key]
        self.malicious_cache[key] = (now + MALICIOUS_CACHE_TTL, result)
        self.malicious_cache.move_to_end(key)
        while len(self.malicious_cache) > MALICIOUS_CACHE_MAX_ENTRIES:
            self.malicious_cache.popitem(last=False)

    @asynccontextmanager
    async def moderation_slot(self, message_id: int) -> AsyncIterator[bool]:
        """Bound admitted work without creating another unbounded queue."""
        # Check and increment before yielding; both run on the same event loop.
        if self.pending_messages >= MAX_PENDING_MESSAGES:
            logger.warning("Moderation capacity reached; message %s left unscanned", message_id)
            yield False
            return
        self.pending_messages += 1
        try:
            yield True
        finally:
            self.pending_messages -= 1

    async def on_ready(self) -> None:
        logger.info(
            "Connected as %s; loaded %d allowlisted hosts", self.user, len(self.safe_domains)
        )

    async def on_message(self, message: discord.Message) -> None:
        await self.moderate_message(message)

    async def on_raw_message_edit(self, payload: discord.RawMessageUpdateEvent) -> None:
        # Raw events cover old messages too. Embed-only updates need no new scan.
        if payload.guild_id is None or "content" not in payload.data:
            return
        if payload.cached_message and payload.cached_message.content == payload.data["content"]:
            return
        if not extract_links(payload.data["content"]):
            return
        async with self.moderation_slot(payload.message_id) as admitted:
            if not admitted:
                return
            try:
                channel = self.get_channel(payload.channel_id) or await self.fetch_channel(
                    payload.channel_id
                )
                message = await channel.fetch_message(payload.message_id)
            except discord.NotFound:
                return
            except discord.HTTPException as error:
                logger.warning(
                    "Could not fetch edited message %s (%s)",
                    payload.message_id,
                    type(error).__name__,
                )
                return
            await self.scan_message(message)

    async def moderate_message(self, message: discord.Message) -> None:
        """Admit a new message only while moderation has available capacity."""
        if message.guild is None or message.author.bot:
            return
        async with self.moderation_slot(message.id) as admitted:
            if admitted:
                await self.scan_message(message)

    async def scan_message(self, message: discord.Message) -> None:
        """Skip trusted hosts; delete the message on the first MALICIOUS verdict."""
        if message.guild is None or message.author.bot:
            return

        # Allowlist exemptions take precedence over cached verdicts and API calls.
        urls = [
            url
            for url in extract_links(message.content)
            if not is_allowlisted(url, self.safe_domains)
        ]
        # Check every URL first so an uncached first link cannot delay a cached second one.
        for url in urls:
            if self.cached_result(url, self.scan_mode) is not None:
                logger.info("Removing message %s using a cached MALICIOUS verdict", message.id)
                await self.remove_message(message)
                return

        for url in urls:
            try:
                result = await asyncio.wait_for(
                    self.scan_url(url),
                    timeout=SCAN_TIMEOUT,
                )
            except (LinkShieldAIError, asyncio.TimeoutError) as error:
                # An unavailable scan is not a safe verdict. Continue with other URLs.
                # Exception messages can contain submitted URLs; log only the type.
                logger.warning("Scan failed for message %s (%s)", message.id, type(error).__name__)
                continue

            if result.verdict == "MALICIOUS":
                await self.remove_message(message)
                return
            if result.verdict != "SAFE":
                logger.info("Inconclusive scan for message %s; no moderation action", message.id)

    async def scan_url(self, url: str) -> ScanResult:
        mode = self.scan_mode
        cached = self.cached_result(url, mode)
        if cached is not None:
            return cached
        # The caller's deadline covers this entire coroutine, including acquisition.
        # The context manager releases the slot on API errors and cancellation too.
        async with self.scan_slots:
            # Another message may have populated the cache while this one waited.
            cached = self.cached_result(url, mode)
            if cached is not None:
                return cached
            result = await self.scanner.scan(url, mode=mode)
            self.cache_result(url, mode, result)
            return result

    async def remove_message(self, message: discord.Message) -> None:
        # Delete first: missing Send Messages permission must not prevent removal.
        try:
            await message.delete()
        except discord.NotFound:
            return  # A moderator or another event already removed it.
        except discord.Forbidden:
            logger.warning("Cannot delete message %s; check Manage Messages permission", message.id)
            return
        except discord.HTTPException as error:
            logger.warning("Could not delete message %s (%s)", message.id, type(error).__name__)
            return

        logger.info("Deleted message %s containing a malicious link", message.id)
        try:
            await message.channel.send(
                "Removed a message containing a link flagged as malicious by LinkShieldAI.",
                allowed_mentions=discord.AllowedMentions.none(),
                delete_after=10,
            )
        except discord.HTTPException as error:
            logger.warning(
                "Message %s removed, but notice failed (%s)", message.id, type(error).__name__
            )


async def main() -> None:
    load_dotenv(ROOT / ".env")
    token = os.getenv("DISCORD_TOKEN", "").strip()
    api_key = os.getenv("LINKSHIELDAI_API_KEY", "").strip()
    if not token or not api_key:
        raise ValueError("Set DISCORD_TOKEN and LINKSHIELDAI_API_KEY in .env or the environment.")
    mode = os.getenv("SCAN_MODE", "deep").strip().lower()
    if mode not in {"standard", "detailed", "deep"}:
        raise ValueError("SCAN_MODE must be standard, detailed, or deep.")
    safe_domains = load_safe_domains(ROOT / "common_safe_domains.txt")

    # Both clients close their network connections on shutdown, including Ctrl+C.
    async with AsyncLinkShieldAI(api_key=api_key, timeout=10, max_retries=2) as scanner:
        async with LinkShieldBot(scanner, safe_domains, mode) as bot:
            await bot.start(token)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        asyncio.run(main())
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from None
    except discord.LoginFailure:
        raise SystemExit("Discord login failed. Check DISCORD_TOKEN.") from None
    except discord.PrivilegedIntentsRequired:
        raise SystemExit("Enable Message Content Intent in the Discord Developer Portal.") from None
    except KeyboardInterrupt:
        pass
