import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import discord
import httpx
from linkshieldai import AsyncLinkShieldAI, ScanResult

from main import LinkShieldBot


def message(content):
    return SimpleNamespace(
        id=123,
        content=content,
        guild=SimpleNamespace(id=456),
        author=SimpleNamespace(bot=False),
        delete=AsyncMock(),
        channel=SimpleNamespace(send=AsyncMock()),
    )


def discord_error(error_type, status):
    return error_type(SimpleNamespace(status=status, reason="Test failure"), "Test failure")


class BotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []
        self.responses = {}

        def handle(request):
            self.requests.append(request)
            url = json.loads(request.content)["url"]
            response = self.responses.get(url, httpx.Response(200, json={"verdict": "SAFE"}))
            if isinstance(response, Exception):
                raise response
            return response

        self.http = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        self.scanner = AsyncLinkShieldAI(api_key="test-key", client=self.http, max_retries=0)
        self.bot = LinkShieldBot(self.scanner, {"example.com"})

    async def asyncTearDown(self):
        await self.bot.close()
        await self.scanner.close()
        await self.http.aclose()

    def requested_urls(self):
        return [json.loads(request.content)["url"] for request in self.requests]

    async def test_allowlisted_links_make_zero_http_requests(self):
        item = message("https://example.com/a HTTPS://EXAMPLE.COM.:443/b")
        await self.bot.on_message(item)
        self.assertEqual(self.requests, [])
        item.delete.assert_not_awaited()

    async def test_apostrophe_bypass_scans_full_destination_and_deletes(self):
        self.bot.safe_domains.add("google.com")
        url = "https://google.com'@attacker.test/payload"
        self.responses[url] = httpx.Response(200, json={"verdict": "MALICIOUS"})
        item = message(f"https://google.com/ [Click]({url})")
        await self.bot.on_message(item)
        self.assertEqual(self.requested_urls(), [url])
        item.delete.assert_awaited_once()

    async def test_two_unlisted_links_are_both_scanned(self):
        urls = ["https://one.test/page", "https://two.test/it's-a-page"]
        await self.bot.on_message(message(f"[One]({urls[0]})[Two]({urls[1]})"))
        self.assertEqual(self.requested_urls(), urls)

    async def test_admission_caps_active_and_waiting_messages(self):
        started = asyncio.Event()
        release = asyncio.Event()
        calls = []

        async def slow_scan(url, **kwargs):
            calls.append(url)
            if len(calls) == 4:
                started.set()
            await release.wait()
            return ScanResult(verdict="SAFE")

        items = [message(f"https://slow.test/{index}") for index in range(10)]
        tasks = []
        with (
            patch("main.MAX_PENDING_MESSAGES", 6),
            patch.object(self.scanner, "scan", side_effect=slow_scan),
            self.assertLogs("main", level="WARNING") as logs,
        ):
            try:
                tasks = [asyncio.create_task(self.bot.on_message(item)) for item in items]
                await asyncio.wait_for(started.wait(), timeout=1)
                await asyncio.sleep(0)
                self.assertEqual(sum(not task.done() for task in tasks), 6)
                self.assertEqual(len(calls), 4)
                release.set()
                await asyncio.wait_for(asyncio.gather(*tasks), timeout=1)
                self.assertEqual(len(calls), 6)
                self.assertEqual(sum("capacity" in entry for entry in logs.output), 4)
            finally:
                release.set()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        for item in items:
            item.delete.assert_not_awaited()
            item.channel.send.assert_not_awaited()

    async def test_queue_wait_expires_without_scanning_and_recovers(self):
        for _ in range(4):
            await self.bot.scan_slots.acquire()
        item = message("https://waiting.test/")
        try:
            with (
                patch("main.SCAN_TIMEOUT", 0.01),
                self.assertLogs("main", level="WARNING") as logs,
            ):
                await asyncio.wait_for(self.bot.on_message(item), timeout=1)
            self.assertTrue(any("TimeoutError" in entry for entry in logs.output))
            self.assertEqual(self.requests, [])
            item.delete.assert_not_awaited()
        finally:
            for _ in range(4):
                self.bot.scan_slots.release()
        await self.bot.on_message(message("https://fresh.test/"))
        self.assertEqual(self.requested_urls(), ["https://fresh.test/"])

    async def test_edited_messages_share_admission_before_discord_fetch(self):
        entered = asyncio.Event()
        release = asyncio.Event()

        async def slow_scan(*args, **kwargs):
            entered.set()
            await release.wait()
            return ScanResult(verdict="SAFE")

        payload = SimpleNamespace(
            guild_id=456,
            channel_id=789,
            message_id=123,
            cached_message=None,
            data={"content": "https://edited.test/"},
        )
        with (
            patch("main.MAX_PENDING_MESSAGES", 1),
            patch.object(self.scanner, "scan", side_effect=slow_scan),
            patch.object(self.bot, "get_channel") as get_channel,
            patch.object(self.bot, "fetch_channel", new=AsyncMock()) as fetch_channel,
        ):
            task = asyncio.create_task(self.bot.on_message(message("https://slow.test/")))
            try:
                await asyncio.wait_for(entered.wait(), timeout=1)
                with self.assertLogs("main", level="WARNING"):
                    await self.bot.on_raw_message_edit(payload)
                get_channel.assert_not_called()
                fetch_channel.assert_not_awaited()
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_exact_v1_contract_and_query_preservation(self):
        url = "https://unlisted.test/path?a=1&b=two%20words#part"
        await self.bot.on_message(message(url))
        self.assertEqual(len(self.requests), 1)
        request = self.requests[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(str(request.url), "https://api.linkshieldai.com/v1/scan")
        self.assertEqual(request.headers["Authorization"], "Bearer test-key")
        self.assertEqual(json.loads(request.content), {"url": url, "mode": "deep"})

    async def test_cancelling_active_scan_releases_capacity(self):
        entered = asyncio.Event()
        stopped = asyncio.Event()

        async def slow_scan(*args, **kwargs):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        with (
            patch("main.MAX_PENDING_MESSAGES", 1),
            patch.object(self.scanner, "scan", side_effect=slow_scan),
        ):
            task = asyncio.create_task(self.bot.on_message(message("https://slow.test/")))
            try:
                await asyncio.wait_for(entered.wait(), timeout=1)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            self.assertTrue(stopped.is_set())
            self.assertEqual(self.bot.pending_messages, 0)

        # All four scan slots must be reusable after cancellation.
        acquired = 0
        try:
            for _ in range(4):
                await asyncio.wait_for(self.bot.scan_slots.acquire(), timeout=1)
                acquired += 1
        finally:
            for _ in range(acquired):
                self.bot.scan_slots.release()
        await self.bot.on_message(message("https://fresh.test/"))
        self.assertEqual(self.requested_urls(), ["https://fresh.test/"])

    async def test_cancelling_waiting_message_releases_admission(self):
        for _ in range(4):
            await self.bot.scan_slots.acquire()
        with patch("main.MAX_PENDING_MESSAGES", 1):
            task = asyncio.create_task(self.bot.on_message(message("https://waiting.test/")))
            try:
                await asyncio.sleep(0)
                self.assertEqual(self.bot.pending_messages, 1)
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                self.assertEqual(self.bot.pending_messages, 0)
                self.assertEqual(self.requests, [])
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                for _ in range(4):
                    self.bot.scan_slots.release()
            await self.bot.on_message(message("https://fresh.test/"))
        self.assertEqual(self.requested_urls(), ["https://fresh.test/"])

    async def test_deadline_cancels_slow_scan_and_releases_slots(self):
        stopped = asyncio.Event()

        async def slow_scan(*args, **kwargs):
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        item = message("https://slow.test/")
        with (
            patch("main.SCAN_TIMEOUT", 0.01),
            patch.object(self.scanner, "scan", side_effect=slow_scan),
            self.assertLogs("main", level="WARNING"),
        ):
            await asyncio.wait_for(self.bot.on_message(item), timeout=1)
        self.assertTrue(stopped.is_set())
        self.assertEqual(self.bot.pending_messages, 0)
        item.delete.assert_not_awaited()
        acquired = 0
        try:
            for _ in range(4):
                await asyncio.wait_for(self.bot.scan_slots.acquire(), timeout=1)
                acquired += 1
        finally:
            for _ in range(acquired):
                self.bot.scan_slots.release()
        await self.bot.on_message(message("https://fresh.test/"))
        self.assertEqual(self.requested_urls(), ["https://fresh.test/"])

    async def test_allowlist_lookalikes_and_subdomains_are_scanned(self):
        urls = [
            "https://example.com.evil.test/",
            "https://example.com@evil.test/",
            "https://www.example.com/",
        ]
        await self.bot.on_message(message(" ".join(urls)))
        self.assertEqual(self.requested_urls(), urls)

    async def test_mixed_links_and_adjacent_markdown_delete_once(self):
        url = "https://evil.test/phishing"
        self.responses[url] = httpx.Response(200, json={"verdict": "MALICIOUS"})
        item = message(f"[trusted](https://example.com/)[click]({url}) {url} https://later.test/")

        async def notice(*args, **kwargs):
            item.delete.assert_awaited_once()
            self.assertNotIn(url, args[0])
            self.assertFalse(kwargs["allowed_mentions"].everyone)

        item.channel.send.side_effect = notice
        await self.bot.on_message(item)
        self.assertEqual(self.requested_urls(), [url])
        item.delete.assert_awaited_once()
        item.channel.send.assert_awaited_once()

    async def test_safe_unknown_and_missing_verdict_do_not_delete(self):
        for payload in ({"verdict": "SAFE"}, {"verdict": "UNKNOWN"}, {}, {"verdict": "new-value"}):
            self.responses["https://unlisted.test/"] = httpx.Response(200, json=payload)
            item = message("https://unlisted.test/")
            with self.subTest(payload=payload):
                await self.bot.on_message(item)
                item.delete.assert_not_awaited()
                item.channel.send.assert_not_awaited()

    async def test_unknown_does_not_prevent_later_malicious_detection(self):
        self.responses["https://unknown.test/"] = httpx.Response(200, json={"verdict": "UNKNOWN"})
        self.responses["https://evil.test/"] = httpx.Response(200, json={"verdict": "MALICIOUS"})
        item = message("https://unknown.test/ https://evil.test/")
        with self.assertLogs("main", level="INFO") as logs:
            await self.bot.on_message(item)
        self.assertTrue(any("Inconclusive" in line for line in logs.output))
        item.delete.assert_awaited_once()

    async def test_sdk_failures_leave_message_and_still_scan_later_links(self):
        failures = [
            httpx.Response(status, json={"error": {"code": "TEST", "message": "failure"}})
            for status in (400, 401, 429, 500, 503)
        ] + [
            httpx.Response(200, text="not JSON"),
            httpx.Response(200, json=[]),
            httpx.ReadTimeout("offline"),
        ]
        for index, failure in enumerate(failures):
            self.responses["https://failure.test/"] = failure
            item = message("https://failure.test/")
            with self.subTest(failure=failure), self.assertLogs("main", level="WARNING"):
                await self.bot.on_message(item)
            item.delete.assert_not_awaited()
            malicious_url = f"https://evil.test/{index}"
            self.responses[malicious_url] = httpx.Response(200, json={"verdict": "MALICIOUS"})
            mixed = message(f"https://failure.test/ {malicious_url}")
            with self.assertLogs("main", level="WARNING"):
                await self.bot.on_message(mixed)
            mixed.delete.assert_awaited_once()

    async def test_total_scan_timeout_leaves_message(self):
        item = message("https://slow.test/")
        with patch.object(self.scanner, "scan", new=AsyncMock(side_effect=asyncio.TimeoutError)):
            with self.assertLogs("main", level="WARNING"):
                await self.bot.on_message(item)
        item.delete.assert_not_awaited()

    async def test_bot_messages_and_dms_are_ignored(self):
        for is_bot, guild in ((True, SimpleNamespace(id=1)), (False, None)):
            item = message("https://evil.test/")
            item.author.bot, item.guild = is_bot, guild
            await self.bot.on_message(item)
        self.assertEqual(self.requests, [])

    async def test_notice_failure_does_not_prevent_deletion(self):
        self.responses["https://evil.test/"] = httpx.Response(200, json={"verdict": "MALICIOUS"})
        item = message("https://evil.test/")
        item.channel.send.side_effect = discord_error(discord.Forbidden, 403)
        with self.assertLogs("main", level="WARNING"):
            await self.bot.on_message(item)
        item.delete.assert_awaited_once()

    async def test_failed_deletion_does_not_claim_success(self):
        for error in (
            discord_error(discord.Forbidden, 403),
            discord_error(discord.NotFound, 404),
            discord_error(discord.HTTPException, 500),
        ):
            item = message("https://evil.test/")
            item.delete.side_effect = error
            await self.bot.remove_message(item)
            item.channel.send.assert_not_awaited()

    async def test_uncached_edit_is_fetched_and_moderated(self):
        self.responses["https://evil.test/"] = httpx.Response(200, json={"verdict": "MALICIOUS"})
        item = message("https://evil.test/")
        channel = SimpleNamespace(fetch_message=AsyncMock(return_value=item))
        payload = SimpleNamespace(
            guild_id=456,
            channel_id=789,
            message_id=123,
            cached_message=None,
            data={"content": item.content},
        )
        with patch.object(self.bot, "get_channel", return_value=channel):
            await self.bot.on_raw_message_edit(payload)
        channel.fetch_message.assert_awaited_once_with(123)
        item.delete.assert_awaited_once()

    async def test_edit_uses_real_pycord_message_with_guild_context(self):
        # REST message payloads may omit guild_id: the channel must supply it.
        state = self.bot._connection
        guild = discord.Guild(data={"id": "456", "name": "Test server"}, state=state)
        channel = discord.TextChannel(
            state=state,
            guild=guild,
            data={"id": "789", "type": 0, "name": "links", "position": 0},
        )
        data = {
            "id": "123",
            "channel_id": "789",
            "content": "https://evil.test/",
            "author": {"id": "321", "username": "tester", "discriminator": "0", "avatar": None},
            "attachments": [],
            "embeds": [],
            "edited_timestamp": None,
            "type": 0,
            "pinned": False,
            "mention_everyone": False,
            "tts": False,
        }
        payload = SimpleNamespace(
            guild_id=456,
            channel_id=789,
            message_id=123,
            cached_message=None,
            data={"content": data["content"]},
        )
        self.responses[data["content"]] = httpx.Response(200, json={"verdict": "MALICIOUS"})
        with (
            patch.object(self.bot, "get_channel", return_value=None),
            patch.object(self.bot, "fetch_channel", new=AsyncMock(return_value=channel)) as fetch,
            patch.object(self.bot.http, "get_message", new=AsyncMock(return_value=data)),
            patch.object(self.bot, "remove_message", new=AsyncMock()) as remove,
        ):
            await self.bot.on_raw_message_edit(payload)
        fetch.assert_awaited_once_with(789)
        remove.assert_awaited_once()
        result = remove.await_args.args[0]
        self.assertIsInstance(result, discord.Message)
        self.assertIs(result.guild, guild)

    async def test_embed_only_and_unchanged_edits_do_not_fetch(self):
        payload = SimpleNamespace(
            guild_id=456,
            channel_id=789,
            message_id=123,
            cached_message=message("https://unlisted.test/"),
            data={"embeds": []},
        )
        with patch.object(self.bot, "get_channel") as channel:
            await self.bot.on_raw_message_edit(payload)
            payload.data = {"content": payload.cached_message.content}
            await self.bot.on_raw_message_edit(payload)
            channel.assert_not_called()

    async def test_edit_fetch_failure_is_handled(self):
        payload = SimpleNamespace(
            guild_id=456,
            channel_id=789,
            message_id=123,
            cached_message=None,
            data={"content": "https://unlisted.test/"},
        )
        for error in (discord_error(discord.NotFound, 404), discord_error(discord.Forbidden, 403)):
            channel = SimpleNamespace(fetch_message=AsyncMock(side_effect=error))
            with patch.object(self.bot, "get_channel", return_value=channel):
                await self.bot.on_raw_message_edit(payload)
        self.assertEqual(self.requests, [])

    async def test_selected_mode_reaches_api(self):
        self.bot.scan_mode = "detailed"
        await self.bot.on_message(message("https://unlisted.test/"))
        self.assertEqual(json.loads(self.requests[0].content)["mode"], "detailed")

    async def test_concurrency_is_bounded(self):
        active = peak = 0

        async def scan(*args, **kwargs):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return ScanResult(verdict="SAFE")

        with patch.object(self.scanner, "scan", side_effect=scan):
            await asyncio.gather(
                *(self.bot.on_message(message("https://unlisted.test/")) for _ in range(12))
            )
        self.assertEqual(peak, 4)
