import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
from linkshieldai import AsyncLinkShieldAI, ScanResult
from test_bot import message

from main import LinkShieldBot


class CacheTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []
        self.response = httpx.Response(200, json={"verdict": "MALICIOUS"})

        def handle(request):
            self.requests.append(json.loads(request.content))
            if isinstance(self.response, Exception):
                raise self.response
            return self.response

        self.http = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        self.scanner = AsyncLinkShieldAI(api_key="test-key", client=self.http, max_retries=0)
        self.bot = LinkShieldBot(self.scanner, set())

    async def asyncTearDown(self):
        await self.bot.close()
        await self.scanner.close()
        await self.http.aclose()

    async def test_repeat_malicious_url_deletes_without_another_request(self):
        first = message("https://bad.test/path?token=abc")
        second = message(first.content)
        await self.bot.on_message(first)
        with self.assertLogs("main", level="INFO") as logs:
            await self.bot.on_message(second)
        first.delete.assert_awaited_once()
        second.delete.assert_awaited_once()
        self.assertEqual(len(self.requests), 1)
        self.assertTrue(any("cached" in entry.lower() for entry in logs.output))
        self.assertFalse(any("token=abc" in entry for entry in logs.output))

    async def test_cache_hit_does_not_extend_six_hour_expiry(self):
        url = "https://bad.test/"
        with patch("main.monotonic", return_value=100.0) as clock:
            await self.bot.on_message(message(url))
            clock.return_value = 100.0 + 5 * 60 * 60
            await self.bot.on_message(message(url))
            self.assertEqual(len(self.requests), 1)
            clock.return_value = 100.0 + 6 * 60 * 60
            self.response = httpx.Response(200, json={"verdict": "SAFE"})
            corrected = message(url)
            await self.bot.on_message(corrected)
            self.assertEqual(len(self.requests), 2)
            corrected.delete.assert_not_awaited()

    async def test_cache_key_uses_the_full_url_and_scan_mode(self):
        url = "https://host.test/bad?x=1#one"
        await self.bot.on_message(message(url))
        self.response = httpx.Response(200, json={"verdict": "SAFE"})
        variants = [
            "https://host.test/other?x=1#one",
            "https://host.test/bad?x=2#one",
            "https://host.test/bad?x=1#two",
            "http://host.test/bad?x=1#one",
        ]
        for variant in variants:
            item = message(variant)
            await self.bot.on_message(item)
            item.delete.assert_not_awaited()
        self.bot.scan_mode = "standard"
        item = message(url)
        await self.bot.on_message(item)
        item.delete.assert_not_awaited()
        self.assertEqual([request["url"] for request in self.requests], [url, *variants, url])
        self.assertEqual(self.requests[-1]["mode"], "standard")

    async def test_safe_unknown_and_unexpected_verdicts_are_not_cached(self):
        for index, verdict in enumerate(("SAFE", "UNKNOWN", "UNRECOGNIZED")):
            url = f"https://changing.test/{index}"
            self.response = httpx.Response(200, json={"verdict": verdict})
            await self.bot.on_message(message(url))
            self.response = httpx.Response(200, json={"verdict": "MALICIOUS"})
            item = message(url)
            await self.bot.on_message(item)
            item.delete.assert_awaited_once()
        self.assertEqual(len(self.requests), 6)

    async def test_errors_are_not_cached(self):
        for index, failure in enumerate(
            (
                httpx.Response(503, json={"error": {"code": "UNAVAILABLE"}}),
                httpx.ReadTimeout("offline"),
            )
        ):
            url = f"https://retry.test/{index}"
            self.response = failure
            with self.assertLogs("main", level="WARNING"):
                await self.bot.on_message(message(url))
            self.response = httpx.Response(200, json={"verdict": "MALICIOUS"})
            item = message(url)
            await self.bot.on_message(item)
            item.delete.assert_awaited_once()
        self.assertEqual(len(self.requests), 4)

    async def test_cached_second_link_is_removed_before_waiting_on_first(self):
        url = "https://known-bad.test/"
        await self.bot.on_message(message(url))
        for _ in range(4):
            await self.bot.scan_slots.acquire()
        try:
            item = message(f"https://not-yet-scanned.test/ {url}")
            await asyncio.wait_for(self.bot.on_message(item), timeout=1)
            item.delete.assert_awaited_once()
            self.assertEqual(len(self.requests), 1)
        finally:
            for _ in range(4):
                self.bot.scan_slots.release()

    async def test_allowlist_takes_precedence_over_cached_verdict(self):
        url = "https://exempt.test/path"
        await self.bot.on_message(message(url))
        self.bot.safe_domains.add("exempt.test")
        item = message(url)
        await self.bot.on_message(item)
        item.delete.assert_not_awaited()
        self.assertEqual(len(self.requests), 1)

    async def test_queued_duplicate_reuses_result_after_getting_a_scan_slot(self):
        self.bot.scan_slots = asyncio.Semaphore(0)
        tasks = [asyncio.create_task(self.bot.scan_url("https://bad.test/")) for _ in range(2)]
        try:
            await asyncio.sleep(0)  # Both requests start with an empty cache and wait.
            self.assertTrue(all(not task.done() for task in tasks))
            self.assertEqual(self.requests, [])
            self.bot.scan_slots.release()
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=1)
            self.assertEqual([result.verdict for result in results], ["MALICIOUS", "MALICIOUS"])
            self.assertEqual(len(self.requests), 1)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_later_safe_response_clears_concurrent_malicious_result(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def delayed_safe(url, **kwargs):
            started.set()
            await release.wait()
            return ScanResult(verdict="SAFE")

        url = "https://corrected.test/"
        with patch.object(self.scanner, "scan", side_effect=delayed_safe):
            task = asyncio.create_task(self.bot.scan_url(url))
            try:
                await asyncio.wait_for(started.wait(), timeout=1)
                self.bot.cache_result(url, "deep", ScanResult(verdict="MALICIOUS"))
                release.set()
                await asyncio.wait_for(task, timeout=1)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        self.response = httpx.Response(200, json={"verdict": "SAFE"})
        item = message(url)
        await self.bot.on_message(item)
        self.assertEqual(len(self.requests), 1)
        item.delete.assert_not_awaited()

    async def test_edited_message_uses_cached_verdict(self):
        url = "https://bad.test/"
        await self.bot.on_message(message(url))
        edited = message(f"Updated message: {url}")
        channel = SimpleNamespace(fetch_message=AsyncMock(return_value=edited))
        payload = SimpleNamespace(
            guild_id=edited.guild.id,
            message_id=edited.id,
            channel_id=789,
            cached_message=None,
            data={"content": edited.content},
        )
        with patch.object(self.bot, "get_channel", return_value=channel):
            await self.bot.on_raw_message_edit(payload)
        edited.delete.assert_awaited_once()
        self.assertEqual(len(self.requests), 1)

    async def test_new_bot_instance_starts_with_an_empty_cache(self):
        url = "https://bad.test/"
        await self.bot.on_message(message(url))
        async with LinkShieldBot(self.scanner, set()) as restarted:
            await restarted.on_message(message(url))
        self.assertEqual(len(self.requests), 2)

    async def test_cache_is_limited_to_1000_entries_with_lru_eviction(self):
        result = ScanResult(verdict="MALICIOUS")
        for index in range(1000):
            self.bot.cache_result(f"https://bad.test/{index}", "deep", result)
        self.assertIsNotNone(self.bot.cached_result("https://bad.test/0", "deep"))
        self.bot.cache_result("https://bad.test/1000", "deep", result)
        self.assertEqual(len(self.bot.malicious_cache), 1000)
        self.assertIsNone(self.bot.cached_result("https://bad.test/1", "deep"))
        self.assertIsNotNone(self.bot.cached_result("https://bad.test/0", "deep"))
        self.assertIsNotNone(self.bot.cached_result("https://bad.test/1000", "deep"))

    async def test_expired_entries_are_purged_before_evicting_fresh_results(self):
        result = ScanResult(verdict="MALICIOUS")
        with patch("main.monotonic", return_value=0.0) as clock:
            self.bot.cache_result("https://expired.test/", "deep", result)
            clock.return_value = 1000.0
            self.bot.cache_result("https://fresh.test/", "deep", result)
            self.bot.cached_result("https://expired.test/", "deep")
            clock.return_value = 6 * 60 * 60
            self.bot.cache_result("https://new.test/", "deep", result)
            self.assertEqual(len(self.bot.malicious_cache), 2)
            self.assertIsNone(self.bot.cached_result("https://expired.test/", "deep"))
            self.assertIsNotNone(self.bot.cached_result("https://fresh.test/", "deep"))
