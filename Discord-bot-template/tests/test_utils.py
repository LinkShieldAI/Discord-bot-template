import tempfile
import unittest
from pathlib import Path

from utils import extract_links, is_allowlisted, load_safe_domains


class AllowlistTests(unittest.TestCase):
    def test_exact_hostname_matching(self):
        for url in (
            "https://example.com/path?x=1&y=2",
            "HTTP://EXAMPLE.COM/",
            "https://example.com.:443/",
        ):
            with self.subTest(url=url):
                self.assertTrue(is_allowlisted(url, {"example.com"}))

    def test_untrusted_hosts_and_ambiguous_urls_cannot_bypass_scanning(self):
        for url in (
            "https://example.com.evil.test/",
            "https://notexample.com/",
            "https://www.example.com/",
            "https://example.com@evil.test/",
            "https://evil.test/?next=https://example.com",
            "https://evil.test/#example.com",
            "https://evil.test\\@example.com/",
            "https://user@example.com/",
            "https://ｅxample.com/",
            "https://exаmple.com/",  # Cyrillic a.
            "https://example.com../",
            "https://example.com:invalid/",
            "https://example.com:99999/",
            "https://exam\nple.com/",
            "https://[broken/",
            "https://%65xample.com/",
            "ftp://example.com/",
            "example.com",
        ):
            with self.subTest(url=url):
                self.assertFalse(is_allowlisted(url, {"example.com"}))

    def test_file_comments_duplicates_and_case(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts.txt"
            path.write_text(
                "\ufeff# Trusted hosts\nEXAMPLE.COM. # comment\n\nexample.com\n", encoding="utf-8"
            )
            self.assertEqual(load_safe_domains(path), {"example.com"})

    def test_missing_and_invalid_files_stop_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts.txt"
            with self.assertRaises(FileNotFoundError):
                load_safe_domains(path)
            for entry in ("https://example.com", "*.example.com", "example.com/path", "a..com"):
                path.write_text(entry, encoding="utf-8")
                with self.subTest(entry=entry), self.assertRaisesRegex(ValueError, "hosts.txt:1"):
                    load_safe_domains(path)

    def test_empty_file_disables_bypass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts.txt"
            path.write_text("# Nothing trusted\n", encoding="utf-8")
            self.assertEqual(load_safe_domains(path), set())

    def test_shipped_list_loads(self):
        domains = load_safe_domains(Path(__file__).resolve().parents[1] / "common_safe_domains.txt")
        self.assertIn("google.com", domains)
        self.assertIn("discord.com", domains)


class ExtractionTests(unittest.TestCase):
    def test_userinfo_punctuation_cannot_hide_the_destination(self):
        for punctuation in ("'", '"', "`", "|", ")", "]", "}"):
            url = f"https://google.com{punctuation}@attacker.test/payload"
            for text in (url, f"[Click]({url})", f"<{url}>"):
                with self.subTest(text=text):
                    self.assertEqual(extract_links(text), [url])
                    self.assertFalse(is_allowlisted(extract_links(text)[0], {"google.com"}))

    def test_apostrophe_in_path_is_preserved(self):
        url = "https://unlisted.test/it's-a-page?name=O'Brien"
        self.assertEqual(extract_links(f"[Page]({url})"), [url])

    def test_explicit_autolink_preserves_punctuation_in_path(self):
        url = "https://unlisted.test/path)with-punctuation!"
        self.assertEqual(extract_links(f"<{url}>"), [url])

    def test_matching_quote_and_spoiler_wrappers_are_removed(self):
        url = "https://unlisted.test/page"
        for wrapper in ("'", '"', "`", "||"):
            with self.subTest(wrapper=wrapper):
                self.assertEqual(extract_links(f"{wrapper}{url}{wrapper}"), [url])

    def test_discord_formatting_and_deduplication(self):
        text = "<https://one.test/> [label](https://two.test/a?x=1&y=2). https://one.test/"
        self.assertEqual(extract_links(text), ["https://one.test/", "https://two.test/a?x=1&y=2"])

    def test_adjacent_markdown_links_do_not_hide_second_destination(self):
        text = "[trusted](https://example.com/)[click](https://evil.test/path)"
        self.assertEqual(extract_links(text), ["https://example.com/", "https://evil.test/path"])

    def test_balanced_path_and_ipv6(self):
        text = "(https://en.wikipedia.org/wiki/Foo_(bar)). <http://[::1]:8080/path>"
        self.assertEqual(
            extract_links(text),
            ["https://en.wikipedia.org/wiki/Foo_(bar)", "http://[::1]:8080/path"],
        )

    def test_nested_url_keeps_original_query_intact(self):
        url = "https://outer.test/?next=https://inner.test/path&x=1"
        self.assertEqual(extract_links(url), [url, "https://inner.test/path&x=1"])

    def test_uppercase_and_no_scheme(self):
        self.assertEqual(
            extract_links("HTTPS://EXAMPLE.COM/a! example.org ftp://files.test"),
            ["HTTPS://EXAMPLE.COM/a"],
        )
