# LinkShieldAI Discord Bot Template

A small, readable Python example for building your own Discord bot with the [LinkShieldAI API](https://docs.linkshieldai.com/#v1-scan). It skips locally allowlisted hosts, scans other links, and deletes messages when the API returns `MALICIOUS`.

This repository is an API integration template. The [hosted LinkShieldAI Discord bot](https://linkshieldai.com) is a separate product.

## How it works

```text
New or edited server message
  → Extract distinct HTTP(S) URLs
  → Skip exact hosts in common_safe_domains.txt
  → Delete immediately if any remaining URL has a cached MALICIOUS verdict
  → Scan remaining URLs with the async Python SDK
  → Delete the message on the first MALICIOUS verdict
```

The API call at the center of the bot is:

```python
result = await scanner.scan(url, mode="deep")
if result.verdict == "MALICIOUS":
    await message.delete()
```

The SDK sends `POST https://api.linkshieldai.com/v1/scan`, with the URL in JSON and the key in the Bearer authentication header. See the [v1 contract](https://docs.linkshieldai.com/#v1-scan) and [Python SDK](https://pypi.org/project/linkshieldai/0.3.1/).

## Quick start

Use **Python 3.10–3.14**, a Discord bot token, and a LinkShieldAI API key.

### 1. Set up your accounts

Create an application and bot in the [Discord Developer Portal](https://discord.com/developers/applications). On the **Bot** page, enable **Message Content Intent** and obtain the bot token. The code enables the corresponding intent too; see [Pycord's intent guide](https://docs.pycord.dev/en/stable/intents.html).

Invite the bot using a **Guild Install** / **bot** installation link. Give it these permissions in the channels you want to moderate:

| Permission | Purpose |
| --- | --- |
| View Channels | Receive messages in the channel. |
| Read Message History | Retrieve edited messages, including older ones. |
| Manage Messages | Delete messages containing malicious links. |
| Send Messages | Post the brief removal notice. |
| Send Messages in Threads | Post notices inside threads, if used. |

Channel overrides also apply. Administrator permission is unnecessary. See [Discord's permission reference](https://docs.discord.com/developers/topics/permissions).

Create a free account in the [LinkShieldAI Developer Portal](https://developer.linkshieldai.com/portal.php?signup=1) and get your API key there.

### 2. Install

Clone your copy of this repository, or extract its ZIP, and open a terminal in that directory.

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

**Windows PowerShell**

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

The Discord library is **Pycord** (`py-cord`), imported as `discord`. Use a fresh virtual environment to avoid conflicts with other libraries sharing that import name.

### 3. Configure and run

Fill in `.env`:

```dotenv
DISCORD_TOKEN=your_discord_bot_token
LINKSHIELDAI_API_KEY=your_linkshieldai_api_key
SCAN_MODE=deep
```

Run `python main.py` in the activated macOS/Linux environment, or `.\.venv\Scripts\python.exe main.py` on Windows. Stop with **Ctrl+C**.

Existing environment variables take precedence over `.env`. Both `.env` and the allowlist are loaded relative to `main.py`, so starting from another working directory is supported. Credentials are required at startup; `.env` is excluded from Git.

`SCAN_MODE` is optional and defaults to `deep`. If upgrading an existing installation, change its `.env` or environment setting to `SCAN_MODE=deep`, or remove that setting to use the default.

## Configure the allowlist

`common_safe_domains.txt` is a local **scan bypass**, shared across all servers using this bot. Entries are loaded once at startup. Use one exact ASCII hostname per line; blank lines and `#` comments are supported:

```text
example.com
www.example.com  # Add subdomains explicitly
```

With only `example.com` listed:

| URL | Action |
| --- | --- |
| `https://example.com/docs` | Skip the API call. |
| `https://EXAMPLE.COM.:443/docs` | Skip; case and one trailing DNS dot are normalized. |
| `https://www.example.com/docs` | Scan; the subdomain is not listed. |
| `https://example.com.evil.test/` | Scan; the actual host is different. |
| `https://example.com@evil.test/` | Scan; credentials do not establish trust. |

Paths, queries, and fragments do not establish an allowlist match. Unicode hosts, userinfo, malformed ports, and ambiguous backslash URLs never bypass scanning. Use ASCII/Punycode hostnames in the file; wildcards and full URLs are rejected.

**Review the inherited list before using it.** Its original entries are retained for compatibility, including shorteners and services that host user content. Listing a host bypasses checks for every path on it, including redirect URLs; popularity is not a safety guarantee. Remove any host you want the API to check. To scan everything, empty the file. Restart after editing it. A missing or invalid file stops startup with an error.

## Moderation behavior

| Outcome | Bot behavior |
| --- | --- |
| Allowlisted host | No scan request for that URL. |
| Cached `MALICIOUS` | Delete the entire message without another API request. |
| `MALICIOUS` | Delete the entire message, then try to post a notice for 10 seconds. |
| `SAFE` | Leave the message. |
| `UNKNOWN` / unexpected verdict | Leave the message and log the inconclusive scan. |
| API failure or timeout | Log the failure, leave that decision unresolved, and continue checking other URLs. |
| Moderation at capacity | Log the skipped message and leave it unscanned; no public safety verdict or automatic retry. |

`UNKNOWN` is not evidence of safety. This example deletes only explicit malicious results. A failure does not produce a public “safe” message.

The bot handles new messages and content edits, skips DMs and bot/webhook authors, and ignores embed-only edits. A failed notice cannot prevent deletion; a failed deletion never produces a success notice. Logs identify message IDs without copying message content or submitted links.

One shared async SDK client handles requests. It has a 10-second request timeout and up to two retries. Each URL gets a **35-second total deadline, including waiting for a scan slot and API retries**. At most four scans run concurrently, and at most 32 message handlers are admitted across new messages and edits, including active and waiting work. Edits count toward this limit before retrieving their content from Discord.

When all 32 places are occupied, additional messages are logged and left unscanned, even if they contain a cached URL. A URL that reaches its deadline is logged as a failed scan; the bot then checks any remaining URLs in that admitted message. Timeouts, errors, and cancellation release capacity. These limits keep slow scans from building an unbounded backlog; they do not guarantee coverage during overload. There is no persistent queue or automatic replay of skipped messages. The limits are named constants near the top of `main.py`.

The extractor recognizes explicit `http://` and `https://` links, common Markdown links, and angle-bracket links. It trims surrounding formatting, preserves balanced parentheses and punctuation inside userinfo, and also checks explicit URLs nested inside other URLs. For example, `https://google.com'@attacker.test/payload` is submitted in full rather than shortened to an allowlisted prefix. Angle-bracket URLs are preserved verbatim. It does not inspect attachments, QR codes, bare domains, or deliberately obfuscated text. The bot never opens submitted URLs itself. `SCAN_MODE=deep` is the default; `standard` and `detailed` are also accepted. See the [API mode descriptions](https://docs.linkshieldai.com/#v1-scan) for redirect and analysis coverage.

## Malicious URL cache

Confirmed `MALICIOUS` results are cached for **six hours**. Reposting the same URL lets the bot proceed directly to Discord deletion, without waiting for another API scan. The first occurrence still needs a scan, and Discord's response time still affects deletion. Every non-allowlisted URL in a message is checked against the cache before scanning, so a cached malicious second link does not wait behind an uncached first link.

- The key is the **exact extracted URL and scan mode**, including its path, query, and fragment. A verdict for one URL does not block other pages on that host.
- Expiry is measured from the completed scan. Cache hits do not extend it.
- Each bot process keeps at most **1,000 entries in memory**, shared across its servers. Expired entries are removed before insertion; when full, the least recently used entry is evicted. Restarting clears the cache.
- `SAFE`, `UNKNOWN`, unexpected verdicts, and errors are never cached. If an already-running scan returns `SAFE`, it clears any cached malicious verdict for that URL and mode.
- The allowlist is checked first and retains its exemptions. The 32-message moderation limit still applies.

A corrected verdict may take up to six hours to be picked up for a cached URL; restart the bot to clear its cache sooner. Adjust `MALICIOUS_CACHE_TTL` (seconds) and `MALICIOUS_CACHE_MAX_ENTRIES` near the top of `main.py` to change these defaults. No database or extra setup is needed.

## Adapt the example

| File | Responsibility |
| --- | --- |
| `main.py` | Configuration, SDK lifecycle, Discord events, malicious URL cache, moderation action. |
| `utils.py` | URL extraction and exact allowlist matching. |
| `common_safe_domains.txt` | Hosts you choose to exempt. |
| `tests/` | Offline SDK request and moderation regression tests. |

Change `remove_message()` to customize notices or add a moderator log channel. If integrating into an existing bot, reuse `moderate_message()` and route its message events through it. Keep the allowlist check before `scanner.scan()`.

This refresh keeps automatic moderation as the single example. The legacy `/scan`, `/results_guide`, `/set_logs`, per-server JSON configuration, and owner join DMs were removed. Old hardcoded credentials move to `.env`; the entry point is `main.py`. Previously registered slash commands on an existing Discord application may need to be removed separately.

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python -m ruff check .
python -m ruff format --check .
```

On Windows, use `.\.venv\Scripts\python.exe` in place of `python`. Tests use the real SDK with an HTTP mock transport and mocked Discord actions. They need no credentials, use no API quota, and send or delete no Discord messages. GitHub Actions runs the checks on Python 3.10, 3.12, and 3.14.

For a live check, use your own test server: confirm an allowlisted URL is skipped, try an unlisted URL, and edit a message to another URL. The offline tests cover malicious deletion without sharing a real malicious link.

If nothing is scanned, check Message Content Intent, channel visibility, the allowlist, and whether the author is a bot. If deletion fails, check Manage Messages and channel overrides. For API failures, check the key and usage in the Developer Portal and inspect the logged error type.

Contributions that keep the example understandable are welcome. Include a regression test for changes to scanning or moderation.

## AI assistance

This template was written with the assistance of AI. AI may be used within certain LinkShieldAI products. However, AI has never had access to, contributed to, or been used to develop LinkShieldAI's private internal detection system code, and it **never will**.

## License

[MIT](LICENSE).
