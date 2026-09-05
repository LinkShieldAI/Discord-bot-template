"""URL extraction and local allowlist matching. These helpers make no requests."""

import re
from pathlib import Path
from urllib.parse import urlsplit

# Handles explicit HTTP(S) links, including <autolinks> and Markdown destinations.
# Lookahead also finds adjacent Markdown links and URLs nested in query strings.
URL_PATTERN = re.compile(r"(?=(https?://[^\s<>]+))", re.IGNORECASE)
AUTHORITY_PATTERN = re.compile(r"https?://[^/?#]*", re.IGNORECASE)
HOST_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


def extract_links(text: str) -> list[str]:
    """Return distinct URLs in message order, removing surrounding punctuation."""
    links = []
    for match in URL_PATTERN.finditer(text):
        url = match.group(1)
        # Angle brackets explicitly delimit a URL; preserve everything inside them.
        prefix = text[: match.start()]
        if prefix.endswith("<"):
            if url not in links:
                links.append(url)
            continue
        # Remove paired message formatting, never punctuation inside a URL.
        if prefix.endswith("||") and url.endswith("||"):
            url = url[:-2]
        elif prefix and prefix[-1] in "\"'`" and url.endswith(prefix[-1]):
            url = url[:-1]

        # Punctuation in userinfo must not hide the real host after @.
        # Inspect the whole authority before trimming any Markdown delimiters.
        userinfo_end = AUTHORITY_PATTERN.match(url).group().rfind("@")
        # Preserve balanced parentheses in paths, e.g. Wikipedia's /wiki/Foo_(bar).
        for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
            depth = 0
            for index, character in enumerate(url):
                if index <= userinfo_end:
                    continue
                if character == opening:
                    depth += 1
                elif character == closing:
                    if depth == 0:
                        url = url[:index]
                        break
                    depth -= 1
        url = url.rstrip(".,!;:")
        if url and url not in links:
            links.append(url)
    return links


def load_safe_domains(path: Path) -> set[str]:
    """Load exact ASCII hostnames; a missing or invalid file stops startup."""
    domains = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        domain = line.split("#", 1)[0].strip().lower().removesuffix(".")
        if not domain:
            continue
        if len(domain) > 253 or not all(
            HOST_PATTERN.fullmatch(label) for label in domain.split(".")
        ):
            raise ValueError(
                f"{path.name}:{line_number}: expected a hostname, not a URL or wildcard."
            )
        domains.add(domain)
    return domains


def is_allowlisted(url: str, safe_domains: set[str]) -> bool:
    """Match the actual hostname exactly, never text elsewhere in a URL."""
    # Backslashes and control characters can be interpreted differently by browsers.
    if "\\" in url or any(ord(character) <= 32 or ord(character) == 127 for character in url):
        return False
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return False
        if parsed.username is not None or parsed.password is not None:
            return False
        _ = parsed.port  # Reject malformed and out-of-range ports.
        hostname = parsed.hostname.lower().removesuffix(".")
    except ValueError:
        return False
    # Unicode hosts are submitted for scanning; no lossy Unicode-to-ASCII folding.
    return hostname.isascii() and hostname in safe_domains
