"""Blocklist format parsers.

Supports multiple formats:
- Hosts format: `0.0.0.0 domain.com` or `127.0.0.1 domain.com`
- Domain list: One domain per line
- Adblock format: `||domain.com^` with optional modifiers
- Wildcard format: `*.domain.com` (OISD style)
"""

import re
from typing import Iterator

import structlog

logger = structlog.get_logger()

# Regex patterns for different formats
HOSTS_PATTERN = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9][\w.-]+\.[a-z]{2,})", re.I)
ADBLOCK_PATTERN = re.compile(r"^\|\|([a-z0-9][\w.-]+\.[a-z]{2,})\^?(?:\$.*)?$", re.I)
DOMAIN_PATTERN = re.compile(r"^([a-z0-9][\w.-]+\.[a-z]{2,})$", re.I)
WILDCARD_PATTERN = re.compile(r"^\*\.([a-z0-9][\w.-]+\.[a-z]{2,})$", re.I)

# Domains to skip (localhost, local, etc.)
SKIP_DOMAINS = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "0.0.0.0",
}


def parse_line(line: str) -> str | None:
    """Parse a single line and extract domain if valid.

    Args:
        line: Raw line from blocklist file

    Returns:
        Domain name or None if not a valid entry
    """
    # Strip whitespace and skip empty lines
    line = line.strip()
    if not line:
        return None

    # Skip comments (various formats)
    if line.startswith("#") or line.startswith("!") or line.startswith("//") or line.startswith(";"):
        return None

    # Skip adblock exception rules (@@||domain^)
    if line.startswith("@@"):
        return None

    # Skip cosmetic/element hiding filters
    if "##" in line or "#@#" in line:
        return None

    # Strip inline comments
    if " #" in line:
        line = line.split(" #")[0].strip()

    # Try hosts format first (most common)
    match = HOSTS_PATTERN.match(line)
    if match:
        domain = match.group(1).lower()
        if domain not in SKIP_DOMAINS:
            return domain
        return None

    # Try adblock format (||domain^ with optional modifiers like $third-party)
    match = ADBLOCK_PATTERN.match(line)
    if match:
        return match.group(1).lower()

    # Try wildcard format (*.domain.com)
    match = WILDCARD_PATTERN.match(line)
    if match:
        return match.group(1).lower()

    # Try plain domain format
    match = DOMAIN_PATTERN.match(line)
    if match:
        domain = match.group(1).lower()
        if domain not in SKIP_DOMAINS:
            return domain

    return None


def parse_blocklist(content: str) -> set[str]:
    """Parse blocklist content and extract all domains.

    Args:
        content: Raw blocklist file content

    Returns:
        Set of unique domain names
    """
    domains = set()
    for line in content.splitlines():
        domain = parse_line(line)
        if domain:
            domains.add(domain)
    return domains


def parse_blocklist_iter(content: str) -> Iterator[str]:
    """Parse blocklist content and yield domains one by one.

    Memory-efficient version for large files.

    Args:
        content: Raw blocklist file content

    Yields:
        Domain names
    """
    seen = set()
    for line in content.splitlines():
        domain = parse_line(line)
        if domain and domain not in seen:
            seen.add(domain)
            yield domain
