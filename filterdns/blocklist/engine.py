"""Blocklist matching engine with O(1) lookup."""

from typing import NamedTuple

import structlog

logger = structlog.get_logger()


class BlockResult(NamedTuple):
    """Result of a block check."""

    blocked: bool
    blocklist_id: str | None = None


class BlocklistEngine:
    """Engine for checking domains against blocklists.

    Uses Python sets for O(1) lookup performance.
    Maintains separate sets per blocklist ID for tracking which list blocked a domain.
    """

    def __init__(self):
        # Map of blocklist_id -> set of domains
        self._blocklists: dict[str, set[str]] = {}
        # Combined set of all blocked domains for fast initial check
        self._all_domains: set[str] = set()

    def set_blocklist(self, blocklist_id: str, domains: set[str]) -> None:
        """Set domains for a blocklist.

        Args:
            blocklist_id: Identifier for the blocklist
            domains: Set of domains to block
        """
        # Remove old domains from combined set
        if blocklist_id in self._blocklists:
            old_domains = self._blocklists[blocklist_id]
            # Only remove domains not in other lists
            for domain in old_domains:
                if not any(
                    domain in bl_domains
                    for bl_id, bl_domains in self._blocklists.items()
                    if bl_id != blocklist_id
                ):
                    self._all_domains.discard(domain)

        # Set new domains
        self._blocklists[blocklist_id] = domains
        self._all_domains.update(domains)

        logger.info(
            "Blocklist updated",
            blocklist_id=blocklist_id,
            domain_count=len(domains),
            total_domains=len(self._all_domains),
        )

    def remove_blocklist(self, blocklist_id: str) -> None:
        """Remove a blocklist.

        Args:
            blocklist_id: Identifier for the blocklist to remove
        """
        if blocklist_id in self._blocklists:
            domains = self._blocklists.pop(blocklist_id)
            # Remove domains not in other lists
            for domain in domains:
                if not any(domain in bl_domains for bl_domains in self._blocklists.values()):
                    self._all_domains.discard(domain)

            logger.info(
                "Blocklist removed",
                blocklist_id=blocklist_id,
                total_domains=len(self._all_domains),
            )

    def is_blocked(
        self,
        domain: str,
        active_blocklist_ids: set[str] | None = None,
    ) -> BlockResult:
        """Check if a domain is blocked.

        Args:
            domain: Domain to check
            active_blocklist_ids: Optional set of blocklist IDs to check against.
                                  If None, checks all blocklists.

        Returns:
            BlockResult with blocked status and blocklist ID if blocked
        """
        domain = domain.lower()

        # Quick check against combined set first
        if domain not in self._all_domains:
            # Also check parent domains (for subdomain blocking)
            parts = domain.split(".")
            found = False
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self._all_domains:
                    domain = parent
                    found = True
                    break
            if not found:
                return BlockResult(blocked=False)

        # Find which blocklist blocked it
        for blocklist_id, domains in self._blocklists.items():
            # Skip if not in active blocklists
            if active_blocklist_ids is not None and blocklist_id not in active_blocklist_ids:
                continue

            if domain in domains:
                return BlockResult(blocked=True, blocklist_id=blocklist_id)

        # Domain was in combined set but not in any active blocklist
        return BlockResult(blocked=False)

    def is_blocked_ordered(
        self,
        domain: str,
        ordered_blocklist_ids: list[str],
    ) -> BlockResult:
        """Check if domain is blocked, checking blocklists in provided order.

        First matching blocklist wins (deterministic attribution).
        This ensures consistent results when a domain appears in multiple blocklists.

        Args:
            domain: Domain to check
            ordered_blocklist_ids: List of blocklist IDs to check, in order.
                                   First match wins.

        Returns:
            BlockResult with blocked status and blocklist ID if blocked
        """
        domain = domain.lower()

        # Check each blocklist in order
        for blocklist_id in ordered_blocklist_ids:
            if blocklist_id not in self._blocklists:
                continue

            blocklist_domains = self._blocklists[blocklist_id]

            # Check exact match
            if domain in blocklist_domains:
                return BlockResult(blocked=True, blocklist_id=blocklist_id)

            # Check parent domains (for subdomain blocking)
            parts = domain.split(".")
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in blocklist_domains:
                    return BlockResult(blocked=True, blocklist_id=blocklist_id)

        return BlockResult(blocked=False)

    def is_domain_in_blocklist(self, domain: str, blocklist_id: str) -> bool:
        """Check if a domain is in a specific blocklist (with subdomain matching).

        Args:
            domain: Domain to check
            blocklist_id: Blocklist ID to check against

        Returns:
            True if domain or any parent is in the blocklist
        """
        if blocklist_id not in self._blocklists:
            return False

        domain = domain.lower()
        blocklist_domains = self._blocklists[blocklist_id]

        # Check exact match
        if domain in blocklist_domains:
            return True

        # Check parent domains
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in blocklist_domains:
                return True

        return False

    def get_blocklist_ids(self) -> list[str]:
        """Get list of loaded blocklist IDs."""
        return list(self._blocklists.keys())

    def get_total_domains(self) -> int:
        """Get total number of unique blocked domains."""
        return len(self._all_domains)

    def get_blocklist_size(self, blocklist_id: str) -> int:
        """Get number of domains in a specific blocklist."""
        return len(self._blocklists.get(blocklist_id, set()))

    def clear(self) -> None:
        """Clear all blocklists."""
        self._blocklists.clear()
        self._all_domains.clear()
        logger.info("All blocklists cleared")


# Global engine instance
_engine: BlocklistEngine | None = None


def get_engine() -> BlocklistEngine:
    """Get the global blocklist engine instance."""
    global _engine
    if _engine is None:
        _engine = BlocklistEngine()
    return _engine
