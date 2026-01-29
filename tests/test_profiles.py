"""Tests for presets (formerly restriction profiles)."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from filterdns.blocklist.engine import BlocklistEngine
from filterdns.profiles.loader import (
    load_all_presets_into_engine,
    load_builtin_presets,
    preset_blocklist_id,
    reload_preset_in_engine,
    remove_preset_from_engine,
)


class TestPresetBlocklistId:
    """Tests for preset blocklist ID generation."""

    def test_preset_blocklist_id(self):
        """Test blocklist ID generation for presets."""
        assert preset_blocklist_id("windows-updates") == "preset_windows-updates"
        assert preset_blocklist_id("samsung-tv") == "preset_samsung-tv"


class TestLoadBuiltinPresets:
    """Tests for loading built-in presets."""

    @pytest.mark.asyncio
    async def test_load_builtin_presets_file_not_found(self):
        """Test handling of missing presets file."""
        engine = BlocklistEngine()
        count = await load_builtin_presets(
            engine, presets_path=Path("/nonexistent/path.yaml")
        )
        assert count == 0

    @pytest.mark.asyncio
    async def test_load_builtin_presets_from_yaml(self, tmp_path):
        """Test loading presets from YAML file."""
        # Create test YAML file
        yaml_content = """
presets:
  - id: test-preset
    name: Test Preset
    category: test
    description: A test preset
    domains:
      - blocked.example.com
      - ads.test.com
"""
        yaml_file = tmp_path / "presets.yaml"
        yaml_file.write_text(yaml_content)

        engine = BlocklistEngine()

        with patch("filterdns.profiles.loader.queries") as mock_queries:
            mock_queries.preset_exists = AsyncMock(return_value=False)
            mock_queries.create_preset = AsyncMock()
            mock_queries.set_preset_domains = AsyncMock()

            count = await load_builtin_presets(engine, presets_path=yaml_file)

            assert count == 1
            mock_queries.create_preset.assert_called_once()
            mock_queries.set_preset_domains.assert_called_once()

            # Check engine has the preset loaded
            assert "preset_test-preset" in engine.get_blocklist_ids()

    @pytest.mark.asyncio
    async def test_load_builtin_presets_idempotent(self, tmp_path):
        """Test that loading presets is idempotent (doesn't recreate existing)."""
        yaml_content = """
presets:
  - id: existing-preset
    name: Existing Preset
    category: test
    domains:
      - example.com
"""
        yaml_file = tmp_path / "presets.yaml"
        yaml_file.write_text(yaml_content)

        engine = BlocklistEngine()

        with patch("filterdns.profiles.loader.queries") as mock_queries:
            # Preset already exists
            mock_queries.preset_exists = AsyncMock(return_value=True)
            mock_queries.create_preset = AsyncMock()

            count = await load_builtin_presets(engine, presets_path=yaml_file)

            assert count == 1
            # Should not create since it exists
            mock_queries.create_preset.assert_not_called()


class TestLoadAllPresetsIntoEngine:
    """Tests for loading all presets from DB into engine."""

    @pytest.mark.asyncio
    async def test_load_all_presets(self):
        """Test loading all presets from DB."""
        engine = BlocklistEngine()

        with patch("filterdns.profiles.loader.queries") as mock_queries:
            mock_queries.get_all_preset_domains = AsyncMock(
                return_value={
                    "preset-1": {"domain1.com", "domain2.com"},
                    "preset-2": {"domain3.com"},
                }
            )

            count = await load_all_presets_into_engine(engine)

            assert count == 2
            assert "preset_preset-1" in engine.get_blocklist_ids()
            assert "preset_preset-2" in engine.get_blocklist_ids()


class TestReloadPresetInEngine:
    """Tests for reloading a preset in the engine."""

    @pytest.mark.asyncio
    async def test_reload_preset(self):
        """Test reloading a preset's domains."""
        engine = BlocklistEngine()
        engine.set_blocklist("preset_test", {"old-domain.com"})

        with patch("filterdns.profiles.loader.queries") as mock_queries:
            mock_queries.get_preset_domains = AsyncMock(
                return_value=["new-domain.com", "another.com"]
            )

            await reload_preset_in_engine(engine, "test")

            # Check domains were updated
            result = engine.is_blocked("new-domain.com", {"preset_test"})
            assert result.blocked is True

            result = engine.is_blocked("old-domain.com", {"preset_test"})
            assert result.blocked is False


class TestRemovePresetFromEngine:
    """Tests for removing a preset from the engine."""

    def test_remove_preset(self):
        """Test removing a preset from the engine."""
        engine = BlocklistEngine()
        engine.set_blocklist("preset_test", {"domain.com"})

        remove_preset_from_engine(engine, "test")

        assert "preset_test" not in engine.get_blocklist_ids()

    def test_remove_nonexistent_preset(self):
        """Test removing a preset that doesn't exist (should not error)."""
        engine = BlocklistEngine()
        # Should not raise
        remove_preset_from_engine(engine, "nonexistent")


class TestBlocklistEngineOrderedLookup:
    """Tests for the ordered blocklist lookup used by presets."""

    def test_is_blocked_ordered_first_match_wins(self):
        """Test that first matching blocklist in order wins."""
        engine = BlocklistEngine()
        engine.set_blocklist("preset_a", {"shared.com", "only-a.com"})
        engine.set_blocklist("preset_b", {"shared.com", "only-b.com"})

        # Test with order [a, b] - should return preset_a
        result = engine.is_blocked_ordered("shared.com", ["preset_a", "preset_b"])
        assert result.blocked is True
        assert result.blocklist_id == "preset_a"

        # Test with order [b, a] - should return preset_b
        result = engine.is_blocked_ordered("shared.com", ["preset_b", "preset_a"])
        assert result.blocked is True
        assert result.blocklist_id == "preset_b"

    def test_is_blocked_ordered_subdomain_matching(self):
        """Test subdomain matching in ordered lookup."""
        engine = BlocklistEngine()
        engine.set_blocklist("preset_test", {"example.com"})

        result = engine.is_blocked_ordered("sub.example.com", ["preset_test"])
        assert result.blocked is True
        assert result.blocklist_id == "preset_test"

    def test_is_blocked_ordered_not_found(self):
        """Test when domain is not blocked by any list."""
        engine = BlocklistEngine()
        engine.set_blocklist("preset_test", {"blocked.com"})

        result = engine.is_blocked_ordered("allowed.com", ["preset_test"])
        assert result.blocked is False
        assert result.blocklist_id is None

    def test_is_blocked_ordered_empty_list(self):
        """Test with empty blocklist list."""
        engine = BlocklistEngine()

        result = engine.is_blocked_ordered("example.com", [])
        assert result.blocked is False

    def test_is_blocked_ordered_skips_missing_lists(self):
        """Test that missing blocklist IDs are skipped."""
        engine = BlocklistEngine()
        engine.set_blocklist("preset_exists", {"blocked.com"})

        result = engine.is_blocked_ordered(
            "blocked.com", ["preset_nonexistent", "preset_exists"]
        )
        assert result.blocked is True
        assert result.blocklist_id == "preset_exists"
