"""Preset loader for FilterDNS presets (predefined blocking rule sets).

Naming convention:
- Preset: A predefined blocking rule set (e.g., "block-social-media")
  Previously called "restriction profile" or just "profile"
- Profile: A DNS filtering configuration for devices (e.g., "ps5-gaming")
  Previously called "client"
"""

from pathlib import Path
from typing import Any

import structlog
import yaml

from filterdns.blocklist.engine import BlocklistEngine
from filterdns.db import queries

logger = structlog.get_logger()

# Default path for built-in presets
DEFAULT_PRESETS_PATH = Path(__file__).parent.parent.parent / "profiles.yaml"


def preset_blocklist_id(preset_id: str) -> str:
    """Generate the blocklist ID for a preset.

    Args:
        preset_id: The preset ID (e.g., "windows-updates")

    Returns:
        Blocklist ID (e.g., "preset_windows-updates")
    """
    return f"preset_{preset_id}"


async def load_builtin_presets(
    engine: BlocklistEngine,
    presets_path: Path | None = None,
) -> int:
    """Load built-in presets from YAML file into DB and engine.

    This function:
    1. Reads presets from the YAML file
    2. Creates presets in DB if they don't exist (idempotent)
    3. Loads preset domains into the BlocklistEngine

    Args:
        engine: The BlocklistEngine to load presets into
        presets_path: Path to presets YAML file (defaults to profiles.yaml)

    Returns:
        Number of presets loaded
    """
    if presets_path is None:
        presets_path = DEFAULT_PRESETS_PATH

    if not presets_path.exists():
        logger.warning("Presets file not found", path=str(presets_path))
        return 0

    # Load YAML
    with open(presets_path) as f:
        data = yaml.safe_load(f)

    if not data or "presets" not in data:
        logger.warning("No presets found in YAML file")
        return 0

    presets_data: list[dict[str, Any]] = data["presets"]
    loaded = 0

    for preset_data in presets_data:
        preset_id = preset_data["id"]
        name = preset_data["name"]
        category = preset_data["category"]
        description = preset_data.get("description")
        domains = preset_data.get("domains", [])

        # Check if preset exists
        exists = await queries.preset_exists(preset_id)

        if not exists:
            # Create preset in DB
            await queries.create_preset(
                preset_id=preset_id,
                name=name,
                category=category,
                description=description,
                is_builtin=True,
            )
            logger.info(
                "Created built-in preset",
                preset_id=preset_id,
                name=name,
                category=category,
            )

            # Set domains
            await queries.set_preset_domains(preset_id, domains)

        # Load into engine (always, for startup)
        domain_set = {d.lower() for d in domains}
        engine.set_blocklist(preset_blocklist_id(preset_id), domain_set)
        loaded += 1

    logger.info("Loaded built-in presets", count=loaded)
    return loaded


async def load_all_presets_into_engine(engine: BlocklistEngine) -> int:
    """Load all presets from DB into the BlocklistEngine.

    This is called on startup to populate the engine with all presets.

    Args:
        engine: The BlocklistEngine to load presets into

    Returns:
        Number of presets loaded
    """
    # Get all preset domains grouped by preset
    all_domains = await queries.get_all_preset_domains()

    for preset_id, domains in all_domains.items():
        engine.set_blocklist(preset_blocklist_id(preset_id), domains)

    logger.info("Loaded presets into engine", count=len(all_domains))
    return len(all_domains)


async def reload_preset_in_engine(engine: BlocklistEngine, preset_id: str) -> None:
    """Reload a single preset's domains into the engine.

    Call this after updating preset domains via API.

    Args:
        engine: The BlocklistEngine
        preset_id: The preset ID to reload
    """
    domains = await queries.get_preset_domains(preset_id)
    domain_set = {d.lower() for d in domains}
    engine.set_blocklist(preset_blocklist_id(preset_id), domain_set)
    logger.info(
        "Reloaded preset in engine",
        preset_id=preset_id,
        domain_count=len(domain_set),
    )


def remove_preset_from_engine(engine: BlocklistEngine, preset_id: str) -> None:
    """Remove a preset from the engine.

    Call this when a preset is deleted.

    Args:
        engine: The BlocklistEngine
        preset_id: The preset ID to remove
    """
    blocklist_id = preset_blocklist_id(preset_id)
    engine.remove_blocklist(blocklist_id)
    logger.info("Removed preset from engine", preset_id=preset_id)


# =============================================================================
# Backwards compatibility aliases
# =============================================================================

profile_blocklist_id = preset_blocklist_id
load_builtin_profiles = load_builtin_presets
load_all_profiles_into_engine = load_all_presets_into_engine
reload_profile_in_engine = reload_preset_in_engine
remove_profile_from_engine = remove_preset_from_engine
DEFAULT_PROFILES_PATH = DEFAULT_PRESETS_PATH
