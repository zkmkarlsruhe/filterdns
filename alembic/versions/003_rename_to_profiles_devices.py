"""Rename clients to profiles, linked_devices to devices, restriction_profiles to presets

This migration implements the museum-focused naming convention:
- Client → Profile (DNS configuration for a group of devices)
- LinkedDevice → Device (individual machines)
- RestrictionProfile → Preset (predefined blocking rules)

Revision ID: 003
Revises: 002
Create Date: 2026-01-29

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # =========================================================================
    # Step 1: Drop existing triggers that reference old table names
    # =========================================================================
    op.execute("DROP TRIGGER IF EXISTS profile_domain_change_trigger ON profile_domains")
    op.execute("DROP TRIGGER IF EXISTS profile_change_trigger ON restriction_profiles")

    # =========================================================================
    # Step 2: Rename main tables
    # =========================================================================

    # clients → profiles
    op.rename_table("clients", "profiles")

    # linked_devices → devices
    op.rename_table("linked_devices", "devices")

    # restriction_profiles → presets
    op.rename_table("restriction_profiles", "presets")

    # client_blocklists → profile_blocklists
    op.rename_table("client_blocklists", "profile_blocklists")

    # client_rules → profile_rules
    op.rename_table("client_rules", "profile_rules")

    # client_profiles → profile_presets
    op.rename_table("client_profiles", "profile_presets")

    # profile_domains → preset_domains
    op.rename_table("profile_domains", "preset_domains")

    # =========================================================================
    # Step 3: Rename columns with client_id → profile_id
    # =========================================================================

    # devices table
    op.alter_column("devices", "client_id", new_column_name="profile_id")

    # profile_blocklists table
    op.alter_column("profile_blocklists", "client_id", new_column_name="profile_id")

    # profile_rules table
    op.alter_column("profile_rules", "client_id", new_column_name="profile_id")

    # profile_presets table - MUST rename profile_id first to free up the name
    op.alter_column("profile_presets", "profile_id", new_column_name="preset_id")
    op.alter_column("profile_presets", "client_id", new_column_name="profile_id")

    # preset_domains table - profile_id → preset_id
    op.alter_column("preset_domains", "profile_id", new_column_name="preset_id")

    # query_logs table
    op.alter_column("query_logs", "client_id", new_column_name="profile_id")

    # =========================================================================
    # Step 4: Add location column to devices
    # =========================================================================
    op.add_column("devices", sa.Column("location", sa.Text(), nullable=True))

    # =========================================================================
    # Step 5: Update foreign key constraints
    # =========================================================================

    # Drop old foreign keys and recreate with new names
    # devices
    op.drop_constraint("linked_devices_client_id_fkey", "devices", type_="foreignkey")
    op.create_foreign_key("devices_profile_id_fkey", "devices", "profiles", ["profile_id"], ["id"], ondelete="CASCADE")

    # profile_blocklists
    op.drop_constraint("client_blocklists_client_id_fkey", "profile_blocklists", type_="foreignkey")
    op.drop_constraint("client_blocklists_blocklist_id_fkey", "profile_blocklists", type_="foreignkey")
    op.create_foreign_key("profile_blocklists_profile_id_fkey", "profile_blocklists", "profiles", ["profile_id"], ["id"], ondelete="CASCADE")
    op.create_foreign_key("profile_blocklists_blocklist_id_fkey", "profile_blocklists", "blocklists", ["blocklist_id"], ["id"], ondelete="CASCADE")

    # profile_rules
    op.drop_constraint("client_rules_client_id_fkey", "profile_rules", type_="foreignkey")
    op.create_foreign_key("profile_rules_profile_id_fkey", "profile_rules", "profiles", ["profile_id"], ["id"], ondelete="CASCADE")

    # profile_presets
    op.drop_constraint("client_profiles_client_id_fkey", "profile_presets", type_="foreignkey")
    op.drop_constraint("client_profiles_profile_id_fkey", "profile_presets", type_="foreignkey")
    op.create_foreign_key("profile_presets_profile_id_fkey", "profile_presets", "profiles", ["profile_id"], ["id"], ondelete="CASCADE")
    op.create_foreign_key("profile_presets_preset_id_fkey", "profile_presets", "presets", ["preset_id"], ["id"], ondelete="CASCADE")

    # preset_domains
    op.drop_constraint("profile_domains_profile_id_fkey", "preset_domains", type_="foreignkey")
    op.create_foreign_key("preset_domains_preset_id_fkey", "preset_domains", "presets", ["preset_id"], ["id"], ondelete="CASCADE")

    # =========================================================================
    # Step 6: Update indexes
    # =========================================================================

    # Drop old indexes
    op.drop_index("idx_logs_client_time", table_name="query_logs")
    op.drop_index("idx_query_logs_client_blocked_time", table_name="query_logs")
    op.drop_index("idx_profile_domains_profile_id", table_name="preset_domains")

    # Create new indexes with correct names
    op.create_index("idx_logs_profile_time", "query_logs", ["profile_id", "timestamp"])
    op.create_index("idx_query_logs_profile_blocked_time", "query_logs", ["profile_id", "blocked", "timestamp"])
    op.create_index("idx_preset_domains_preset_id", "preset_domains", ["preset_id"])

    # Add index for device location lookup
    op.create_index("idx_devices_location", "devices", ["location"])

    # =========================================================================
    # Step 7: Recreate triggers with new table names
    # =========================================================================
    op.execute("""
        CREATE TRIGGER preset_change_trigger
        AFTER INSERT OR UPDATE OR DELETE ON presets
        FOR EACH STATEMENT EXECUTE FUNCTION increment_global_version();
    """)

    op.execute("""
        CREATE TRIGGER preset_domain_change_trigger
        AFTER INSERT OR UPDATE OR DELETE ON preset_domains
        FOR EACH STATEMENT EXECUTE FUNCTION increment_global_version();
    """)


def downgrade() -> None:
    # Drop new triggers
    op.execute("DROP TRIGGER IF EXISTS preset_domain_change_trigger ON preset_domains")
    op.execute("DROP TRIGGER IF EXISTS preset_change_trigger ON presets")

    # Drop new indexes
    op.drop_index("idx_devices_location", table_name="devices")
    op.drop_index("idx_preset_domains_preset_id", table_name="preset_domains")
    op.drop_index("idx_query_logs_profile_blocked_time", table_name="query_logs")
    op.drop_index("idx_logs_profile_time", table_name="query_logs")

    # Recreate old indexes
    op.create_index("idx_profile_domains_profile_id", "preset_domains", ["preset_id"])
    op.create_index("idx_query_logs_client_blocked_time", "query_logs", ["profile_id", "blocked", "timestamp"])
    op.create_index("idx_logs_client_time", "query_logs", ["profile_id", "timestamp"])

    # Drop new foreign keys and recreate old ones
    op.drop_constraint("preset_domains_preset_id_fkey", "preset_domains", type_="foreignkey")
    op.create_foreign_key("profile_domains_profile_id_fkey", "preset_domains", "presets", ["preset_id"], ["id"], ondelete="CASCADE")

    op.drop_constraint("profile_presets_preset_id_fkey", "profile_presets", type_="foreignkey")
    op.drop_constraint("profile_presets_profile_id_fkey", "profile_presets", type_="foreignkey")
    op.create_foreign_key("client_profiles_profile_id_fkey", "profile_presets", "presets", ["preset_id"], ["id"], ondelete="CASCADE")
    op.create_foreign_key("client_profiles_client_id_fkey", "profile_presets", "profiles", ["profile_id"], ["id"], ondelete="CASCADE")

    op.drop_constraint("profile_rules_profile_id_fkey", "profile_rules", type_="foreignkey")
    op.create_foreign_key("client_rules_client_id_fkey", "profile_rules", "profiles", ["profile_id"], ["id"], ondelete="CASCADE")

    op.drop_constraint("profile_blocklists_blocklist_id_fkey", "profile_blocklists", type_="foreignkey")
    op.drop_constraint("profile_blocklists_profile_id_fkey", "profile_blocklists", type_="foreignkey")
    op.create_foreign_key("client_blocklists_blocklist_id_fkey", "profile_blocklists", "blocklists", ["blocklist_id"], ["id"], ondelete="CASCADE")
    op.create_foreign_key("client_blocklists_client_id_fkey", "profile_blocklists", "profiles", ["profile_id"], ["id"], ondelete="CASCADE")

    op.drop_constraint("devices_profile_id_fkey", "devices", type_="foreignkey")
    op.create_foreign_key("linked_devices_client_id_fkey", "devices", "profiles", ["profile_id"], ["id"], ondelete="CASCADE")

    # Drop location column
    op.drop_column("devices", "location")

    # Rename columns back
    op.alter_column("query_logs", "profile_id", new_column_name="client_id")
    op.alter_column("preset_domains", "preset_id", new_column_name="profile_id")
    # profile_presets - MUST rename profile_id first, then rename preset_id to profile_id
    op.alter_column("profile_presets", "profile_id", new_column_name="client_id")
    op.alter_column("profile_presets", "preset_id", new_column_name="profile_id")
    op.alter_column("profile_rules", "profile_id", new_column_name="client_id")
    op.alter_column("profile_blocklists", "profile_id", new_column_name="client_id")
    op.alter_column("devices", "profile_id", new_column_name="client_id")

    # Rename tables back
    op.rename_table("preset_domains", "profile_domains")
    op.rename_table("profile_presets", "client_profiles")
    op.rename_table("profile_rules", "client_rules")
    op.rename_table("profile_blocklists", "client_blocklists")
    op.rename_table("presets", "restriction_profiles")
    op.rename_table("devices", "linked_devices")
    op.rename_table("profiles", "clients")

    # Recreate old triggers
    op.execute("""
        CREATE TRIGGER profile_change_trigger
        AFTER INSERT OR UPDATE OR DELETE ON restriction_profiles
        FOR EACH STATEMENT EXECUTE FUNCTION increment_global_version();
    """)

    op.execute("""
        CREATE TRIGGER profile_domain_change_trigger
        AFTER INSERT OR UPDATE OR DELETE ON profile_domains
        FOR EACH STATEMENT EXECUTE FUNCTION increment_global_version();
    """)
