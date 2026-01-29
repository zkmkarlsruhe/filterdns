"""Restriction profiles and maintenance mode

Revision ID: 002
Revises: 001
Create Date: 2026-01-29

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Global config table for cache invalidation
    op.create_table(
        "config",
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )

    # Insert initial global version
    op.execute("INSERT INTO config (key, value) VALUES ('global_version', '1')")

    # Add versioning and maintenance columns to clients
    op.add_column("clients", sa.Column("config_version", sa.Integer(), server_default="1", nullable=False))
    op.add_column("clients", sa.Column("maintenance_mode", sa.Boolean(), server_default="FALSE", nullable=False))
    op.add_column("clients", sa.Column("maintenance_allowlist", sa.ARRAY(sa.Text()), server_default="{}", nullable=False))

    # Restriction profiles table
    op.create_table(
        "restriction_profiles",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("is_builtin", sa.Boolean(), server_default="FALSE", nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # Profile domains table
    op.create_table(
        "profile_domains",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("domain", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["profile_id"], ["restriction_profiles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # Index for faster domain lookup by profile
    op.create_index("idx_profile_domains_profile_id", "profile_domains", ["profile_id"])

    # Client profiles (many-to-many)
    op.create_table(
        "client_profiles",
        sa.Column("client_id", sa.UUID(), nullable=False),
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("enabled_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["clients.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["profile_id"], ["restriction_profiles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("client_id", "profile_id"),
    )

    # Additional query log indexes for better filtering performance
    op.create_index("idx_query_logs_client_blocked_time", "query_logs", ["client_id", "blocked", "timestamp"])
    op.create_index("idx_query_logs_domain_lower", "query_logs", [sa.text("LOWER(domain)")])

    # Trigger function to auto-increment global_version on profile changes
    op.execute("""
        CREATE OR REPLACE FUNCTION increment_global_version()
        RETURNS TRIGGER AS $$
        BEGIN
            UPDATE config SET value = (value::INTEGER + 1)::TEXT, updated_at = NOW()
            WHERE key = 'global_version';
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    # Triggers for profile tables
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


def downgrade() -> None:
    # Drop triggers
    op.execute("DROP TRIGGER IF EXISTS profile_domain_change_trigger ON profile_domains")
    op.execute("DROP TRIGGER IF EXISTS profile_change_trigger ON restriction_profiles")
    op.execute("DROP FUNCTION IF EXISTS increment_global_version()")

    # Drop indexes
    op.drop_index("idx_query_logs_domain_lower", table_name="query_logs")
    op.drop_index("idx_query_logs_client_blocked_time", table_name="query_logs")
    op.drop_index("idx_profile_domains_profile_id", table_name="profile_domains")

    # Drop tables
    op.drop_table("client_profiles")
    op.drop_table("profile_domains")
    op.drop_table("restriction_profiles")

    # Remove columns from clients
    op.drop_column("clients", "maintenance_allowlist")
    op.drop_column("clients", "maintenance_mode")
    op.drop_column("clients", "config_version")

    # Drop config table
    op.drop_table("config")
