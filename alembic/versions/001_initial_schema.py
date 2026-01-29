"""Initial schema

Revision ID: 001
Revises:
Create Date: 2026-01-29

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Clients table
    op.create_table(
        "clients",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("filtering_paused_until", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    # Linked devices table
    op.create_table(
        "linked_devices",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("client_id", sa.UUID(), nullable=False),
        sa.Column("ip_address", sa.Text(), nullable=False),
        sa.Column("hostname", sa.Text(), nullable=True),
        sa.Column("label", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["clients.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ip_address"),
    )

    # Blocklists table
    op.create_table(
        "blocklists",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.Text(), nullable=True),
        sa.Column("domain_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_updated", sa.DateTime(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default="TRUE", nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # Client blocklist assignments
    op.create_table(
        "client_blocklists",
        sa.Column("client_id", sa.UUID(), nullable=False),
        sa.Column("blocklist_id", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["blocklist_id"], ["blocklists.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["client_id"], ["clients.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("client_id", "blocklist_id"),
    )

    # Client rules (custom allow/deny)
    op.create_table(
        "client_rules",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("client_id", sa.UUID(), nullable=False),
        sa.Column("domain", sa.Text(), nullable=False),
        sa.Column("rule_type", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["clients.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # Query logs
    op.create_table(
        "query_logs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("client_id", sa.UUID(), nullable=True),
        sa.Column("domain", sa.Text(), nullable=False),
        sa.Column("query_type", sa.Text(), nullable=False),
        sa.Column("blocked", sa.Boolean(), nullable=False),
        sa.Column("blocklist_id", sa.Text(), nullable=True),
        sa.Column("response_time_ms", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # Indexes for query logs
    op.create_index("idx_logs_client_time", "query_logs", ["client_id", "timestamp"])
    op.create_index("idx_logs_domain", "query_logs", ["domain"])
    op.create_index("idx_logs_timestamp", "query_logs", ["timestamp"])

    # Create default client
    op.execute("""
        INSERT INTO clients (name) VALUES ('default')
        ON CONFLICT (name) DO NOTHING
    """)


def downgrade() -> None:
    op.drop_index("idx_logs_timestamp", table_name="query_logs")
    op.drop_index("idx_logs_domain", table_name="query_logs")
    op.drop_index("idx_logs_client_time", table_name="query_logs")
    op.drop_table("query_logs")
    op.drop_table("client_rules")
    op.drop_table("client_blocklists")
    op.drop_table("blocklists")
    op.drop_table("linked_devices")
    op.drop_table("clients")
