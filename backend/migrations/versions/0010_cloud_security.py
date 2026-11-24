# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Cloud-native application protection: cloud accounts, normalised inventories and runtime events, each isolated
per tenant with forced row-level security.

Revision ID: 0010
Revises: 0009
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def _rls(name):
    op.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY")
    op.execute(f"""CREATE POLICY tenant_isolation ON {name}
        USING (tenant_id = myelin_current_tenant()) WITH CHECK (tenant_id = myelin_current_tenant())""")
    op.execute(f"CREATE POLICY admin_all ON {name} TO myelin_admin USING (true) WITH CHECK (true)")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO myelin_app")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO myelin_admin")


def _tenant():
    return sa.Column("tenant_id", pg.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)


def upgrade() -> None:
    op.create_table("cloud_accounts",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True), _tenant(),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("config", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("credential_ref", sa.String(1024)),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("last_collected_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text),
        sa.Column("created_by", sa.String(320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("provider IN ('azure','aws','gcp','kubernetes')", name="ck_cloud_account_provider"))
    _rls("cloud_accounts")
    op.create_table("cloud_inventories",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True), _tenant(),
        sa.Column("key", sa.String(300), nullable=False),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("account", sa.String(300), nullable=False),
        sa.Column("summary", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("doc", pg.JSONB, nullable=False),
        sa.Column("collected_by", sa.String(320), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("tenant_id", "key", name="uq_cloud_inventory_key"))
    _rls("cloud_inventories")
    op.create_table("runtime_events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True), _tenant(),
        sa.Column("cluster", sa.String(200), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("rule", sa.String(300), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("namespace", sa.String(200), nullable=False, server_default=""),
        sa.Column("workload", sa.String(300), nullable=False, server_default=""),
        sa.Column("event", pg.JSONB, nullable=False))
    _rls("runtime_events")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE runtime_events_id_seq TO myelin_app")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE runtime_events_id_seq TO myelin_admin")


def downgrade() -> None:
    op.drop_table("runtime_events")
    op.drop_table("cloud_inventories")
    op.drop_table("cloud_accounts")
