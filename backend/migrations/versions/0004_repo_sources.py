# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Repositories scanned from the console, isolated per tenant with row-level security.

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repo_sources",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("branch", sa.String(200)),
        sa.Column("credential_ref", sa.String(1024)),
        sa.Column("config", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.String(16), nullable=False, server_default="new"),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_scan_id", sa.String(64)),
        sa.Column("last_commit", sa.String(64)),
        sa.Column("last_result", pg.JSONB),
        sa.Column("last_error", sa.Text),
        sa.Column("created_by", sa.String(320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("tenant_id", "name", name="uq_repo_source_name"),
    )
    op.execute("ALTER TABLE repo_sources ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE repo_sources FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY tenant_isolation ON repo_sources
                  USING (tenant_id = myelin_current_tenant()) WITH CHECK (tenant_id = myelin_current_tenant())""")
    op.execute("CREATE POLICY admin_all ON repo_sources TO myelin_admin USING (true) WITH CHECK (true)")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON repo_sources TO myelin_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON repo_sources TO myelin_admin")


def downgrade() -> None:
    op.drop_table("repo_sources")
