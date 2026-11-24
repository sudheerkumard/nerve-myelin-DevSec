# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Online live-application assessment targets, isolated per tenant with row-level security.

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dast_targets",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("base_url", sa.String(2048), nullable=False),
        sa.Column("spec_url", sa.String(2048)),
        sa.Column("spec", pg.JSONB),
        sa.Column("identities", pg.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("config", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("verification_token", sa.String(64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(16), nullable=False, server_default="new"),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_scan_id", sa.String(64)),
        sa.Column("last_result", pg.JSONB),
        sa.Column("last_error", sa.Text),
        sa.Column("created_by", sa.String(320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("tenant_id", "name", name="uq_dast_target_name"),
    )
    op.execute("ALTER TABLE dast_targets ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE dast_targets FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY tenant_isolation ON dast_targets
                  USING (tenant_id = myelin_current_tenant()) WITH CHECK (tenant_id = myelin_current_tenant())""")
    op.execute("CREATE POLICY admin_all ON dast_targets TO myelin_admin USING (true) WITH CHECK (true)")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON dast_targets TO myelin_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON dast_targets TO myelin_admin")


def downgrade() -> None:
    op.drop_table("dast_targets")
