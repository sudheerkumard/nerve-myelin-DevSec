# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Persist normalized advisory records and import execution history.

Revision ID: 0009
Revises: 0008
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def _tenant_table(name, *columns, constraints=()):
    op.create_table(name,
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        *columns, *constraints)
    op.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY")
    op.execute(f"""CREATE POLICY tenant_isolation ON {name}
        USING (tenant_id = myelin_current_tenant())
        WITH CHECK (tenant_id = myelin_current_tenant())""")
    op.execute(f"CREATE POLICY admin_all ON {name} TO myelin_admin USING (true) WITH CHECK (true)")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO myelin_app")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO myelin_admin")


def upgrade() -> None:
    _tenant_table("advisory_records",
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("advisory_id", sa.String(200), nullable=False),
        sa.Column("modified_at", sa.DateTime(timezone=True)),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("payload", pg.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        constraints=(sa.UniqueConstraint("tenant_id", "source", "advisory_id", name="uq_advisory_tenant_source_id"),))
    _tenant_table("import_jobs",
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("requested_by", sa.String(320), nullable=False),
        sa.Column("counters", pg.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        constraints=(
            sa.CheckConstraint("status IN ('queued','running','succeeded','partial','failed')", name="ck_import_job_status"),
            sa.CheckConstraint("kind IN ('advisory_sync','sbom_import')", name="ck_import_job_kind"),
        ))


def downgrade() -> None:
    op.drop_table("import_jobs")
    op.drop_table("advisory_records")
