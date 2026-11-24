# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Time-boxed policy exception requests with four-eyes approval.

Revision ID: 0008
Revises: 0007
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policy_exceptions",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("scope_type", sa.String(16), nullable=False),
        sa.Column("scope_key", sa.String(300), nullable=False),
        sa.Column("match", pg.JSONB(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("requested_by", sa.String(320), nullable=False),
        sa.Column("reviewed_by", sa.String(320)),
        sa.Column("review_note", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("scope_type IN ('organisation','project','repository')", name="ck_policy_exception_scope"),
        sa.CheckConstraint("status IN ('pending','approved','rejected','expired')", name="ck_policy_exception_status"),
        sa.CheckConstraint("(scope_type = 'organisation' AND scope_key = '*') OR (scope_type <> 'organisation' AND length(trim(scope_key)) > 0)", name="ck_policy_exception_key"),
    )
    op.execute("ALTER TABLE policy_exceptions ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE policy_exceptions FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY tenant_isolation ON policy_exceptions
        USING (tenant_id = myelin_current_tenant())
        WITH CHECK (tenant_id = myelin_current_tenant())""")
    op.execute("CREATE POLICY admin_all ON policy_exceptions TO myelin_admin USING (true) WITH CHECK (true)")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON policy_exceptions TO myelin_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON policy_exceptions TO myelin_admin")


def downgrade() -> None:
    op.drop_table("policy_exceptions")
