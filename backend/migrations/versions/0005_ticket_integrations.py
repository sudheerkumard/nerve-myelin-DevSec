# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Ticketing integrations (Jira, ServiceNow, Azure Boards, webhooks), isolated per tenant with row-level security.

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ticket_integrations",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("config", pg.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("credential_ref", sa.String(1024)),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("last_error", sa.Text),
        sa.Column("created_by", sa.String(320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.execute("ALTER TABLE ticket_integrations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ticket_integrations FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY tenant_isolation ON ticket_integrations
                  USING (tenant_id = myelin_current_tenant()) WITH CHECK (tenant_id = myelin_current_tenant())""")
    op.execute("CREATE POLICY admin_all ON ticket_integrations TO myelin_admin USING (true) WITH CHECK (true)")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ticket_integrations TO myelin_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ticket_integrations TO myelin_admin")


def downgrade() -> None:
    op.drop_table("ticket_integrations")
