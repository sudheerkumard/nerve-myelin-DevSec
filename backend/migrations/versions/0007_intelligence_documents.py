# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Persist tenant-scoped VEX and advisory source documents.

Revision ID: 0007
Revises: 0006
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "intelligence_documents",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("format", sa.String(32), nullable=False),
        sa.Column("document_id", sa.String(300), nullable=False, server_default=""),
        sa.Column("issuer", sa.String(300), nullable=False, server_default=""),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("document", pg.JSONB(), nullable=False),
        sa.Column("imported_by", sa.String(320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("tenant_id", "sha256", name="uq_intelligence_document_digest"),
    )
    op.execute("ALTER TABLE intelligence_documents ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE intelligence_documents FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY tenant_isolation ON intelligence_documents
        USING (tenant_id = myelin_current_tenant())
        WITH CHECK (tenant_id = myelin_current_tenant())""")
    op.execute("CREATE POLICY admin_all ON intelligence_documents TO myelin_admin USING (true) WITH CHECK (true)")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON intelligence_documents TO myelin_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON intelligence_documents TO myelin_admin")


def downgrade() -> None:
    op.drop_table("intelligence_documents")
