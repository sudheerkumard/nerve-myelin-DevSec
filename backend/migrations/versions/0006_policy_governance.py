# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Immutable tenant policy versions, four-eyes publication approvals and scoped bindings.

Revision ID: 0006
Revises: 0005
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def _rls(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(f"""CREATE POLICY tenant_isolation ON {table}
        USING (tenant_id = myelin_current_tenant())
        WITH CHECK (tenant_id = myelin_current_tenant())""")
    op.execute(f"CREATE POLICY admin_all ON {table} TO myelin_admin USING (true) WITH CHECK (true)")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO myelin_app")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO myelin_admin")


def upgrade() -> None:
    op.create_table(
        "policy_versions",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("content", pg.JSONB(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("created_by", sa.String(320), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("published_by", sa.String(320)),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("tenant_id", "name", "version", name="uq_policy_version_number"),
        sa.CheckConstraint("version > 0", name="ck_policy_version_positive"),
        sa.CheckConstraint("status IN ('draft','pending','published','rejected','superseded')", name="ck_policy_version_status"),
    )
    _rls("policy_versions")

    op.create_table(
        "policy_approval_requests",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("policy_version_id", pg.UUID(as_uuid=True), sa.ForeignKey("policy_versions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requested_by", sa.String(320), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("reviewed_by", sa.String(320)),
        sa.Column("review_note", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("tenant_id", "policy_version_id", name="uq_policy_approval_version"),
        sa.CheckConstraint("status IN ('pending','approved','rejected')", name="ck_policy_approval_status"),
    )
    _rls("policy_approval_requests")

    op.create_table(
        "policy_bindings",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", pg.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("scope_type", sa.String(16), nullable=False),
        sa.Column("scope_key", sa.String(300), nullable=False),
        sa.Column("policy_version_id", pg.UUID(as_uuid=True), sa.ForeignKey("policy_versions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("updated_by", sa.String(320), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("tenant_id", "scope_type", "scope_key", name="uq_policy_binding_scope"),
        sa.CheckConstraint("scope_type IN ('organisation','project','repository')", name="ck_policy_binding_scope"),
        sa.CheckConstraint("(scope_type = 'organisation' AND scope_key = '*') OR (scope_type <> 'organisation' AND length(trim(scope_key)) > 0)", name="ck_policy_binding_key"),
    )
    _rls("policy_bindings")

    # The JSON policy and its digest are immutable even though publication status is a lifecycle field.
    op.execute("""
    CREATE FUNCTION myelin_policy_version_immutable() RETURNS trigger AS $$
    BEGIN
      IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.name <> OLD.name
         OR NEW.version <> OLD.version OR NEW.content_sha256 <> OLD.content_sha256
         OR NEW.content <> OLD.content OR NEW.created_by <> OLD.created_by OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'policy version content is immutable; create a new version';
      END IF;
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql
    """)
    op.execute("""
    CREATE FUNCTION myelin_policy_version_no_delete() RETURNS trigger AS $$
    BEGIN
      IF pg_trigger_depth() > 1 THEN
        RETURN OLD; -- allow a tenant-level cascade purge initiated by the platform administrator
      END IF;
      RAISE EXCEPTION 'published and draft policy versions are retained; create a new version instead';
      RETURN OLD;
    END;
    $$ LANGUAGE plpgsql
    """)
    op.execute("""
    CREATE TRIGGER policy_version_no_delete
    BEFORE DELETE ON policy_versions
    FOR EACH ROW EXECUTE FUNCTION myelin_policy_version_no_delete()
    """)
    op.execute("""
    CREATE TRIGGER policy_version_immutable
    BEFORE UPDATE ON policy_versions
    FOR EACH ROW EXECUTE FUNCTION myelin_policy_version_immutable()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS policy_version_no_delete ON policy_versions")
    op.execute("DROP FUNCTION IF EXISTS myelin_policy_version_no_delete()")
    op.execute("DROP TRIGGER IF EXISTS policy_version_immutable ON policy_versions")
    op.execute("DROP FUNCTION IF EXISTS myelin_policy_version_immutable()")
    op.drop_table("policy_bindings")
    op.drop_table("policy_approval_requests")
    op.drop_table("policy_versions")
