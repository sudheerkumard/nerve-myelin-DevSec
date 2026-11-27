# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Index tenant advisory records for package and CVE lookups.

Revision ID: 0011
Revises: 0010
"""
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("CREATE INDEX ix_advisory_package_keys ON advisory_records USING gin ((payload -> 'package_keys'))")
    op.execute("CREATE INDEX ix_advisory_cve_ids ON advisory_records USING gin ((payload -> 'cve_ids'))")


def downgrade():
    op.drop_index("ix_advisory_cve_ids", table_name="advisory_records")
    op.drop_index("ix_advisory_package_keys", table_name="advisory_records")
