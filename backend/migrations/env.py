# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Alembic environment. Migrations run as the schema OWNER role (MYELIN_MIGRATIONS_DATABASE_URL);
the application runs as a separate role without BYPASSRLS (MYELIN_DATABASE_URL)."""
import os
from alembic import context
from sqlalchemy import create_engine

from app.db.models import Base

url = os.environ.get("MYELIN_MIGRATIONS_DATABASE_URL")
if not url:
    raise SystemExit("Set MYELIN_MIGRATIONS_DATABASE_URL to the owner-role connection string")


def run():
    if context.is_offline_mode():
        context.configure(url=url, target_metadata=Base.metadata, literal_binds=True)
        with context.begin_transaction():
            context.run_migrations()
        return
    with create_engine(url).connect() as conn:
        context.configure(connection=conn, target_metadata=Base.metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run()
