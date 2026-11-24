# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Test helper: provision a throw-away PostgreSQL database with production roles and migrations.

Set MYELIN_TEST_PG to a superuser libpq location, e.g.
  MYELIN_TEST_PG="host=/tmp port=5433 user=postgres"         (local socket)
  MYELIN_TEST_PG="host=localhost port=5432 user=postgres password=postgres"   (CI service)
Tests that need PostgreSQL are skipped when it is not set.
"""
import os
import uuid

import psycopg
from psycopg import sql
import pytest

PG = os.getenv("MYELIN_TEST_PG")
needs_pg = pytest.mark.skipif(not PG, reason="MYELIN_TEST_PG not set — PostgreSQL isolation tests skipped")
BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _kv(dsn: str) -> dict:
    return dict(p.split("=", 1) for p in dsn.split())


def _url(user: str, db: str, password: str | None = None) -> str:
    kv = _kv(PG)
    host, port = kv.get("host", "localhost"), kv.get("port", "5432")
    auth = f"{user}:{password}@" if password else f"{user}@"
    if host.startswith("/"):
        return f"postgresql+psycopg://{auth}/{db}?host={host}&port={port}"
    return f"postgresql+psycopg://{auth}{host}:{port}/{db}"


def provision() -> dict:
    """Create a fresh database, owner and API login roles; run migrations as the owner. Returns URLs."""
    from alembic import command
    from alembic.config import Config

    db = "myelin_test_" + uuid.uuid4().hex[:8]
    pw = "t_" + uuid.uuid4().hex[:12]
    with psycopg.connect(PG + " dbname=postgres", autocommit=True) as c:
        for role, attributes in (("myelin_owner_t", "LOGIN CREATEROLE"), ("myelin_api_t", "LOGIN")):
            exists = c.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
            statement = "ALTER ROLE" if exists else "CREATE ROLE"
            c.execute(sql.SQL("{} {} {} PASSWORD {}").format(
                sql.SQL(statement), sql.Identifier(role), sql.SQL(attributes), sql.Literal(pw)
            ))
        # Pre-create the non-login security roles as the cluster DBA. The migration owner
        # must be a member with ADMIN OPTION so it can safely transfer SECURITY DEFINER
        # function ownership on PostgreSQL 16+.
        for role in ("myelin_app", "myelin_auth", "myelin_admin"):
            exists = c.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
            if not exists:
                c.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOBYPASSRLS").format(sql.Identifier(role)))
        c.execute("GRANT myelin_auth, myelin_admin TO myelin_owner_t WITH ADMIN OPTION")
        c.execute(sql.SQL("CREATE DATABASE {} OWNER myelin_owner_t").format(sql.Identifier(db)))
    with psycopg.connect(PG + f" dbname={db}", autocommit=True) as c:
        c.execute("ALTER SCHEMA public OWNER TO myelin_owner_t")
    owner = _url("myelin_owner_t", db, pw)
    cfg = Config(os.path.join(BACKEND, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND, "migrations"))
    os.environ["MYELIN_MIGRATIONS_DATABASE_URL"] = owner
    command.upgrade(cfg, "head")
    with psycopg.connect(PG + " dbname=postgres", autocommit=True) as c:
        c.execute("GRANT myelin_app TO myelin_api_t")
    return {"db": db, "owner": owner, "app": _url("myelin_api_t", db, pw)}


def drop(db: str) -> None:
    from app.db import session
    for e in list(session._ENGINES.values()):
        e.dispose()
    session._ENGINES.clear()
    with psycopg.connect(PG + " dbname=postgres", autocommit=True) as c:
        c.execute(f"DROP DATABASE IF EXISTS {db} WITH (FORCE)")
