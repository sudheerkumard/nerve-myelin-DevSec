# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Tenant isolation: roles, row-level security, auth lookup functions, append-only audit log.

Roles
  myelin_app    application role. NOBYPASSRLS. Sees only rows whose tenant_id equals app.tenant_id.
  myelin_auth   owns two SECURITY DEFINER lookup functions (API key -> tenant, session -> tenant);
                can read only the columns those lookups need. Not grantable to the app.
  myelin_admin  platform operations (tenant provisioning, identity bindings, retention purge).
                Used only by the admin CLI / jobs via SET ROLE, never by the API.
Login users are created by the DBA and granted membership: GRANT myelin_app TO <api_login>;
If the DBA pre-creates these roles, grant the migrating owner membership first:
  GRANT myelin_auth, myelin_admin TO <owner_login> WITH ADMIN OPTION;

Revision ID: 0002
Revises: 0001
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TENANT_TABLES = ["users", "api_keys", "web_sessions", "repos", "scans", "findings", "connectors", "evidence",
                 "evidence_reviews", "provenance_manifests", "audit_log"]


def upgrade() -> None:
    op.execute("""
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'myelin_app')   THEN CREATE ROLE myelin_app   NOLOGIN NOBYPASSRLS; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'myelin_auth')  THEN CREATE ROLE myelin_auth  NOLOGIN NOBYPASSRLS; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'myelin_admin') THEN CREATE ROLE myelin_admin NOLOGIN NOBYPASSRLS; END IF;
    END $$;
    """)
    # the migrating owner needs membership to hand function ownership to myelin_auth and to act as admin
    op.execute("""
    DO $$ BEGIN
      IF NOT pg_has_role(current_user, 'myelin_auth', 'MEMBER')  THEN EXECUTE 'GRANT myelin_auth TO ' || quote_ident(current_user);  END IF;
      IF NOT pg_has_role(current_user, 'myelin_admin', 'MEMBER') THEN EXECUTE 'GRANT myelin_admin TO ' || quote_ident(current_user); END IF;
    END $$;
    """)

    op.execute("""
    CREATE OR REPLACE FUNCTION myelin_current_tenant() RETURNS uuid
    LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$;
    """)

    # ---- row-level security on every tenant-owned table (FORCE: applies to the table owner too)
    for t in TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_isolation ON {t}
                       USING (tenant_id = myelin_current_tenant())
                       WITH CHECK (tenant_id = myelin_current_tenant())""")
        op.execute(f"CREATE POLICY admin_all ON {t} TO myelin_admin USING (true) WITH CHECK (true)")
    op.execute("ALTER TABLE tenants ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tenants FORCE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY tenant_self ON tenants USING (id = myelin_current_tenant())")
    op.execute("CREATE POLICY admin_all ON tenants TO myelin_admin USING (true) WITH CHECK (true)")

    # ---- privileges: least privilege for the application role
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA public TO myelin_app, myelin_auth, myelin_admin")
    op.execute("GRANT SELECT ON tenants, tenant_identity_bindings TO myelin_app")
    op.execute("GRANT SELECT ON alembic_version TO myelin_app")          # readiness probe checks schema version
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON users, api_keys, web_sessions, repos, scans, findings, connectors TO myelin_app")
    op.execute("GRANT SELECT, INSERT ON evidence, evidence_reviews, provenance_manifests, audit_log TO myelin_app")
    op.execute("GRANT UPDATE (status, legal_hold, meta) ON evidence TO myelin_app")       # no DELETE: retention job only
    op.execute("GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO myelin_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO myelin_admin")
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO myelin_admin")

    # ---- pre-tenant lookups: only the minimum columns, only through these two functions
    op.execute("GRANT SELECT (id, tenant_id, revoked_at, expires_at) ON api_keys TO myelin_auth")
    op.execute("GRANT SELECT (id_hash, tenant_id, revoked, absolute_expiry) ON web_sessions TO myelin_auth")
    op.execute("CREATE POLICY auth_lookup ON api_keys FOR SELECT TO myelin_auth USING (true)")
    op.execute("CREATE POLICY auth_lookup ON web_sessions FOR SELECT TO myelin_auth USING (true)")
    op.execute("""
    CREATE OR REPLACE FUNCTION myelin_auth_api_key_tenant(p_key_id text) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
      SELECT tenant_id FROM api_keys
       WHERE id = p_key_id AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
    $$;
    """)
    op.execute("""
    CREATE OR REPLACE FUNCTION myelin_auth_session_tenant(p_hash text) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
      SELECT tenant_id FROM web_sessions WHERE id_hash = p_hash AND NOT revoked AND absolute_expiry > now()
    $$;
    """)
    op.execute("GRANT CREATE ON SCHEMA public TO myelin_auth")       # required momentarily to take ownership
    for fn in ("myelin_auth_api_key_tenant(text)", "myelin_auth_session_tenant(text)"):
        op.execute(f"ALTER FUNCTION {fn} OWNER TO myelin_auth")
        op.execute(f"REVOKE ALL ON FUNCTION {fn} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {fn} TO myelin_app")
    op.execute("REVOKE CREATE ON SCHEMA public FROM myelin_auth")

    # ---- audit log: append-only, enforced in the database
    op.execute("""
    CREATE OR REPLACE FUNCTION myelin_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'audit_log is append-only'; END $$;
    """)
    op.execute("""CREATE TRIGGER audit_log_immutable BEFORE UPDATE OR DELETE ON audit_log
                  FOR EACH ROW EXECUTE FUNCTION myelin_audit_immutable()""")
    op.execute("""
    CREATE OR REPLACE FUNCTION myelin_evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN
        IF OLD.legal_hold OR OLD.retention_until > now() THEN
          RAISE EXCEPTION 'evidence % is under retention or legal hold', OLD.id;
        END IF;
        RETURN OLD;
      END IF;
      IF NEW.sha256 <> OLD.sha256 OR NEW.storage_uri <> OLD.storage_uri OR NEW.size <> OLD.size
         OR NEW.retention_until < OLD.retention_until THEN
        RAISE EXCEPTION 'evidence content, location and retention cannot be altered';
      END IF;
      RETURN NEW;
    END $$;
    """)
    op.execute("""CREATE TRIGGER evidence_guard BEFORE UPDATE OR DELETE ON evidence
                  FOR EACH ROW EXECUTE FUNCTION myelin_evidence_guard()""")


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS evidence_guard ON evidence")
    op.execute("DROP TRIGGER IF EXISTS audit_log_immutable ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS myelin_evidence_guard()")
    op.execute("DROP FUNCTION IF EXISTS myelin_audit_immutable()")
    op.execute("DROP FUNCTION IF EXISTS myelin_auth_api_key_tenant(text)")
    op.execute("DROP FUNCTION IF EXISTS myelin_auth_session_tenant(text)")
    for t in TENANT_TABLES + ["tenants"]:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"DROP POLICY IF EXISTS tenant_self ON {t}")
        op.execute(f"DROP POLICY IF EXISTS admin_all ON {t}")
        op.execute(f"DROP POLICY IF EXISTS auth_lookup ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP FUNCTION IF EXISTS myelin_current_tenant()")
