#!/bin/sh
# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
# First-boot only: least-privilege login for the API and a separate database for Keycloak.
# Schema, RLS policies and the myelin_app/myelin_auth/myelin_admin roles are created by `myelin migrate`.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE myelin_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '${MYELIN_DB_APP_PASSWORD}';
CREATE ROLE keycloak LOGIN PASSWORD '${KEYCLOAK_DB_PASSWORD}';
CREATE DATABASE keycloak OWNER keycloak;
REVOKE ALL ON DATABASE myelin FROM PUBLIC;
GRANT CONNECT ON DATABASE myelin TO myelin_api;
SQL
