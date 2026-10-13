#!/bin/bash
# Pipeline role (parsing / extraction / review): reads raw, writes core. Idempotent.
# Runs automatically on a fresh volume (docker-entrypoint-initdb.d) and can be re-run on an
# existing database with:  bash scripts/add_roles.sh
# Passwords come from the container environment (.env); re-running syncs the password.
set -euo pipefail

: "${DB_OWNER_USER:?}" "${DB_PIPELINE_USER:?}" "${DB_PIPELINE_PASSWORD:?}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v owner="$DB_OWNER_USER" -v pipeline="$DB_PIPELINE_USER" \
  -v pipeline_pw="$DB_PIPELINE_PASSWORD" -v appdb="$POSTGRES_DB" <<'SQL'
-- create the role once, then always (re)set its password
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE', :'pipeline')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'pipeline') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'pipeline', :'pipeline_pw') \gexec

GRANT CONNECT ON DATABASE :"appdb" TO :"pipeline";
GRANT USAGE ON SCHEMA raw, core TO :"pipeline";

-- raw: read only (originals are never modified by the pipeline)
GRANT SELECT ON ALL TABLES IN SCHEMA raw TO :"pipeline";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA raw GRANT SELECT ON TABLES TO :"pipeline";

-- core: derived data, rebuildable -> read/write incl. DELETE, but not DDL
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA core TO :"pipeline";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA core TO :"pipeline";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA core
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"pipeline";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA core
  GRANT USAGE, SELECT ON SEQUENCES TO :"pipeline";

-- the migration bookkeeping table belongs to the owner alone (it may not exist yet on a fresh
-- volume; migrations/env.py repeats this after every `alembic upgrade`)
SELECT format('REVOKE INSERT, UPDATE, DELETE ON core.alembic_version FROM %I', :'pipeline')
WHERE to_regclass('core.alembic_version') IS NOT NULL \gexec
SQL
