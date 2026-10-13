#!/usr/bin/env bash
# Add/refresh roles on an EXISTING database (init scripts only run on an empty volume).
#   1) bash scripts/init_env.sh --fill-missing   # adds DB_PIPELINE_* to .env
#   2) docker compose up -d postgres             # recreates the container with the new env
#   3) bash scripts/add_roles.sh
# Safe to run repeatedly. Requires the migrations to have been applied first
# (core.alembic_version must exist):  python -m opsgraph db upgrade
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose exec -T postgres bash /docker-entrypoint-initdb.d/02-pipeline-role.sh
echo "pipeline role is in place"
