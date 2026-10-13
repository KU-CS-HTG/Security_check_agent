#!/usr/bin/env bash
# Add/refresh roles on an EXISTING database (init scripts only run on an empty volume).
#   1) bash scripts/init_env.sh --fill-missing   # adds DB_PIPELINE_* to .env
#   2) docker compose up -d postgres             # recreates the container with the new env
#   3) python -m opsgraph db upgrade             # core.alembic_version must exist
#   4) bash scripts/add_roles.sh
# Safe to run repeatedly (also re-syncs the role password with .env).
set -euo pipefail
cd "$(dirname "$0")/.."

# Git Bash on Windows rewrites arguments that start with "/" into C:/Program Files/Git/...
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

fail() { echo "ERROR: $*" >&2; exit 1; }

[ -f .env ] || fail ".env not found"
for key in DB_PIPELINE_USER DB_PIPELINE_PASSWORD; do
  grep -q "^${key}=" .env || fail "$key is missing in .env -> run: bash scripts/init_env.sh --fill-missing"
done
# The running container only knows these values if it was recreated after .env changed.
docker compose exec -T postgres sh -c 'test -n "$DB_PIPELINE_PASSWORD"' \
  || fail "the postgres container has no DB_PIPELINE_* variables -> run: docker compose up -d postgres"

docker compose exec -T postgres bash /docker-entrypoint-initdb.d/02-pipeline-role.sh
echo "pipeline role is in place"
