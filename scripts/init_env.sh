#!/usr/bin/env bash
# Create or complete .env from .env.example with random secrets. Secrets are never printed.
#   bash scripts/init_env.sh                 # create a new .env (refuses to overwrite)
#   bash scripts/init_env.sh --fill-missing  # append only the keys missing from an existing .env
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077

rand() { openssl rand -base64 36 | tr -d '/+=\n' | cut -c1-24; }
fernet() { openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'; }

gen_line() {  # replace "change-me" and an empty Fernet key by random values
  local line=$1
  if [[ $line =~ ^([A-Z0-9_]+)=change-me(.*)$ ]]; then
    printf '%s=%s%s\n' "${BASH_REMATCH[1]}" "$(rand)" "${BASH_REMATCH[2]}"
  elif [[ $line =~ ^AIRFLOW_FERNET_KEY=$ ]]; then
    printf 'AIRFLOW_FERNET_KEY=%s\n' "$(fernet)"
  else
    printf '%s\n' "$line"
  fi
}

mode=${1:-new}
if [ "$mode" = "--fill-missing" ]; then
  [ -f .env ] || { echo ".env not found; run without --fill-missing"; exit 1; }
  added=0
  [ -n "$(tail -c1 .env)" ] && echo >> .env      # ensure trailing newline
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ $line =~ ^([A-Z0-9_]+)= ]]; then
      key=${BASH_REMATCH[1]}                      # gen_line clobbers BASH_REMATCH
      if ! grep -q "^${key}=" .env; then
        gen_line "$line" >> .env
        echo "added: $key"; added=$((added+1))
      fi
    fi
  done < .env.example
  echo "done: $added key(s) added (existing values untouched)"
else
  [ -e .env ] && { echo ".env already exists; refusing to overwrite (use --fill-missing)"; exit 1; }
  while IFS= read -r line || [ -n "$line" ]; do gen_line "$line"; done < .env.example > .env
  chmod 600 .env 2>/dev/null || true
  echo ".env created with random secrets. Edit HTTP_CONTACT (your email) and check the ports."
fi
