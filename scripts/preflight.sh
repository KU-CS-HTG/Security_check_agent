#!/usr/bin/env bash
# Pre-flight checks for running the stack on a Linux host (WSL2 Ubuntu). Exit 1 on any FAIL.
set -u
cd "$(dirname "$0")/.."
fail=0
ok()   { printf '  [ OK ] %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; }
bad()  { printf '  [FAIL] %s\n' "$*"; fail=1; }

echo "== Environment"
IS_GITBASH=0
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) IS_GITBASH=1 ;; esac
case "$PWD" in
  /mnt/*) bad "repo is on a Windows drive ($PWD): slow I/O, broken permissions. Move it under ~/" ;;
  *) if [ $IS_GITBASH -eq 1 ]; then
       warn "Git Bash on a Windows drive ($PWD): file modes (chmod 600) cannot be enforced; use WSL Ubuntu for the Linux-server setup"
     else ok "repo path $PWD"; fi ;;
esac
if grep -qi microsoft /proc/version 2>/dev/null; then ok "running in WSL"; else warn "not WSL (fine for a native Linux host)"; fi

echo "== Secrets"
if [ -f .env ]; then
  mode=$(stat -c '%a' .env)
  if [ "$mode" = "600" ]; then ok ".env permissions 600"
  elif [ $IS_GITBASH -eq 1 ]; then warn ".env mode is $mode: NTFS cannot enforce 600 here (keep the file out of shared folders / OneDrive)"
  else bad ".env permissions are $mode (run: chmod 600 .env)"; fi
  if grep -qE '=change-me' .env; then bad ".env still contains 'change-me' placeholders"; else ok "no placeholder secrets"; fi
  git check-ignore -q .env && ok ".env is git-ignored" || bad ".env is NOT git-ignored"
else
  bad ".env missing (cp .env.example .env && chmod 600 .env)"
fi

echo "== Docker"
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  ok "docker daemon reachable"
  docker compose version >/dev/null 2>&1 && ok "docker compose available" || bad "docker compose plugin missing"
else
  bad "docker not available (start Docker Desktop with WSL integration enabled)"
fi

echo "== Ports (must be free before first start)"
envport() { grep -E "^$1=" .env 2>/dev/null | head -1 | cut -d= -f2 | cut -d' ' -f1; }
for spec in POSTGRES_PORT:5432 NEO4J_HTTP_PORT:7474 NEO4J_BOLT_PORT:7687 AIRFLOW_PORT:8080; do
  p=$(envport "${spec%%:*}"); p=${p:-${spec##*:}}
  if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then
    warn "port $p (${spec%%:*}) in use: fine if it is this stack (docker compose ps); otherwise change it in .env"
  else ok "port $p (${spec%%:*}) free"; fi
done

echo "== Resources"
free_gb=$(df -BG --output=avail . | tail -1 | tr -dc '0-9')
[ "${free_gb:-0}" -ge 10 ] && ok "disk free ${free_gb}G" || bad "disk free ${free_gb}G (<10G)"
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
[ "$mem_mb" -ge 6000 ] && ok "memory ${mem_mb}MB" || warn "memory ${mem_mb}MB: raise WSL limit in %UserProfile%\\.wslconfig ([wsl2] memory=...)"
if command -v nvidia-smi >/dev/null 2>&1; then ok "GPU: $(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader | head -1)"; else warn "nvidia-smi not found (local LLM would run on CPU)"; fi

echo
[ $fail -eq 0 ] && echo "preflight: PASS" || echo "preflight: FAIL"
exit $fail
