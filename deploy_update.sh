#!/usr/bin/env bash
set -euo pipefail

# Auto-update script for Cadmux Security.
# Usage: ./deploy_update.sh

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

if ! command -v git >/dev/null 2>&1; then
  echo "Error: git is not installed." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is not installed." >&2
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Error: this script must live inside a git repository." >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Error: repository has uncommitted changes. Commit/stash them before updating." >&2
  exit 1
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
REMOTE="origin"

if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
  echo "Error: remote '$REMOTE' is not configured for this repository." >&2
  exit 1
fi

echo "==> Fetching latest changes from $REMOTE/$BRANCH"
git fetch "$REMOTE" "$BRANCH"

echo "==> Pulling latest code"
git pull --ff-only "$REMOTE" "$BRANCH"

# Determine whether Docker Compose V2 or legacy docker-compose is available.
if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD=(docker-compose)
else
  echo "Error: docker compose is not available (neither 'docker compose' nor 'docker-compose')." >&2
  exit 1
fi

echo "==> Rebuilding images and restarting containers"
"${COMPOSE_CMD[@]}" pull --ignore-pull-failures || true
"${COMPOSE_CMD[@]}" up -d --build --remove-orphans

echo "==> Cleanup dangling images"
docker image prune -f >/dev/null 2>&1 || true

echo "Done. Application updated and running with latest code/configuration."
