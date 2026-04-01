#!/usr/bin/env bash
set -euo pipefail

# In-place auto-update script for Cadmux Security.
# Usage: ./deploy_update.sh [container_id]

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

# Keep updates in the existing container, do not rebuild/recreate.
DEFAULT_CONTAINER_ID="5c7c20fb9d61"
CONTAINER_ID="${1:-${CONTAINER_ID:-$DEFAULT_CONTAINER_ID}}"

if ! docker container inspect "$CONTAINER_ID" >/dev/null 2>&1; then
  echo "Error: container '$CONTAINER_ID' was not found." >&2
  exit 1
fi

RUNNING_STATE="$(docker inspect -f '{{.State.Running}}' "$CONTAINER_ID")"
if [[ "$RUNNING_STATE" != "true" ]]; then
  echo "==> Starting existing container $CONTAINER_ID"
  docker start "$CONTAINER_ID" >/dev/null
fi

echo "==> Syncing updated source code into container $CONTAINER_ID"
docker exec "$CONTAINER_ID" sh -lc "rm -rf /app/app"
docker cp "$REPO_DIR/app" "$CONTAINER_ID:/app"
docker cp "$REPO_DIR/pyproject.toml" "$CONTAINER_ID:/app/pyproject.toml"
docker cp "$REPO_DIR/README.md" "$CONTAINER_ID:/app/README.md"

echo "==> Reinstalling app dependencies in existing container"
docker exec "$CONTAINER_ID" sh -lc "cd /app && pip install --no-cache-dir ."

echo "==> Restarting existing container (no rebuild, no new container)"
docker restart "$CONTAINER_ID" >/dev/null

echo "Done. Application updated in-place inside container $CONTAINER_ID."
