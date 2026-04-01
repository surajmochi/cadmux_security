#!/usr/bin/env bash
set -euo pipefail

# In-place auto-update script for Cadmux Security.
# Usage: ./deploy_update.sh [container_id_or_name]

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
DEFAULT_CONTAINER_NAME="cadmux-security"
CONTAINER_ID_OR_NAME="${1:-${CONTAINER_ID:-}}"

if [[ -z "$CONTAINER_ID_OR_NAME" ]]; then
  if docker container inspect "$DEFAULT_CONTAINER_NAME" >/dev/null 2>&1; then
    CONTAINER_ID_OR_NAME="$DEFAULT_CONTAINER_NAME"
  else
    CONTAINER_ID_OR_NAME="$DEFAULT_CONTAINER_ID"
  fi
fi

if ! docker container inspect "$CONTAINER_ID_OR_NAME" >/dev/null 2>&1; then
  echo "Error: container '$CONTAINER_ID_OR_NAME' was not found." >&2
  exit 1
fi

RUNNING_STATE="$(docker inspect -f '{{.State.Running}}' "$CONTAINER_ID_OR_NAME")"
if [[ "$RUNNING_STATE" != "true" ]]; then
  echo "==> Starting existing container $CONTAINER_ID_OR_NAME"
  docker start "$CONTAINER_ID_OR_NAME" >/dev/null
fi

echo "==> Syncing updated source code into container $CONTAINER_ID_OR_NAME"
docker exec "$CONTAINER_ID_OR_NAME" sh -lc "rm -rf /app/.app_new && mkdir -p /app/.app_new"
docker cp "$REPO_DIR/app/." "$CONTAINER_ID_OR_NAME:/app/.app_new/"
docker exec "$CONTAINER_ID_OR_NAME" sh -lc "rm -rf /app/app && mv /app/.app_new /app/app"
docker cp "$REPO_DIR/pyproject.toml" "$CONTAINER_ID_OR_NAME:/app/pyproject.toml"
docker cp "$REPO_DIR/README.md" "$CONTAINER_ID_OR_NAME:/app/README.md"

echo "==> Reinstalling app dependencies in existing container"
docker exec "$CONTAINER_ID_OR_NAME" sh -lc "cd /app && pip install --no-cache-dir ."

echo "==> Restarting existing container (no rebuild, no new container)"
docker restart "$CONTAINER_ID_OR_NAME" >/dev/null

echo "Done. Application updated in-place inside container $CONTAINER_ID_OR_NAME."
