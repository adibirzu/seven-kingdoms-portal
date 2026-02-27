#!/usr/bin/env bash
# C4 Docker: Stop and remove Docker containers.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== C4: App Docker Teardown ==="

cd "$ROOT_DIR"
docker compose -f deploy/docker/docker-compose.yml down -v 2>/dev/null || true

echo "  Docker containers removed."
