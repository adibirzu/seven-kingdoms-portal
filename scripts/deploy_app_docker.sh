#!/usr/bin/env bash
# C4 Docker: Build and run the app locally via Docker Compose.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== C4: App Docker Deployment ==="

# Check Docker
if ! command -v docker &>/dev/null; then
    echo "ERROR: docker not found"
    exit 1
fi

cd "$ROOT_DIR"

# Build and start
echo "  Building and starting Docker containers..."
docker compose -f deploy/docker/docker-compose.yml up --build -d

# Wait for health
echo "  Waiting for health check..."
APP_PORT="${APP_PORT:-9010}"
for i in $(seq 1 30); do
    if curl -sf --max-time 5 "http://localhost:${APP_PORT}/health" &>/dev/null; then
        echo "  App healthy at http://localhost:${APP_PORT}"

        # Write to .env.local
        ENV_FILE="$ROOT_DIR/.env.local"
        if [[ ! -f "$ENV_FILE" ]]; then touch "$ENV_FILE"; fi
        if grep -q "^APP_URL=" "$ENV_FILE" 2>/dev/null; then
            sed -i.bak "s|^APP_URL=.*|APP_URL=http://localhost:${APP_PORT}|" "$ENV_FILE"
            rm -f "${ENV_FILE}.bak"
        else
            echo "APP_URL=http://localhost:${APP_PORT}" >> "$ENV_FILE"
        fi

        echo ""
        echo "  Docker deployment complete!"
        echo "    URL: http://localhost:${APP_PORT}"
        echo "    Portal: http://localhost:${APP_PORT}/portal/"
        exit 0
    fi
    sleep 2
done

echo "ERROR: App failed health check after 60s"
docker compose -f deploy/docker/docker-compose.yml logs --tail=50
exit 1
