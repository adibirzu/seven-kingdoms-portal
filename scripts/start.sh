#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Configuration
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-9010}"
RELOAD="${RELOAD:-0}"
PID_FILE="$ROOT_DIR/.server.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if a process is running
is_running() {
  local pid=$1
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    return 0
  fi
  return 1
}

# Function to stop the previous session
stop_previous_session() {
  if [[ -f "$PID_FILE" ]]; then
    local old_pid
    old_pid=$(cat "$PID_FILE" 2>/dev/null || echo "")

    if [[ -n "$old_pid" ]] && is_running "$old_pid"; then
      log_warn "Found running server (PID: $old_pid). Stopping it..."
      kill "$old_pid" 2>/dev/null || true

      # Wait for graceful shutdown (max 5 seconds)
      local count=0
      while is_running "$old_pid" && [[ $count -lt 10 ]]; do
        sleep 0.5
        ((count++))
      done

      # Force kill if still running
      if is_running "$old_pid"; then
        log_warn "Server didn't stop gracefully. Force killing..."
        kill -9 "$old_pid" 2>/dev/null || true
      fi

      log_info "Previous server stopped."
    else
      log_info "Stale PID file found. Cleaning up..."
    fi

    rm -f "$PID_FILE"
  fi
}

# Cleanup function for graceful shutdown
cleanup() {
  local exit_code=$?
  echo ""
  log_info "Shutting down server..."

  if [[ -f "$PID_FILE" ]]; then
    local pid
    pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
    if [[ -n "$pid" ]] && is_running "$pid"; then
      kill "$pid" 2>/dev/null || true

      # Wait for graceful shutdown
      local count=0
      while is_running "$pid" && [[ $count -lt 10 ]]; do
        sleep 0.5
        ((count++))
      done

      # Force kill if necessary
      if is_running "$pid"; then
        kill -9 "$pid" 2>/dev/null || true
      fi
    fi
    rm -f "$PID_FILE"
  fi

  log_info "Server stopped. Goodbye!"
  exit $exit_code
}

# Trap signals for graceful shutdown
trap cleanup SIGINT SIGTERM SIGHUP EXIT

# Stop any previous session
stop_previous_session

# Build uvicorn command
UVICORN_ARGS=(uvicorn server.main:app --host "$HOST" --port "$PORT")
if [[ "$RELOAD" == "1" || "$RELOAD" == "true" ]]; then
  UVICORN_ARGS+=(--reload)
  log_info "Hot-reload enabled"
fi

log_info "Starting server on http://${HOST}:${PORT}"
log_info "Press Ctrl+C to stop the server"
echo ""

# Start uvicorn in background, capture its PID
"${UVICORN_ARGS[@]}" &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"

# Health check: wait for server to be ready
HEALTH_URL="http://127.0.0.1:${PORT}/health"
HEALTH_TIMEOUT=15
HEALTH_COUNT=0

while [[ $HEALTH_COUNT -lt $HEALTH_TIMEOUT ]]; do
  if curl -sf "$HEALTH_URL" > /dev/null 2>&1; then
    log_info "Server is healthy and accepting connections"
    break
  fi
  # Check if process is still alive
  if ! is_running "$SERVER_PID"; then
    log_error "Server process exited before becoming healthy"
    rm -f "$PID_FILE"
    exit 1
  fi
  sleep 1
  ((HEALTH_COUNT++))
done

if [[ $HEALTH_COUNT -ge $HEALTH_TIMEOUT ]]; then
  log_warn "Health check timed out after ${HEALTH_TIMEOUT}s (server may still be starting)"
fi

# Wait for the server process
wait $SERVER_PID
