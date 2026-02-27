#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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

# Parse arguments
FORCE=false
while [[ $# -gt 0 ]]; do
  case $1 in
    -f|--force)
      FORCE=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [-f|--force]"
      echo ""
      echo "Options:"
      echo "  -f, --force    Force kill the server immediately (SIGKILL)"
      echo "  -h, --help     Show this help message"
      exit 0
      ;;
    *)
      log_error "Unknown option: $1"
      echo "Use -h or --help for usage information"
      exit 1
      ;;
  esac
done

# Check if PID file exists
if [[ ! -f "$PID_FILE" ]]; then
  log_warn "No PID file found. Server may not be running."

  # Try to find any uvicorn process on the configured port
  PORT="${PORT:-9010}"
  PIDS=$(lsof -ti :"$PORT" 2>/dev/null || true)

  if [[ -n "$PIDS" ]]; then
    log_warn "Found process(es) on port $PORT: $PIDS"
    echo "Do you want to kill these processes? [y/N]"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
      echo "$PIDS" | xargs kill 2>/dev/null || true
      log_info "Processes killed."
    fi
  fi
  exit 0
fi

# Read PID from file
PID=$(cat "$PID_FILE" 2>/dev/null || echo "")

if [[ -z "$PID" ]]; then
  log_error "PID file is empty. Cleaning up..."
  rm -f "$PID_FILE"
  exit 1
fi

# Check if process is running
if ! is_running "$PID"; then
  log_warn "Server (PID: $PID) is not running. Cleaning up stale PID file..."
  rm -f "$PID_FILE"
  exit 0
fi

log_info "Stopping server (PID: $PID)..."

if [[ "$FORCE" == true ]]; then
  # Force kill immediately
  kill -9 "$PID" 2>/dev/null || true
  log_info "Server force killed."
else
  # Graceful shutdown
  kill "$PID" 2>/dev/null || true

  # Wait for graceful shutdown (max 10 seconds)
  log_info "Waiting for graceful shutdown..."
  count=0
  while is_running "$PID" && [[ $count -lt 20 ]]; do
    sleep 0.5
    ((count++))
  done

  # Force kill if still running
  if is_running "$PID"; then
    log_warn "Server didn't stop gracefully. Force killing..."
    kill -9 "$PID" 2>/dev/null || true
  fi
fi

# Clean up PID file
rm -f "$PID_FILE"

log_info "Server stopped successfully."
