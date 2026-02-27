#!/usr/bin/env bash
# End-to-end health checks for the Seven Kingdoms Portal platform.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Seven Kingdoms Portal — End-to-End Verification ==="

PASS=0
FAIL=0

check() {
    local name="$1" url="$2" expected="${3:-200}"
    printf "  %-40s " "$name"
    HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "$expected" ]]; then
        echo "[OK]  ($HTTP_CODE)"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] (got $HTTP_CODE, expected $expected)"
        FAIL=$((FAIL + 1))
    fi
}

# Determine app URL
APP_URL="${APP_URL:-}"
if [[ -z "$APP_URL" ]]; then
    if [[ -f "$ROOT_DIR/.env.local" ]]; then
        APP_URL=$(grep "^APP_URL=" "$ROOT_DIR/.env.local" 2>/dev/null | cut -d'=' -f2- || echo "")
    fi
fi

if [[ -z "$APP_URL" ]]; then
    echo "  ERROR: APP_URL not set. Cannot verify."
    exit 1
fi

APP_URL="${APP_URL%/}"  # Remove trailing slash
echo "  Target: $APP_URL"
echo ""

# Core health checks
check "Health endpoint"        "$APP_URL/health"
check "Readiness endpoint"     "$APP_URL/ready"
check "Portal UI"              "$APP_URL/portal/"
check "Vulnerable app"         "$APP_URL/vulnerable"
check "Detection rules API"    "$APP_URL/portal/api/detection-rules"

# GOAD connectivity (if enabled)
if [[ "${DEPLOY_GOAD:-true}" == "true" ]]; then
    check "GOAD connectivity"  "$APP_URL/portal/api/goad/connectivity"
fi

echo ""
echo "  Results: $PASS passed, $FAIL failed"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
echo "  All checks passed!"
