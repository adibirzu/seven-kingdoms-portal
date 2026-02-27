#!/usr/bin/env bash
# C3: Destroy observability resources.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== C3: Observability Teardown ==="

OCI_PROFILE="${OCI_PROFILE:-DEFAULT}"

# Delete APM domain
if [[ -n "${OCI_APM_DOMAIN_ID:-}" ]]; then
    echo "  Deleting APM domain: ${OCI_APM_DOMAIN_ID:0:40}..."
    oci apm-control-plane apm-domain delete \
        --profile "$OCI_PROFILE" \
        --apm-domain-id "$OCI_APM_DOMAIN_ID" \
        --force \
        --wait-for-state SUCCEEDED \
        --max-wait-seconds 300 2>/dev/null || true
    echo "  APM domain deleted."
else
    echo "  No APM domain to delete."
fi

echo "  Observability teardown complete."
echo "  NOTE: Log Analytics namespace cannot be deleted — it persists at tenancy level."
