#!/usr/bin/env bash
# C7: Deploy ONS notification topics and subscriptions.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== C7: Notifications Deployment ==="

: "${OCI_COMPARTMENT_ID:?OCI_COMPARTMENT_ID is required}"

OCI_PROFILE="${OCI_PROFILE:-DEFAULT}"
PROJECT_NAME="${PROJECT_NAME:-skp}"

echo "  Creating ONS topic..."
EXISTING_TOPIC=$(oci ons topic list \
    --profile "$OCI_PROFILE" \
    --compartment-id "$OCI_COMPARTMENT_ID" \
    --name "${PROJECT_NAME}-alerts" \
    --lifecycle-state ACTIVE \
    --query 'data[0]."topic-id"' --raw-output 2>/dev/null || echo "")

if [[ -n "$EXISTING_TOPIC" && "$EXISTING_TOPIC" != "null" ]]; then
    echo "    Topic exists: ${EXISTING_TOPIC:0:40}..."
else
    oci ons topic create \
        --profile "$OCI_PROFILE" \
        --compartment-id "$OCI_COMPARTMENT_ID" \
        --name "${PROJECT_NAME}-alerts" \
        --description "Seven Kingdoms Portal monitoring alerts"
    echo "    Topic created"
fi

echo ""
echo "  Notifications deployment complete!"
echo "  Add subscriptions via OCI Console or: oci ons subscription create"
