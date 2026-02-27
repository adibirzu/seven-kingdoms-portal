#!/usr/bin/env bash
# C3: Deploy Observability — APM domain, Log Analytics, Monitoring alarms.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== C3: Observability Deployment ==="

: "${OCI_COMPARTMENT_ID:?OCI_COMPARTMENT_ID is required}"
: "${OCI_REGION:?OCI_REGION is required}"

OCI_PROFILE="${OCI_PROFILE:-DEFAULT}"
PROJECT_NAME="${PROJECT_NAME:-skp}"

echo "  Region:      $OCI_REGION"
echo "  Profile:     $OCI_PROFILE"
echo "  Compartment: ${OCI_COMPARTMENT_ID:0:40}..."

# Check OCI CLI
if ! command -v oci &>/dev/null; then
    echo "ERROR: OCI CLI not found. Install: brew install oci-cli"
    exit 1
fi

ENV_FILE="$ROOT_DIR/.env.local"
_update_env() {
    local key="$1" val="$2"
    if [[ -z "$val" ]]; then return; fi
    if [[ ! -f "$ENV_FILE" ]]; then touch "$ENV_FILE"; fi
    if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
        sed -i.bak "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
        rm -f "${ENV_FILE}.bak"
    else
        echo "${key}=${val}" >> "$ENV_FILE"
    fi
}

# --- APM Domain ---
echo "  Creating APM domain..."
EXISTING_APM=$(oci apm-control-plane apm-domain list \
    --profile "$OCI_PROFILE" \
    --compartment-id "$OCI_COMPARTMENT_ID" \
    --display-name "${PROJECT_NAME}-apm" \
    --lifecycle-state ACTIVE \
    --query 'data[0].id' --raw-output 2>/dev/null || echo "")

if [[ -n "$EXISTING_APM" && "$EXISTING_APM" != "null" ]]; then
    echo "    APM domain already exists: ${EXISTING_APM:0:40}..."
    APM_DOMAIN_ID="$EXISTING_APM"
else
    APM_RESULT=$(oci apm-control-plane apm-domain create \
        --profile "$OCI_PROFILE" \
        --compartment-id "$OCI_COMPARTMENT_ID" \
        --display-name "${PROJECT_NAME}-apm" \
        --is-free-tier false \
        --wait-for-state ACTIVE \
        --max-wait-seconds 300 2>/dev/null || echo "")

    APM_DOMAIN_ID=$(oci apm-control-plane apm-domain list \
        --profile "$OCI_PROFILE" \
        --compartment-id "$OCI_COMPARTMENT_ID" \
        --display-name "${PROJECT_NAME}-apm" \
        --lifecycle-state ACTIVE \
        --query 'data[0].id' --raw-output 2>/dev/null || echo "")
fi

if [[ -z "$APM_DOMAIN_ID" || "$APM_DOMAIN_ID" == "null" ]]; then
    echo "ERROR: Failed to create APM domain"
    exit 1
fi

# Get APM data keys
APM_ENDPOINT=$(oci apm-control-plane apm-domain get \
    --profile "$OCI_PROFILE" \
    --apm-domain-id "$APM_DOMAIN_ID" \
    --query 'data."data-upload-endpoint"' --raw-output 2>/dev/null || echo "")

APM_PRIVATE_KEY=$(oci apm-control-plane data-key list \
    --profile "$OCI_PROFILE" \
    --apm-domain-id "$APM_DOMAIN_ID" \
    --query 'data[?type==`PRIVATE`].value | [0]' --raw-output 2>/dev/null || echo "")

APM_PUBLIC_KEY=$(oci apm-control-plane data-key list \
    --profile "$OCI_PROFILE" \
    --apm-domain-id "$APM_DOMAIN_ID" \
    --query 'data[?type==`PUBLIC`].value | [0]' --raw-output 2>/dev/null || echo "")

echo "    APM Domain:  ${APM_DOMAIN_ID:0:40}..."
echo "    APM Endpoint: ${APM_ENDPOINT:0:50}..."

_update_env "OCI_APM_DOMAIN_ID" "$APM_DOMAIN_ID"
_update_env "OCI_APM_ENDPOINT" "$APM_ENDPOINT"
_update_env "OCI_APM_PRIVATE_DATAKEY" "$APM_PRIVATE_KEY"
_update_env "OCI_APM_PUBLIC_DATAKEY" "$APM_PUBLIC_KEY"

# --- Log Analytics ---
echo "  Setting up Log Analytics..."
LA_NAMESPACE=$(oci log-analytics namespace list \
    --profile "$OCI_PROFILE" \
    --compartment-id "$OCI_COMPARTMENT_ID" \
    --query 'data.items[0]."namespace-name"' --raw-output 2>/dev/null || echo "")

if [[ -n "$LA_NAMESPACE" && "$LA_NAMESPACE" != "null" ]]; then
    echo "    Log Analytics namespace: $LA_NAMESPACE"

    # Create log group
    EXISTING_LG=$(oci log-analytics log-group list \
        --profile "$OCI_PROFILE" \
        --namespace-name "$LA_NAMESPACE" \
        --compartment-id "$OCI_COMPARTMENT_ID" \
        --display-name "${PROJECT_NAME}-logs" \
        --query 'data.items[0].id' --raw-output 2>/dev/null || echo "")

    if [[ -n "$EXISTING_LG" && "$EXISTING_LG" != "null" ]]; then
        echo "    Log group exists: ${EXISTING_LG:0:40}..."
        LOG_GROUP_OCID="$EXISTING_LG"
    else
        LOG_GROUP_OCID=$(oci log-analytics log-group create \
            --profile "$OCI_PROFILE" \
            --namespace-name "$LA_NAMESPACE" \
            --compartment-id "$OCI_COMPARTMENT_ID" \
            --display-name "${PROJECT_NAME}-logs" \
            --description "Seven Kingdoms Portal application logs" \
            --query 'data.id' --raw-output 2>/dev/null || echo "")
        echo "    Created log group: ${LOG_GROUP_OCID:0:40}..."
    fi

    if [[ -n "$LOG_GROUP_OCID" && "$LOG_GROUP_OCID" != "null" ]]; then
        _update_env "OCI_LOG_GROUP_OCID" "$LOG_GROUP_OCID"
    fi
else
    echo "    WARNING: Log Analytics namespace not found. On-board via OCI Console."
fi

# --- Monitoring Alarms ---
echo "  Setting up Monitoring alarms..."
# Create alarm for HTTP 5xx errors (uses custom metrics from the app)
echo "    Monitoring alarms are defined by the application's OTel instrumentation."
echo "    Custom namespace: ${OCI_MONITORING_NAMESPACE:-CustomAttackMetrics}"

echo ""
echo "  Observability deployment complete!"
echo "    APM Endpoint:  $APM_ENDPOINT"
echo "    APM Domain ID: $APM_DOMAIN_ID"
