#!/bin/bash
#
# OCI Observability Overview - Focused Code Update Script
# Updates only the application code on the OCI VM
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DEPLOY_DIR="$PROJECT_ROOT/deploy"
ENVIRONMENT="prod"

# Load local environment variables if present
if [[ -f "$PROJECT_ROOT/.env.local" ]]; then
    # shellcheck disable=SC1091
    source "$PROJECT_ROOT/.env.local"
fi

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

_is_valid_ipv4() {
    [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
}

_sanitize_tf_output() {
    # Strip ANSI escape codes and whitespace from terraform output.
    # terraform output -raw can emit warnings to stdout when state is empty.
    printf '%s' "$1" | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\n\r' | xargs
}

# 1. Fetch deployment info (from environment or Terraform)
get_info() {
    # Allow overrides from environment
    INSTANCE_IP="${INSTANCE_IP:-}"
    BASTION_IP="${BASTION_IP:-}"
    INSTANCE_ID="${INSTANCE_ID:-}"

    if _is_valid_ipv4 "$INSTANCE_IP" && _is_valid_ipv4 "$BASTION_IP"; then
        log_info "Using IP information provided via environment variables."
        log_info "  INSTANCE_IP=$INSTANCE_IP  BASTION_IP=$BASTION_IP"
        return
    fi

    # If only INSTANCE_IP is set (no bastion), attempt direct connection later
    if _is_valid_ipv4 "$INSTANCE_IP"; then
        log_info "INSTANCE_IP=$INSTANCE_IP from environment (no bastion)."
        return
    fi

    local tf_dir="$DEPLOY_DIR/terraform/environments/$ENVIRONMENT"
    if [[ ! -d "$tf_dir" ]]; then
        log_error "Terraform directory not found: $tf_dir"
        log_error "Set INSTANCE_IP and BASTION_IP environment variables manually."
        exit 1
    fi

    # Check if terraform state has resources before querying outputs
    local tf_state="$tf_dir/terraform.tfstate"
    if [[ -f "$tf_state" ]]; then
        local res_count
        res_count="$(python3 -c "import json; print(len(json.load(open('$tf_state')).get('resources',[])))" 2>/dev/null || echo "0")"
        if [[ "$res_count" == "0" ]]; then
            log_error "Terraform state is empty (no resources). Set INSTANCE_IP and BASTION_IP manually."
            exit 1
        fi
    fi

    log_info "Fetching info from Terraform..."
    cd "$tf_dir"

    if [[ -z "$INSTANCE_IP" ]]; then
        local raw
        raw="$(_sanitize_tf_output "$(terraform output -raw instance_private_ip 2>/dev/null || true)")"
        if _is_valid_ipv4 "$raw"; then
            INSTANCE_IP="$raw"
        fi
    fi
    if [[ -z "$BASTION_IP" ]]; then
        local raw
        raw="$(_sanitize_tf_output "$(terraform output -raw bastion_public_ip 2>/dev/null || true)")"
        if _is_valid_ipv4 "$raw"; then
            BASTION_IP="$raw"
        fi
    fi
    if [[ -z "$INSTANCE_ID" ]]; then
        INSTANCE_ID=$(_sanitize_tf_output "$(terraform output -raw instance_id 2>/dev/null || true)")
    fi

    if ! _is_valid_ipv4 "$INSTANCE_IP"; then
        log_error "Could not retrieve a valid INSTANCE_IP. Is Terraform deployed?"
        log_error "Got: '$INSTANCE_IP'"
        log_error "Set INSTANCE_IP and BASTION_IP environment variables manually."
        exit 1
    fi
}

# 2. Ensure instances are started
ensure_started() {
    local id=$1
    local name=$2
    
    if [[ -z "$id" || ! "$id" =~ ^ocid1\. ]]; then
        log_info "No valid OCID for $name provided. Skipping OCI status check."
        return
    fi

    # Skip if oci cli is not available (e.g. in simple CI)
    if ! command -v oci &> /dev/null; then
        log_warning "OCI CLI not found. Skipping power state check."
        return
    fi

    log_info "Checking status of $name ($id)..."

    local max_wait_seconds="${C6_ENSURE_STARTED_TIMEOUT_SECONDS:-300}"
    local start_ts
    start_ts="$(date +%s)"
    while true; do
        local state
        state=$(oci compute instance get --instance-id "$id" --query 'data."lifecycle-state"' --raw-output 2>/dev/null || echo "UNKNOWN")

        log_info "Current state of $name: $state"

        if [[ "$state" == "RUNNING" ]]; then
            log_success "$name is RUNNING."
            break
        elif [[ "$state" == "STOPPED" ]]; then
            log_info "Starting $name..."
            oci compute instance action --instance-id "$id" --action START > /dev/null
        elif [[ "$state" == "STARTING" || "$state" == "PROVISIONING" ]]; then
            log_info "Waiting for $name to boot..."
        else
            log_warning "Unexpected state: $state. Waiting..."
        fi
        local elapsed
        elapsed=$(( $(date +%s) - start_ts ))
        if (( elapsed >= max_wait_seconds )); then
            log_warning "$name did not reach RUNNING within ${max_wait_seconds}s (last state: $state). Continuing anyway."
            break
        fi
        sleep 10
    done
}

# 3. Perform code update
update_code() {
    log_info "Preparing focused code update package..."
    local deploy_pkg="/tmp/observability-code-update.tar.gz"
    
    cd "$PROJECT_ROOT"
    tar -czf "$deploy_pkg" \
        server/ \
        web/ \
        requirements.txt \
        .env.local.example \
        README.md

    local ssh_connect_timeout="${C6_SSH_CONNECT_TIMEOUT_SECONDS:-10}"
    local cloud_init_timeout="${C6_REMOTE_CLOUD_INIT_TIMEOUT_SECONDS:-900}"
    local cloud_init_strict="${C6_REMOTE_CLOUD_INIT_STRICT:-false}"

    # Determine SSH key
    local key_path="${SSH_KEY:-}"
    
    # Fallback to identified project key if not provided
    if [[ -z "$key_path" ]]; then
        if [[ -f "$HOME/.ssh/new_id_rsa" ]]; then
            key_path="$HOME/.ssh/new_id_rsa"
            log_info "No SSH_KEY provided, defaulting to $key_path"
        fi
    fi

    local ssh_key_args=()
    if [[ -n "$key_path" ]]; then
        ssh_key_args=("-i" "$key_path")
        log_info "Using identity file: $key_path"
    fi

    # Define common SSH options
    local jump_options=(
        "-o" "StrictHostKeyChecking=no"
        "-o" "ConnectTimeout=${ssh_connect_timeout}"
        "-o" "ServerAliveInterval=15"
        "-o" "ServerAliveCountMax=3"
    )
    if [[ -n "$BASTION_IP" ]]; then
        log_info "Using bastion $BASTION_IP to reach $INSTANCE_IP"
        local proxy_command="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=${ssh_connect_timeout}"
        if [[ -n "$key_path" ]]; then
            proxy_command+=" -i $key_path"
        fi
        proxy_command+=" -W %h:%p opc@$BASTION_IP"
        jump_options+=("-o" "ProxyCommand=${proxy_command}")
    else
        log_warning "No bastion host found in Terraform outputs. Attempting direct connection to $INSTANCE_IP..."
    fi

    log_info "Uploading code to VM..."
    scp "${ssh_key_args[@]}" "${jump_options[@]}" "$deploy_pkg" "opc@$INSTANCE_IP:/tmp/"

    local skip_cloud_init="${C6_SKIP_CLOUD_INIT_WAIT:-false}"

    log_info "Applying update on VM..."
    ssh "${ssh_key_args[@]}" "${jump_options[@]}" "opc@$INSTANCE_IP" \
        "C6_CLOUD_INIT_TIMEOUT=${cloud_init_timeout} C6_CLOUD_INIT_STRICT=${cloud_init_strict} C6_SKIP_CLOUD_INIT=${skip_cloud_init} bash -s" << 'EOF'
set -e

SKIP_INIT="$(printf '%s' "${C6_SKIP_CLOUD_INIT:-false}" | tr '[:upper:]' '[:lower:]')"
if [ "$SKIP_INIT" = "true" ] || [ "$SKIP_INIT" = "1" ] || [ "$SKIP_INIT" = "yes" ]; then
    echo -e "\033[0;34m[REMOTE]\033[0m Skipping cloud-init wait (C6_SKIP_CLOUD_INIT=true)."
else

# Wait for cloud-init to finish (max timeout)
echo -e "\033[0;34m[REMOTE]\033[0m Waiting for cloud-init to complete..."
TIMEOUT="${C6_CLOUD_INIT_TIMEOUT:-900}"
STRICT_MODE="$(printf '%s' "${C6_CLOUD_INIT_STRICT:-false}" | tr '[:upper:]' '[:lower:]')"
ELAPSED=0
until [ -f /var/log/cloud-init-app.log ] && grep -q "Cloud-init completed" /var/log/cloud-init-app.log || [ $ELAPSED -ge $TIMEOUT ]; do
    sleep 10
    ((ELAPSED+=10))
    echo -e "  Still waiting... ($ELAPSED/$TIMEOUT seconds)"
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    if [ "$STRICT_MODE" = "true" ] || [ "$STRICT_MODE" = "1" ] || [ "$STRICT_MODE" = "yes" ]; then
        echo -e "\033[0;31m[REMOTE] ERROR: Cloud-init timed out in strict mode.\033[0m"
        exit 1
    fi
    echo -e "\033[1;33m[REMOTE] WARNING: Cloud-init marker not found after ${TIMEOUT}s; continuing.\033[0m"
fi

fi  # end of cloud-init wait (skipped when C6_SKIP_CLOUD_INIT=true)

echo -e "\033[0;34m[REMOTE]\033[0m Performing clean deployment..."
# Stop service first to prevent systemd Restart=always from racing with code extraction
sudo systemctl stop observability-app 2>/dev/null || sudo fuser -k 9010/tcp || true
sudo rm -rf /opt/observability/app/server /opt/observability/app/web
sudo tar -xzf /tmp/observability-code-update.tar.gz -C /opt/observability/app/
sudo chown -R observability:observability /opt/observability/app
rm -f /tmp/observability-code-update.tar.gz

echo -e "\033[0;34m[REMOTE]\033[0m Updating dependencies..."
sudo -u observability bash -c '
    source /opt/observability/venv/bin/activate
    cd /opt/observability/app
    pip install --no-cache-dir -r requirements.txt
'

echo -e "\033[0;34m[REMOTE]\033[0m Restarting service..."
sudo systemctl restart observability-app

echo -e "\033[0;34m[REMOTE]\033[0m Verifying health..."
sleep 3
if curl -sf http://127.0.0.1:9010/health > /dev/null; then
    echo -e "\033[0;32m[REMOTE] Application is healthy!\033[0m"
else
    echo -e "\033[0;31m[REMOTE] ERROR: Health check failed.\033[0m"
    sudo journalctl -u observability-app --no-pager -n 20
    exit 1
fi
EOF

    rm -f "$deploy_pkg"
}

# Main
log_info "Starting application code update..."
get_info

if ! _is_valid_ipv4 "$INSTANCE_IP"; then
    log_error "INSTANCE_IP is not a valid IP: '$INSTANCE_IP'"
    exit 1
fi
if [[ -z "$BASTION_IP" ]]; then
    log_warning "No BASTION_IP set. Will attempt direct SSH to $INSTANCE_IP."
fi

ensure_started "$INSTANCE_ID" "Application VM"

log_info "Waiting 30s for SSH to be ready..."
sleep 30

update_code

log_success "Code update completed successfully!"
