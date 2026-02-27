#!/usr/bin/env bash
# C4 VM Step 1: Deploy app compute instance via Terraform.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TF_DIR="$ROOT_DIR/deploy/terraform/environments/dev"

echo "=== C4: App VM Deployment (Terraform) ==="

: "${OCI_COMPARTMENT_ID:?OCI_COMPARTMENT_ID is required}"
: "${PRIVATE_SUBNET_OCID:?PRIVATE_SUBNET_OCID is required (deploy C1 first)}"

OCI_PROFILE="${OCI_PROFILE:-DEFAULT}"
SSH_PUBLIC_KEY_PATH="${SSH_PUBLIC_KEY_PATH:-$HOME/.ssh/id_rsa.pub}"

echo "  Deploying compute instance for app VM..."
echo "  Subnet: ${PRIVATE_SUBNET_OCID:0:40}..."

# Ensure the Terraform environment includes compute module
# This reuses deploy/terraform/modules/compute
cd "$TF_DIR"

# Add deployment_mode=vm to existing tfvars
if grep -q "^deployment_mode" terraform.tfvars 2>/dev/null; then
    sed -i.bak 's/^deployment_mode.*/deployment_mode = "vm"/' terraform.tfvars
    rm -f terraform.tfvars.bak
else
    echo 'deployment_mode = "vm"' >> terraform.tfvars
fi

echo "  Running terraform plan..."
terraform plan -out=tfplan -input=false -target=module.compute

echo "  Running terraform apply..."
terraform apply -auto-approve tfplan
rm -f tfplan

# Capture outputs
APP_INSTANCE_IP=$(terraform output -raw instance_private_ip 2>/dev/null || echo "")
BASTION_IP=$(terraform output -raw bastion_public_ip 2>/dev/null || echo "")

ENV_FILE="$ROOT_DIR/.env.local"
_update_env() {
    local key="$1" val="$2"
    if [[ -z "$val" ]]; then return; fi
    if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
        sed -i.bak "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
        rm -f "${ENV_FILE}.bak"
    else
        echo "${key}=${val}" >> "$ENV_FILE"
    fi
}

_update_env "APP_INSTANCE_IP" "$APP_INSTANCE_IP"
_update_env "BASTION_IP" "$BASTION_IP"

echo ""
echo "  VM deployed!"
echo "    Instance IP: $APP_INSTANCE_IP"
echo "    Bastion IP:  $BASTION_IP"
