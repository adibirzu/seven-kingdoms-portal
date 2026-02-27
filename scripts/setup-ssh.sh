#!/bin/bash
#
# setup-ssh.sh - Synchronize local SSH key with Terraform
#

set -euo pipefail

SSH_KEY_NAME="new_id_rsa"
SSH_DIR="$HOME/.ssh"
PRIVATE_KEY="$SSH_DIR/$SSH_KEY_NAME"
PUBLIC_KEY="$PRIVATE_KEY.pub"
TF_VARS="deploy/terraform/environments/prod/terraform.tfvars"

log_info() { echo -e "\033[0;34m[INFO]\033[0m $1"; }
log_success() { echo -e "\033[0;32m[SUCCESS]\033[0m $1"; }

# 1. Ensure SSH key exists
if [[ ! -f "$PRIVATE_KEY" ]]; then
    log_info "Generating new SSH key: $SSH_KEY_NAME"
    ssh-keygen -t rsa -b 4096 -f "$PRIVATE_KEY" -N ""
else
    log_info "Found existing SSH key: $PRIVATE_KEY"
fi

# 2. Extract public key
PUB_CONTENT=$(cat "$PUBLIC_KEY")

# 3. Update terraform.tfvars
if [[ -f "$TF_VARS" ]]; then
    log_info "Updating Terraform variables with the public key..."
    grep -v "ssh_public_key =" "$TF_VARS" > "$TF_VARS.tmp"
    echo "ssh_public_key = \"$PUB_CONTENT\"" >> "$TF_VARS.tmp"
    mv "$TF_VARS.tmp" "$TF_VARS"
    log_success "Updated $TF_VARS"
fi

# 4. Update .env.local
if [[ -f ".env.local" ]]; then
    log_info "Updating .env.local..."
    grep -v "SSH_KEY=" ".env.local" > ".env.local.tmp"
    echo "SSH_KEY=$PRIVATE_KEY" >> ".env.local.tmp"
    mv ".env.local.tmp" ".env.local"
    log_success "Updated .env.local"
fi
