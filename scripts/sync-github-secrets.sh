#!/bin/bash
#
# sync-github-secrets.sh - Automatically sync local OCI info to GitHub Environment Secrets
#

set -euo pipefail

ENVIRONMENT_NAME="${GITHUB_ENVIRONMENT:-production}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$PROJECT_ROOT/deploy/terraform/environments/prod"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 1. Check gh CLI
if ! command -v gh &> /dev/null; then
    log_error "GitHub CLI (gh) is not installed. Please install it to sync secrets."
    exit 1
fi

# 2. Fetch info from Terraform
log_info "Fetching information from Terraform..."
if [[ ! -d "$TF_DIR" ]]; then
    log_error "Terraform directory not found: $TF_DIR"
    exit 1
fi

cd "$TF_DIR"
INSTANCE_IP=$(terraform output -raw instance_private_ip 2>/dev/null || echo "")
BASTION_IP=$(terraform output -raw bastion_public_ip 2>/dev/null || echo "")
INSTANCE_ID=$(terraform output -raw instance_id 2>/dev/null || echo "")

if [[ -z "$INSTANCE_IP" ]]; then
    log_error "Could not fetch Instance IP. Is Terraform deployed?"
    exit 1
fi

# 3. Get SSH Private Key
# Load from .env.local if possible
SSH_KEY_PATH=""
if [[ -f "$PROJECT_ROOT/.env.local" ]]; then
    SSH_KEY_PATH=$(grep "SSH_KEY=" "$PROJECT_ROOT/.env.local" | cut -d'=' -f2 | sed 's|^~|'"$HOME"'|')
fi

# Fallback
if [[ -z "$SSH_KEY_PATH" || ! -f "$SSH_KEY_PATH" ]]; then
    SSH_KEY_PATH="$HOME/.ssh/new_id_rsa"
fi

if [[ ! -f "$SSH_KEY_PATH" ]]; then
    log_error "SSH Private Key not found at $SSH_KEY_PATH"
    exit 1
fi

log_info "Syncing secrets to GitHub Environment: $ENVIRONMENT_NAME..."

# 4. Sync Secrets
gh secret set BASTION_IP --env "$ENVIRONMENT_NAME" --body "$BASTION_IP"
gh secret set INSTANCE_IP --env "$ENVIRONMENT_NAME" --body "$INSTANCE_IP"
gh secret set INSTANCE_ID --env "$ENVIRONMENT_NAME" --body "$INSTANCE_ID"
gh secret set SSH_PRIVATE_KEY --env "$ENVIRONMENT_NAME" < "$SSH_KEY_PATH"

log_success "All secrets synced successfully to GitHub!"
log_info "You can now push your code to trigger the deployment."
