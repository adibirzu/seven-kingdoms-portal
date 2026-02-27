#!/usr/bin/env bash
# C1: Destroy infrastructure (Terraform destroy).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="$ROOT_DIR/deploy/terraform/environments/dev"

echo "=== C1: Infrastructure Teardown ==="

if [[ ! -d "$TF_DIR/.terraform" ]]; then
    echo "  No Terraform state found — nothing to destroy."
    exit 0
fi

cd "$TF_DIR"
echo "  Running terraform destroy..."
terraform destroy -auto-approve

echo "  Infrastructure destroyed."
