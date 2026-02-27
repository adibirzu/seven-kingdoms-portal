#!/usr/bin/env bash
# C2: Destroy GOAD infrastructure (Terraform destroy).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="$ROOT_DIR/goad/terraform"

echo "=== C2: GOAD Teardown ==="

if [[ ! -d "$TF_DIR/.terraform" ]]; then
    echo "  No Terraform state found — nothing to destroy."
    exit 0
fi

cd "$TF_DIR"
echo "  Running terraform destroy..."
terraform destroy -auto-approve

echo "  GOAD infrastructure destroyed."
