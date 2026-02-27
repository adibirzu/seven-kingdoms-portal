#!/usr/bin/env bash
# C6: Destroy DNS resources.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="$ROOT_DIR/deploy/terraform/environments/dev"

echo "=== C6: DNS Teardown ==="

if [[ ! -d "$TF_DIR/.terraform" ]]; then
    echo "  No Terraform state found."
    exit 0
fi

cd "$TF_DIR"
terraform destroy -auto-approve -target=module.dns || true

echo "  DNS destroyed."
