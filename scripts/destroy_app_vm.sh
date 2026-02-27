#!/usr/bin/env bash
# C4 VM: Destroy app compute instance.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="$ROOT_DIR/deploy/terraform/environments/dev"

echo "=== C4: App VM Teardown ==="

if [[ ! -d "$TF_DIR/.terraform" ]]; then
    echo "  No Terraform state found."
    exit 0
fi

cd "$TF_DIR"
terraform destroy -auto-approve -target=module.compute || true

echo "  App VM destroyed."
