#!/usr/bin/env bash
# C5: Destroy WAF resources.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="$ROOT_DIR/deploy/terraform/environments/dev"

echo "=== C5: WAF Teardown ==="

if [[ ! -d "$TF_DIR/.terraform" ]]; then
    echo "  No Terraform state found."
    exit 0
fi

cd "$TF_DIR"
terraform destroy -auto-approve -target=module.waf || true

echo "  WAF destroyed."
