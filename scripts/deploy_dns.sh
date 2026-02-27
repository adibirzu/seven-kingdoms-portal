#!/usr/bin/env bash
# C6: Deploy DNS zone and records via Terraform.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TF_DIR="$ROOT_DIR/deploy/terraform/environments/dev"

echo "=== C6: DNS Deployment ==="

: "${OCI_COMPARTMENT_ID:?OCI_COMPARTMENT_ID is required}"
: "${DNS_ZONE_NAME:?DNS_ZONE_NAME is required}"

cd "$TF_DIR"

echo "  Running terraform plan (DNS module)..."
terraform plan -out=tfplan -input=false -target=module.dns

echo "  Running terraform apply..."
terraform apply -auto-approve tfplan
rm -f tfplan

echo ""
echo "  DNS deployment complete!"
echo "    Zone: ${DNS_ZONE_NAME}"
