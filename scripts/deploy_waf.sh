#!/usr/bin/env bash
# C5: Deploy WAF policy via Terraform.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TF_DIR="$ROOT_DIR/deploy/terraform/environments/dev"

echo "=== C5: WAF Deployment ==="

: "${OCI_COMPARTMENT_ID:?OCI_COMPARTMENT_ID is required}"

OCI_PROFILE="${OCI_PROFILE:-DEFAULT}"

cd "$TF_DIR"

# Add WAF variables to tfvars
if ! grep -q "enable_waf" terraform.tfvars 2>/dev/null; then
    cat >> terraform.tfvars <<EOF

# WAF configuration
enable_waf             = true
enable_owasp_rules     = true
enable_rate_limiting   = true
rate_limit_threshold   = 1000
EOF
fi

echo "  Running terraform plan (WAF module)..."
terraform plan -out=tfplan -input=false -target=module.waf

echo "  Running terraform apply..."
terraform apply -auto-approve tfplan
rm -f tfplan

# Capture WAF outputs
WAF_POLICY_OCID=$(terraform output -raw waf_policy_id 2>/dev/null || echo "")

ENV_FILE="$ROOT_DIR/.env.local"
if [[ -n "$WAF_POLICY_OCID" ]]; then
    if grep -q "^WAF_POLICY_OCID=" "$ENV_FILE" 2>/dev/null; then
        sed -i.bak "s|^WAF_POLICY_OCID=.*|WAF_POLICY_OCID=${WAF_POLICY_OCID}|" "$ENV_FILE"
        rm -f "${ENV_FILE}.bak"
    else
        echo "WAF_POLICY_OCID=${WAF_POLICY_OCID}" >> "$ENV_FILE"
    fi
fi

echo ""
echo "  WAF deployed!"
echo "    WAF Policy: ${WAF_POLICY_OCID:0:40}..."
