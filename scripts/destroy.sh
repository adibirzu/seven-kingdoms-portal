#!/usr/bin/env bash
# Destroy all deployed resources (in reverse dependency order).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Seven Kingdoms Portal — Full Teardown ==="
echo ""
echo "WARNING: This will destroy ALL deployed resources."
echo "  - GOAD Windows VMs and jumpbox"
echo "  - Application VMs/OKE cluster"
echo "  - WAF, DNS, Observability resources"
echo "  - VCN and all network resources"
echo ""
read -p "Type 'yes' to confirm: " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted."
    exit 0
fi

echo ""

# Use the Python orchestrator for proper dependency ordering
cd "$ROOT_DIR"
python3 deploy.py --destroy --component all

echo ""
echo "  Teardown complete!"
