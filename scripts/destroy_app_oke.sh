#!/usr/bin/env bash
# C4 OKE: Delete Kubernetes resources and optionally OKE cluster.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== C4: App OKE Teardown ==="

NAMESPACE="${K8S_NAMESPACE:-seven-kingdoms-portal}"

# Delete K8s resources
if command -v kubectl &>/dev/null; then
    echo "  Deleting Kubernetes resources in namespace $NAMESPACE..."
    kubectl delete namespace "$NAMESPACE" --ignore-not-found --timeout=120s 2>/dev/null || true
fi

# Optionally destroy OKE cluster (expensive to recreate)
if [[ "${DESTROY_OKE_CLUSTER:-false}" == "true" ]]; then
    TF_DIR="$ROOT_DIR/deploy/terraform/environments/dev"
    if [[ -d "$TF_DIR/.terraform" ]]; then
        cd "$TF_DIR"
        terraform destroy -auto-approve -target=module.oke || true
    fi
fi

echo "  OKE teardown complete."
