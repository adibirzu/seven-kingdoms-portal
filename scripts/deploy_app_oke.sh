#!/usr/bin/env bash
# C4 OKE: Build Docker image, push to OCIR, deploy to OKE cluster.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== C4: App OKE Deployment ==="

: "${OCI_COMPARTMENT_ID:?OCI_COMPARTMENT_ID is required}"
: "${OCI_REGION:?OCI_REGION is required}"
: "${OCIR_URL:?OCIR_URL is required (e.g., eu-frankfurt-1.ocir.io/namespace)}"

OCI_PROFILE="${OCI_PROFILE:-DEFAULT}"
IMAGE_TAG="${DOCKER_IMAGE_TAG:-latest}"
IMAGE_NAME="seven-kingdoms-portal"
FULL_IMAGE="${OCIR_URL}/${IMAGE_NAME}:${IMAGE_TAG}"
K8S_DIR="$ROOT_DIR/deploy/kubernetes"

echo "  Image: $FULL_IMAGE"

# Check tools
for tool in docker kubectl; do
    if ! command -v $tool &>/dev/null; then
        echo "ERROR: $tool not found"
        exit 1
    fi
done

cd "$ROOT_DIR"

# --- Step 1: Build Docker image ---
echo "  Building Docker image..."
docker build -f deploy/docker/Dockerfile -t "$FULL_IMAGE" .

# --- Step 2: Push to OCIR ---
echo "  Pushing to OCIR..."
OCIR_HOST=$(echo "$OCIR_URL" | cut -d'/' -f1)

# Login to OCIR (use auth token from env or OCI CLI)
if [[ -n "${OCIR_AUTH_TOKEN:-}" ]]; then
    echo "$OCIR_AUTH_TOKEN" | docker login "$OCIR_HOST" \
        --username "${OCI_NAMESPACE:-}/oracleidentitycloudservice/${OCIR_USERNAME:-}" \
        --password-stdin
fi

docker push "$FULL_IMAGE"
echo "  Pushed: $FULL_IMAGE"

# --- Step 3: Configure kubeconfig ---
echo "  Configuring kubeconfig..."
OKE_CLUSTER_ID="${OKE_CLUSTER_ID:-}"
if [[ -z "$OKE_CLUSTER_ID" ]]; then
    # Try to discover from Terraform
    TF_DIR="$ROOT_DIR/deploy/terraform/environments/dev"
    if [[ -f "$TF_DIR/terraform.tfstate" ]]; then
        OKE_CLUSTER_ID=$(cd "$TF_DIR" && terraform output -raw cluster_id 2>/dev/null || echo "")
    fi
fi

if [[ -n "$OKE_CLUSTER_ID" ]]; then
    oci ce cluster create-kubeconfig \
        --profile "$OCI_PROFILE" \
        --cluster-id "$OKE_CLUSTER_ID" \
        --file "$HOME/.kube/config" \
        --region "$OCI_REGION" \
        --token-version 2.0.0 \
        --kube-endpoint PUBLIC_ENDPOINT
fi

# --- Step 4: Apply Kubernetes manifests ---
echo "  Applying Kubernetes manifests..."
OVERLAY="${ENVIRONMENT:-production}"
if [[ "$OVERLAY" == "production" ]]; then
    OVERLAY="prod"
fi

OVERLAY_DIR="$K8S_DIR/overlays/$OVERLAY"
if [[ -d "$OVERLAY_DIR" ]]; then
    # Update image in kustomization
    cd "$OVERLAY_DIR"
    if command -v kustomize &>/dev/null; then
        kustomize edit set image "seven-kingdoms-portal=$FULL_IMAGE"
    fi
    kubectl apply -k "$OVERLAY_DIR"
else
    # Fall back to base manifests
    kubectl apply -k "$K8S_DIR/base"
fi

# --- Step 5: Wait for rollout ---
echo "  Waiting for deployment rollout..."
NAMESPACE="${K8S_NAMESPACE:-seven-kingdoms-portal}"
kubectl rollout status deployment/seven-kingdoms-portal \
    -n "$NAMESPACE" --timeout=300s || true

# --- Step 6: Get LoadBalancer IP ---
echo "  Waiting for LoadBalancer IP..."
for i in $(seq 1 60); do
    LB_IP=$(kubectl get svc seven-kingdoms-portal \
        -n "$NAMESPACE" \
        -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
    if [[ -n "$LB_IP" ]]; then
        break
    fi
    sleep 5
done

if [[ -n "$LB_IP" ]]; then
    APP_URL="http://${LB_IP}"
    echo "  LoadBalancer IP: $LB_IP"

    # Write to .env.local
    ENV_FILE="$ROOT_DIR/.env.local"
    if [[ ! -f "$ENV_FILE" ]]; then touch "$ENV_FILE"; fi

    _update_env() {
        local key="$1" val="$2"
        if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
            sed -i.bak "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
            rm -f "${ENV_FILE}.bak"
        else
            echo "${key}=${val}" >> "$ENV_FILE"
        fi
    }

    _update_env "APP_URL" "$APP_URL"
    _update_env "APP_INSTANCE_IP" "$LB_IP"
else
    echo "  WARNING: LoadBalancer IP not available yet"
fi

echo ""
echo "  OKE deployment complete!"
if [[ -n "${LB_IP:-}" ]]; then
    echo "    URL:    http://${LB_IP}"
    echo "    Portal: http://${LB_IP}/portal/"
    echo "    Health: http://${LB_IP}/health"
fi
