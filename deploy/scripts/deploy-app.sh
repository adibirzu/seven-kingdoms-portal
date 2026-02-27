#!/bin/bash
#
# OCI Observability Overview - Application Deployment Script
# Deploys the application to VM or OKE
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DEPLOY_DIR="$PROJECT_ROOT/deploy"

# Load local environment variables if present
if [[ -f "$PROJECT_ROOT/.env.local" ]]; then
    # shellcheck disable=SC1091
    source "$PROJECT_ROOT/.env.local"
fi

# Default values
ENVIRONMENT="prod"
DEPLOYMENT_MODE="vm"
REGISTRY=""
IMAGE_TAG="latest"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Deploy application to any supported infrastructure.

Options:
    -e, --environment ENV   Environment (dev, prod) [default: prod]
    -m, --mode MODE         Deployment mode [default: vm]
                              vm                 - Deploy to OCI Compute VM via SSH
                              docker             - Run locally with Docker Compose
                              container-instance - Deploy to OCI Container Instance
                              oke                - Deploy to OKE (Kubernetes)
    -r, --registry URL      Container registry URL (required for oke/container-instance)
    -t, --tag TAG           Image tag [default: latest]
    -h, --help              Show this help message

Examples:
    # Deploy to VM (existing behavior)
    $(basename "$0") --mode vm

    # Run locally with Docker
    $(basename "$0") --mode docker

    # Deploy to OCI Container Instance
    $(basename "$0") --mode container-instance --registry fra.ocir.io/namespace --tag v1.0.0

    # Deploy to OKE
    $(basename "$0") --mode oke --registry fra.ocir.io/namespace
EOF
    exit 0
}

get_terraform_output() {
    local key="$1"
    cd "$DEPLOY_DIR/terraform/environments/$ENVIRONMENT"
    terraform output -raw "$key" 2>/dev/null || echo ""
}

deploy_to_vm() {
    log_info "Deploying application to VM..."

    local instance_ip
    instance_ip=$(get_terraform_output "instance_private_ip")
    local bastion_ip
    bastion_ip=$(get_terraform_output "bastion_public_ip")

    if [[ -z "$instance_ip" ]]; then
        log_error "Could not get instance IP from Terraform output"
        exit 1
    fi

    log_info "Target VM IP: $instance_ip"

    # Create deployment package
    local deploy_pkg="/tmp/observability-deploy.tar.gz"
    log_info "Creating deployment package..."

    cd "$PROJECT_ROOT"
    tar -czf "$deploy_pkg" \
        --exclude='.git' \
        --exclude='deploy' \
        --exclude='__pycache__' \
        --exclude='.venv' \
        --exclude='venv' \
        --exclude='*.pyc' \
        --exclude='.DS_Store' \
        .

    # Deployment behavior tuning
    local ssh_connect_timeout="${C6_SSH_CONNECT_TIMEOUT_SECONDS:-10}"
    local cloud_init_timeout="${C6_REMOTE_CLOUD_INIT_TIMEOUT_SECONDS:-900}"
    local cloud_init_strict="${C6_REMOTE_CLOUD_INIT_STRICT:-false}"

    # Determine SSH key
    local key_path="${SSH_KEY:-}"
    
    # Fallback to identified project key if not provided
    if [[ -z "$key_path" ]]; then
        if [[ -f "$HOME/.ssh/new_id_rsa" ]]; then
            key_path="$HOME/.ssh/new_id_rsa"
            log_info "No SSH_KEY provided, defaulting to $key_path"
        fi
    fi

    local ssh_key_args=()
    if [[ -n "$key_path" ]]; then
        ssh_key_args=("-i" "$key_path")
        log_info "Using identity file: $key_path"
    fi

    # Determine SSH command
    local jump_options=(
        "-o" "StrictHostKeyChecking=no"
        "-o" "ConnectTimeout=${ssh_connect_timeout}"
        "-o" "ServerAliveInterval=15"
        "-o" "ServerAliveCountMax=3"
    )
    if [[ -n "$bastion_ip" ]]; then
        log_info "Using bastion host: $bastion_ip"
        local proxy_command="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=${ssh_connect_timeout}"
        if [[ -n "$key_path" ]]; then
            proxy_command+=" -i $key_path"
        fi
        proxy_command+=" -W %h:%p opc@$bastion_ip"
        jump_options+=("-o" "ProxyCommand=${proxy_command}")
    else
        log_warning "No bastion host available. Ensure you have direct VPN/FastConnect access."
    fi

    # Copy deployment package
    log_info "Copying deployment package to VM..."
    scp "${ssh_key_args[@]}" "${jump_options[@]}" "$deploy_pkg" "opc@$instance_ip:/tmp/"

    # Deploy on VM
    log_info "Installing application on VM..."
    ssh "${ssh_key_args[@]}" "${jump_options[@]}" "opc@$instance_ip" \
        "C6_CLOUD_INIT_TIMEOUT=${cloud_init_timeout} C6_CLOUD_INIT_STRICT=${cloud_init_strict} bash -s" << 'DEPLOY_SCRIPT'
set -e

# Wait for cloud-init to finish (max 10 minutes)
echo -e "\033[0;34m[REMOTE]\033[0m Waiting for cloud-init to complete..."
TIMEOUT="${C6_CLOUD_INIT_TIMEOUT:-900}"
STRICT_MODE="$(printf '%s' "${C6_CLOUD_INIT_STRICT:-false}" | tr '[:upper:]' '[:lower:]')"
ELAPSED=0
until [ -f /var/log/cloud-init-app.log ] && grep -q "Cloud-init completed" /var/log/cloud-init-app.log || [ $ELAPSED -ge $TIMEOUT ]; do
    sleep 10
    ((ELAPSED+=10))
    echo -e "  Still waiting... ($ELAPSED/$TIMEOUT seconds)"
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    if [ "$STRICT_MODE" = "true" ] || [ "$STRICT_MODE" = "1" ] || [ "$STRICT_MODE" = "yes" ]; then
        echo -e "\033[0;31m[REMOTE] ERROR: Cloud-init timed out in strict mode.\033[0m"
        exit 1
    fi
    echo -e "\033[1;33m[REMOTE] WARNING: Cloud-init marker not found after ${TIMEOUT}s; continuing.\033[0m"
fi

# Extract application
echo -e "\033[0;34m[REMOTE]\033[0m Performing clean deployment..."
sudo fuser -k 9010/tcp || true
sudo rm -rf /opt/observability/app/*
sudo tar -xzf /tmp/observability-deploy.tar.gz -C /opt/observability/app
sudo chown -R observability:observability /opt/observability/app
rm -f /tmp/observability-deploy.tar.gz

# Install/update Python dependencies
sudo -u observability bash -c '
    source /opt/observability/venv/bin/activate
    cd /opt/observability/app
    pip install --no-cache-dir -r requirements.txt
'

# Enable and restart service
sudo systemctl enable observability-app
sudo systemctl restart observability-app

# Health check: poll /health endpoint until ready (max 30s)
echo "Waiting for application to become healthy..."
HEALTH_OK=0
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:9010/health > /dev/null 2>&1; then
        HEALTH_OK=1
        break
    fi
    # Check if process is still alive
    if ! sudo systemctl is-active --quiet observability-app; then
        echo "ERROR: Service stopped unexpectedly"
        sudo journalctl -u observability-app --no-pager -n 30
        exit 1
    fi
    sleep 1
done

if [ "$HEALTH_OK" = "1" ]; then
    echo "Application is healthy and serving on port 9010"
    curl -s http://127.0.0.1:9010/health
    echo ""
else
    echo "ERROR: Health check timed out after 30s"
    sudo journalctl -u observability-app --no-pager -n 50
    exit 1
fi
DEPLOY_SCRIPT

    # Cleanup
    rm -f "$deploy_pkg"

    # Ensure backend is registered with the load balancer
    local lb_id
    lb_id=$(get_terraform_output "lb_id")
    local backend_set_name
    backend_set_name=$(get_terraform_output "backend_set_name")

    if [[ -n "$lb_id" && -n "$backend_set_name" ]]; then
        log_info "Verifying load balancer backend registration..."

        # Check if backend already exists
        local existing_backend
        existing_backend=$(oci lb backend list \
            --load-balancer-id "$lb_id" \
            --backend-set-name "$backend_set_name" \
            --query "data[?\"ip-address\"=='$instance_ip'].\"ip-address\" | [0]" \
            --raw-output 2>/dev/null || echo "")

        if [[ -z "$existing_backend" || "$existing_backend" == "null" ]]; then
            log_info "Registering VM ($instance_ip:${backend_port:-9010}) with load balancer..."
            oci lb backend create \
                --load-balancer-id "$lb_id" \
                --backend-set-name "$backend_set_name" \
                --ip-address "$instance_ip" \
                --port "${backend_port:-9010}" \
                --wait-for-state SUCCEEDED \
                --wait-for-state FAILED 2>/dev/null || log_warning "Backend registration via CLI failed - verify in Terraform state"
        else
            log_info "Backend already registered with load balancer"
        fi
    else
        log_warning "Could not get LB details from Terraform - verify backend registration manually"
    fi

    log_success "Application deployed to VM successfully!"
}

deploy_to_oke() {
    log_info "Deploying application to OKE..."

    if [[ -z "$REGISTRY" ]]; then
        log_error "Container registry is required for OKE deployment"
        log_info "Use --registry fra.ocir.io/your-namespace"
        exit 1
    fi

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        exit 1
    fi

    # Get kubeconfig
    local cluster_id
    cluster_id=$(get_terraform_output "oke_cluster_id")
    if [[ -z "$cluster_id" ]]; then
        log_error "Could not get OKE cluster ID from Terraform output"
        exit 1
    fi

    log_info "Configuring kubectl..."
    oci ce cluster create-kubeconfig \
        --cluster-id "$cluster_id" \
        --file "$HOME/.kube/config" \
        --token-version 2.0.0 \
        --kube-endpoint PUBLIC_ENDPOINT

    # Create/update K8s secrets from environment variables
    local ns="observability-app"
    kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f -

    log_info "Creating K8s secrets from environment..."
    kubectl create secret generic observability-secrets \
        --from-literal=OCI_APM_ENDPOINT="${OCI_APM_ENDPOINT:-}" \
        --from-literal=OCI_APM_PUBLIC_DATAKEY="${OCI_APM_PUBLIC_DATAKEY:-}" \
        --from-literal=OCI_APM_PRIVATE_DATAKEY="${OCI_APM_PRIVATE_DATAKEY:-}" \
        --from-literal=OCI_LOG_OCID="${OCI_LOG_OCID:-}" \
        --from-literal=OCI_LOG_GROUP_OCID="${OCI_LOG_GROUP_OCID:-}" \
        --from-literal=OCI_COMPARTMENT_OCID="${OCI_COMPARTMENT_OCID:-}" \
        --from-literal=PORTAL_JWT_SECRET="${PORTAL_JWT_SECRET:-seven-kingdoms-secret-key-2024}" \
        -n "$ns" --dry-run=client -o yaml | kubectl apply -f -

    # Build and push Docker image
    log_info "Building Docker image..."
    cd "$PROJECT_ROOT"

    local image_name="$REGISTRY/observability-app:$IMAGE_TAG"

    docker build -t "$image_name" -f deploy/docker/Dockerfile .

    log_info "Pushing image to registry..."
    docker push "$image_name"

    # Update Kustomize with image
    cd "$DEPLOY_DIR/kubernetes/overlays/$ENVIRONMENT"

    # Set the image via kustomize before applying
    log_info "Setting image to $image_name in Kustomize overlay..."
    if command -v kustomize &> /dev/null; then
        kustomize edit set image "observability-app=$image_name"
    else
        # Fallback: use kubectl kustomize with image override
        log_info "kustomize CLI not found, using kubectl apply -k with image override"
    fi

    # Apply Kubernetes manifests
    log_info "Applying Kubernetes manifests..."

    # Create namespace if not exists
    kubectl create namespace observability-app --dry-run=client -o yaml | kubectl apply -f -

    # Apply with Kustomize
    kubectl apply -k .

    # Ensure image is correct (in case kustomize edit wasn't available)
    kubectl set image deployment/observability-app \
        app="$image_name" \
        -n observability-app

    # Wait for rollout
    log_info "Waiting for deployment rollout..."
    kubectl rollout status deployment/observability-app -n observability-app --timeout=300s

    # Get service external IP
    log_info "Getting service external IP..."
    local external_ip=""
    local attempts=0
    while [[ -z "$external_ip" && $attempts -lt 30 ]]; do
        external_ip=$(kubectl get svc observability-app -n observability-app \
            -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
        if [[ -z "$external_ip" ]]; then
            sleep 10
            ((attempts++))
        fi
    done

    if [[ -n "$external_ip" ]]; then
        log_success "Application deployed to OKE successfully!"
        log_info "External IP: $external_ip"
        log_info "Access URL: http://$external_ip"
    else
        log_warning "External IP not yet available. Check with:"
        log_info "kubectl get svc observability-app -n observability-app"
    fi
}

build_docker_image() {
    log_info "Building Docker image locally..."

    cd "$PROJECT_ROOT"

    docker build -t observability-app:local -f deploy/docker/Dockerfile .

    log_success "Docker image built: observability-app:local"
}

deploy_to_docker() {
    log_info "Deploying application with Docker Compose..."

    cd "$PROJECT_ROOT"

    # Check Docker is available
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    # Build and start
    log_info "Building and starting container..."
    docker compose -f deploy/docker/docker-compose.yml up --build -d

    # Health check
    local port="${APP_PORT:-9010}"
    log_info "Waiting for application to become healthy on port $port..."
    local health_ok=0
    for i in $(seq 1 30); do
        if curl -sf "http://localhost:${port}/health" > /dev/null 2>&1; then
            health_ok=1
            break
        fi
        sleep 1
    done

    if [[ "$health_ok" == "1" ]]; then
        log_success "Application deployed with Docker Compose!"
        log_info "Access URL: http://localhost:${port}"
        log_info "Logs:       docker compose -f deploy/docker/docker-compose.yml logs -f"
        log_info "Stop:       docker compose -f deploy/docker/docker-compose.yml down"
    else
        log_error "Health check timed out after 30s"
        docker compose -f deploy/docker/docker-compose.yml logs --tail 30
        exit 1
    fi
}

deploy_to_container_instance() {
    log_info "Deploying application to OCI Container Instance..."

    if [[ -z "$REGISTRY" ]]; then
        log_error "Container registry is required for container-instance deployment"
        log_info "Use --registry fra.ocir.io/your-namespace"
        exit 1
    fi

    # Check OCI CLI
    if ! command -v oci &> /dev/null; then
        log_error "OCI CLI is required for container-instance deployment"
        exit 1
    fi

    local image_name="$REGISTRY/observability-app:$IMAGE_TAG"

    # Build and push image
    log_info "Building Docker image..."
    cd "$PROJECT_ROOT"
    docker build -t "$image_name" -f deploy/docker/Dockerfile .

    log_info "Pushing image to $image_name..."
    docker push "$image_name"

    # Check for container instance config
    local ci_config="$DEPLOY_DIR/oci-container-instance/container-instance.json"
    if [[ ! -f "$ci_config" ]]; then
        log_error "Container instance config not found at $ci_config"
        exit 1
    fi

    # Validate required variables
    local compartment_id="${OCI_COMPARTMENT_OCID:-}"
    if [[ -z "$compartment_id" ]]; then
        log_error "OCI_COMPARTMENT_OCID is required. Set it in .env.local"
        exit 1
    fi

    # Generate config with actual values substituted
    local rendered_config="/tmp/ci-config-rendered.json"
    sed \
        -e "s|<COMPARTMENT_OCID>|${OCI_COMPARTMENT_OCID:-}|g" \
        -e "s|<AD_NAME>|${OCI_AD_NAME:-$(oci iam availability-domain list --compartment-id "$compartment_id" --query 'data[0].name' --raw-output 2>/dev/null || echo "")}|g" \
        -e "s|<REGION>|${OCI_REGION:-fra}|g" \
        -e "s|<NAMESPACE>|$(echo "$REGISTRY" | sed 's|.*ocir.io/||')|g" \
        -e "s|<TAG>|${IMAGE_TAG}|g" \
        -e "s|<APM_ENDPOINT_URL>|${OCI_APM_ENDPOINT:-}|g" \
        -e "s|<APM_PUBLIC_KEY>|${OCI_APM_PUBLIC_DATAKEY:-}|g" \
        -e "s|<APM_PRIVATE_KEY>|${OCI_APM_PRIVATE_DATAKEY:-}|g" \
        -e "s|<LOG_OCID>|${OCI_LOG_OCID:-}|g" \
        -e "s|<JWT_SECRET>|${PORTAL_JWT_SECRET:-seven-kingdoms-secret-key-2024}|g" \
        -e "s|<SUBNET_OCID>|${OCI_SUBNET_OCID:-}|g" \
        -e "s|<NSG_OCID>|${OCI_NSG_OCID:-}|g" \
        "$ci_config" > "$rendered_config"

    # Update image URL in rendered config
    python3 -c "
import json, sys
with open('$rendered_config') as f:
    config = json.load(f)
config['containers'][0]['imageUrl'] = '$image_name'
# Remove the _comment field
config.pop('_comment', None)
with open('$rendered_config', 'w') as f:
    json.dump(config, f, indent=2)
"

    log_info "Creating OCI Container Instance..."
    local ci_id
    ci_id=$(oci container-instances container-instance create \
        --from-json "file://$rendered_config" \
        --query 'data.id' --raw-output 2>&1) || {
        log_error "Failed to create container instance: $ci_id"
        rm -f "$rendered_config"
        exit 1
    }

    rm -f "$rendered_config"

    log_success "Container Instance created: $ci_id"
    log_info "Check status: oci container-instances container-instance get --container-instance-id $ci_id"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -m|--mode)
            DEPLOYMENT_MODE="$2"
            shift 2
            ;;
        -r|--registry)
            REGISTRY="$2"
            shift 2
            ;;
        -t|--tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate inputs
if [[ ! "$ENVIRONMENT" =~ ^(dev|prod)$ ]]; then
    log_error "Invalid environment: $ENVIRONMENT"
    exit 1
fi

if [[ ! "$DEPLOYMENT_MODE" =~ ^(vm|docker|container-instance|oke)$ ]]; then
    log_error "Invalid deployment mode: $DEPLOYMENT_MODE. Must be 'vm', 'docker', 'container-instance', or 'oke'"
    exit 1
fi

# Main execution
echo ""
echo "=============================================="
echo "  OCI Observability Overview - App Deploy"
echo "=============================================="
echo "  Environment:     $ENVIRONMENT"
echo "  Deployment Mode: $DEPLOYMENT_MODE"
if [[ -n "$REGISTRY" ]]; then
    echo "  Registry:        $REGISTRY"
    echo "  Image Tag:       $IMAGE_TAG"
fi
echo "=============================================="
echo ""

case "$DEPLOYMENT_MODE" in
    vm)
        deploy_to_vm
        ;;
    docker)
        deploy_to_docker
        ;;
    container-instance)
        deploy_to_container_instance
        ;;
    oke)
        deploy_to_oke
        ;;
esac

echo ""
log_success "Deployment completed!"

# Show access URLs (skip for docker mode — already shown)
if [[ "$DEPLOYMENT_MODE" != "docker" ]]; then
    lb_ip=$(get_terraform_output "lb_public_ip" 2>/dev/null || echo "")
    if [[ -n "$lb_ip" ]]; then
        echo ""
        log_info "Access URLs:"
        echo "  - http://$lb_ip"
    fi
fi
