#!/bin/bash
#
# OCI Observability Overview - Cleanup Script
# Removes all deployed resources
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DEPLOY_DIR="$PROJECT_ROOT/deploy"

ENVIRONMENT="prod"
FORCE=""
CLEANUP_DOCKER=""
CLEANUP_K8S=""

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Cleanup OCI Observability Overview deployment.

Options:
    -e, --environment ENV   Environment (dev, prod) [default: prod]
    -f, --force             Skip confirmation prompts
    --docker                Also remove local Docker images
    --k8s                   Also cleanup Kubernetes resources
    -h, --help              Show this help message

Examples:
    # Cleanup production (with confirmation)
    $(basename "$0") --environment prod

    # Force cleanup without confirmation
    $(basename "$0") --environment prod --force

    # Full cleanup including Docker and K8s
    $(basename "$0") --environment prod --force --docker --k8s
EOF
    exit 0
}

cleanup_kubernetes() {
    log_info "Cleaning up Kubernetes resources..."

    if command -v kubectl &> /dev/null; then
        kubectl delete namespace observability-app --ignore-not-found=true 2>/dev/null || true
        kubectl delete namespace observability-app-dev --ignore-not-found=true 2>/dev/null || true
        log_success "Kubernetes resources cleaned up"
    else
        log_warning "kubectl not found, skipping Kubernetes cleanup"
    fi
}

cleanup_docker() {
    log_info "Cleaning up Docker images..."

    if command -v docker &> /dev/null; then
        docker rmi observability-app:local 2>/dev/null || true
        docker rmi $(docker images -q '*observability-app*' 2>/dev/null) 2>/dev/null || true
        log_success "Docker images cleaned up"
    else
        log_warning "Docker not found, skipping Docker cleanup"
    fi
}

cleanup_terraform() {
    log_info "Destroying Terraform infrastructure..."

    cd "$DEPLOY_DIR/terraform/environments/$ENVIRONMENT"

    if [[ ! -f "terraform.tfstate" ]]; then
        log_warning "No Terraform state found, nothing to destroy"
        return
    fi

    if [[ -n "$FORCE" ]]; then
        terraform destroy -auto-approve
    else
        terraform destroy
    fi

    log_success "Terraform infrastructure destroyed"
}

cleanup_local_files() {
    log_info "Cleaning up local files..."

    # Remove Terraform files
    cd "$DEPLOY_DIR/terraform/environments/$ENVIRONMENT"
    rm -f tfplan
    rm -rf .terraform
    rm -f .terraform.lock.hcl

    # Remove temporary files
    rm -f /tmp/observability-deploy.tar.gz

    log_success "Local files cleaned up"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -f|--force)
            FORCE="true"
            shift
            ;;
        --docker)
            CLEANUP_DOCKER="true"
            shift
            ;;
        --k8s)
            CLEANUP_K8S="true"
            shift
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

# Confirmation
if [[ -z "$FORCE" ]]; then
    echo ""
    log_warning "This will destroy ALL resources in the '$ENVIRONMENT' environment!"
    echo ""
    read -p "Are you sure you want to continue? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        log_info "Cleanup cancelled"
        exit 0
    fi
fi

echo ""
echo "=============================================="
echo "  OCI Observability Overview - Cleanup"
echo "=============================================="
echo "  Environment: $ENVIRONMENT"
echo "=============================================="
echo ""

# Run cleanup
if [[ -n "$CLEANUP_K8S" ]]; then
    cleanup_kubernetes
fi

if [[ -n "$CLEANUP_DOCKER" ]]; then
    cleanup_docker
fi

cleanup_terraform
cleanup_local_files

echo ""
log_success "Cleanup completed!"
