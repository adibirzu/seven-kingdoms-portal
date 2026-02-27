#!/bin/bash
#
# OCI Observability Overview - Destroy Infrastructure
# Selectively destroys compute resources while preserving critical infrastructure (LB, Network).
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Defaults
DESTROY_ALL=false
ENVIRONMENT="prod"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TERRAFORM_DIR="$PROJECT_ROOT/deploy/terraform/environments/$ENVIRONMENT"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    echo "Usage: $(basename "$0") [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --all       Destroy EVERYTHING (Compute, Network, LB, WAF, DNS)"
    echo "              Default: Destroys only Compute (VM/OKE) resources."
    echo "  --env       Environment to target (default: prod)"
    echo "  -h, --help  Show this help"
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --all)
            DESTROY_ALL=true
            shift
            ;;
        --env)
            ENVIRONMENT="$2"
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

if [ ! -d "$TERRAFORM_DIR" ]; then
    log_error "Terraform directory not found: $TERRAFORM_DIR"
    exit 1
fi

cd "$TERRAFORM_DIR"

echo "=============================================="
echo "  OCI Infrastructure Destruction"
echo "=============================================="
echo "  Environment: $ENVIRONMENT"
echo "  Scope:       $( [ "$DESTROY_ALL" = true ] && echo "FULL DESTRUCTION" || echo "COMPUTE ONLY (Preserve Network/LB/WAF)" )"
echo "=============================================="
echo ""

if [ "$DESTROY_ALL" = true ]; then
    log_warn "You are about to destroy ALL resources including Load Balancer and Public IP."
    read -p "Are you sure? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Aborted."
        exit 0
    fi
    
    log_info "Destroying all resources..."
    terraform destroy -auto-approve
else
    log_info "Destroying Compute resources only..."
    # Target only the compute module (for VM) or OKE module (for k8s)
    # Note: We rely on the deployment_mode variable in terraform to know which exists, 
    # but targeting a non-existent module is generally safe or ignored if count=0.
    
    # Check current mode to be precise
    MODE=$(grep 'deployment_mode' terraform.tfvars | cut -d'"' -f2 || echo "vm")
    
    if [[ "$MODE" == "vm" ]]; then
        terraform destroy -target=module.compute -auto-approve
    elif [[ "$MODE" == "oke" ]]; then
        terraform destroy -target=module.oke -auto-approve
    else
        # Hybrid or unknown - try both
        terraform destroy -target=module.compute -target=module.oke -auto-approve
    fi
fi

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}[SUCCESS]${NC} Destruction completed successfully."
else
    echo ""
    echo -e "${RED}[ERROR]${NC} Destruction failed."
    exit 1
fi
