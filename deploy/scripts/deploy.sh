#!/bin/bash
#
# OCI Observability Overview - Infrastructure Deployment Script
# Deploys OCI infrastructure using Terraform
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

# Default values
ENVIRONMENT="prod"
DEPLOYMENT_MODE="vm"
ACTION="apply"
AUTO_APPROVE=""

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

Deploy OCI infrastructure for Observability Overview application.

Options:
    -e, --environment ENV   Environment to deploy (dev, prod) [default: prod]
    -m, --mode MODE         Deployment mode (vm, oke, hybrid) [default: vm]
    -a, --action ACTION     Terraform action (plan, apply, destroy) [default: apply]
    -y, --auto-approve      Auto-approve Terraform changes
    -h, --help              Show this help message

Examples:
    # Deploy VM infrastructure to production
    $(basename "$0") --environment prod --mode vm

    # Plan OKE deployment
    $(basename "$0") --environment prod --mode oke --action plan

    # Deploy with auto-approval
    $(basename "$0") --environment prod --mode vm -y

    # Destroy infrastructure
    $(basename "$0") --environment prod --action destroy
EOF
    exit 0
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        log_error "Terraform is not installed. Please install Terraform >= 1.5.0"
        exit 1
    fi

    # Check OCI CLI
    if ! command -v oci &> /dev/null; then
        log_warning "OCI CLI is not installed. Some features may not work."
    fi

    # Check terraform.tfvars exists
    local tfvars_file="$DEPLOY_DIR/terraform/environments/$ENVIRONMENT/terraform.tfvars"
    if [[ ! -f "$tfvars_file" ]]; then
        log_error "terraform.tfvars not found at $tfvars_file"
        log_info "Please copy terraform.tfvars.example to terraform.tfvars and configure your values"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

init_terraform() {
    log_info "Initializing Terraform..."

    cd "$DEPLOY_DIR/terraform/environments/$ENVIRONMENT"

    terraform init -upgrade

    log_success "Terraform initialized"
}

run_terraform() {
    local action="$1"
    local mode_var="-var=deployment_mode=$DEPLOYMENT_MODE"

    cd "$DEPLOY_DIR/terraform/environments/$ENVIRONMENT"

    case "$action" in
        plan)
            log_info "Running Terraform plan..."
            terraform plan $mode_var -out=tfplan
            ;;
        apply)
            log_info "Running Terraform apply..."
            if [[ -n "$AUTO_APPROVE" ]]; then
                if [[ -f "tfplan" ]]; then
                    terraform apply $AUTO_APPROVE tfplan
                else
                    terraform apply $AUTO_APPROVE $mode_var
                fi
            else
                terraform apply $mode_var
            fi
            ;;
        destroy)
            log_warning "This will destroy all infrastructure!"
            if [[ -n "$AUTO_APPROVE" ]]; then
                terraform destroy $AUTO_APPROVE $mode_var
            else
                terraform destroy $mode_var
            fi
            ;;
        *)
            log_error "Unknown action: $action"
            exit 1
            ;;
    esac
}

show_outputs() {
    log_info "Terraform outputs:"
    echo ""

    cd "$DEPLOY_DIR/terraform/environments/$ENVIRONMENT"
    terraform output -json | python3 -c "
import json
import sys

data = json.load(sys.stdin)
for key, value in data.items():
    if value.get('sensitive'):
        print(f'  {key}: [SENSITIVE]')
    else:
        v = value.get('value')
        if isinstance(v, dict):
            print(f'  {key}:')
            for k, vv in v.items():
                print(f'    {k}: {vv}')
        else:
            print(f'  {key}: {v}')
"
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
        -a|--action)
            ACTION="$2"
            shift 2
            ;;
        -y|--auto-approve)
            AUTO_APPROVE="-auto-approve"
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

# Validate inputs
if [[ ! "$ENVIRONMENT" =~ ^(dev|prod)$ ]]; then
    log_error "Invalid environment: $ENVIRONMENT. Must be 'dev' or 'prod'"
    exit 1
fi

if [[ ! "$DEPLOYMENT_MODE" =~ ^(vm|oke|hybrid)$ ]]; then
    log_error "Invalid deployment mode: $DEPLOYMENT_MODE. Must be 'vm', 'oke', or 'hybrid'"
    exit 1
fi

if [[ ! "$ACTION" =~ ^(plan|apply|destroy)$ ]]; then
    log_error "Invalid action: $ACTION. Must be 'plan', 'apply', or 'destroy'"
    exit 1
fi

# Main execution
echo ""
echo "=============================================="
echo "  OCI Observability Overview Deployment"
echo "=============================================="
echo "  Environment:     $ENVIRONMENT"
echo "  Deployment Mode: $DEPLOYMENT_MODE"
echo "  Action:          $ACTION"
echo "=============================================="
echo ""

check_prerequisites
init_terraform
run_terraform "$ACTION"

if [[ "$ACTION" == "apply" ]]; then
    echo ""
    show_outputs
    echo ""
    
    # Sync to GitHub if possible (non-critical — failure must not abort deployment)
    if [[ -f "$PROJECT_ROOT/scripts/sync-github-secrets.sh" ]] && command -v gh &> /dev/null; then
        log_info "Syncing infrastructure info to GitHub Secrets..."
        "$PROJECT_ROOT/scripts/sync-github-secrets.sh" || log_warning "GitHub Secrets sync failed (non-critical)"
    fi

    log_success "Deployment completed successfully!"
    log_info "Next step: Run ./deploy-app.sh to deploy the application"
fi
