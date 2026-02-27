#!/bin/bash
#
# Setup SSL certificates using Let's Encrypt (Certbot)
# Run this after infrastructure is deployed
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DEPLOY_DIR="$PROJECT_ROOT/deploy"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Domains
PRIMARY_DOMAIN="observability.learnoci.cloud"
SECONDARY_DOMAIN="observability.cyber-sec.ro"
EMAIL=""
ENVIRONMENT="prod"

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Generate SSL certificates using Let's Encrypt.

Options:
    -e, --email EMAIL       Email for Let's Encrypt registration (required)
    -d, --domain DOMAIN     Additional domain (can be repeated)
    --env ENV               Environment (dev, prod) [default: prod]
    -h, --help              Show this help message

Prerequisites:
    - DNS must be configured and propagated
    - Port 80 must be accessible from the internet
    - certbot must be installed

Examples:
    $(basename "$0") --email admin@example.com

    $(basename "$0") --email admin@example.com --domain custom.example.com
EOF
    exit 0
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v certbot &> /dev/null; then
        log_error "certbot is not installed"
        log_info "Install with: brew install certbot (macOS) or apt install certbot (Linux)"
        exit 1
    fi

    if [[ -z "$EMAIL" ]]; then
        log_error "Email is required for Let's Encrypt registration"
        usage
    fi
}

verify_dns() {
    local domain="$1"
    log_info "Verifying DNS for $domain..."

    if ! host "$domain" &> /dev/null; then
        log_warning "DNS not resolving for $domain"
        return 1
    fi

    log_success "DNS verified for $domain"
    return 0
}

get_certificates() {
    log_info "Requesting certificates from Let's Encrypt..."

    local domains=""

    if verify_dns "$PRIMARY_DOMAIN"; then
        domains="-d $PRIMARY_DOMAIN"
    fi

    if verify_dns "$SECONDARY_DOMAIN"; then
        domains="$domains -d $SECONDARY_DOMAIN"
    fi

    if [[ -z "$domains" ]]; then
        log_error "No domains could be verified. Check DNS configuration."
        exit 1
    fi

    # Create certificate directory
    local cert_dir="$DEPLOY_DIR/certs"
    mkdir -p "$cert_dir"

    # Request certificate
    sudo certbot certonly \
        --standalone \
        --agree-tos \
        --email "$EMAIL" \
        --non-interactive \
        $domains

    log_success "Certificates obtained!"

    # Copy to deploy directory
    local cert_live="/etc/letsencrypt/live/$PRIMARY_DOMAIN"
    if [[ -d "$cert_live" ]]; then
        sudo cp "$cert_live/fullchain.pem" "$cert_dir/"
        sudo cp "$cert_live/privkey.pem" "$cert_dir/"
        sudo cp "$cert_live/chain.pem" "$cert_dir/"
        sudo chown -R "$USER" "$cert_dir"
        chmod 600 "$cert_dir"/*.pem

        log_success "Certificates copied to $cert_dir"
    fi
}

show_terraform_config() {
    local cert_dir="$DEPLOY_DIR/certs"

    echo ""
    log_info "Add the following to your terraform.tfvars:"
    echo ""
    cat << EOF
ssl_certificate_name   = "observability-ssl"
ssl_public_certificate = <<-EOT
$(cat "$cert_dir/fullchain.pem" 2>/dev/null || echo "# Certificate content here")
EOT

ssl_private_key = <<-EOT
$(cat "$cert_dir/privkey.pem" 2>/dev/null || echo "# Private key content here")
EOT

ssl_ca_certificate = <<-EOT
$(cat "$cert_dir/chain.pem" 2>/dev/null || echo "# CA chain content here")
EOT
EOF
    echo ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--email) EMAIL="$2"; shift 2 ;;
        --env) ENVIRONMENT="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

echo ""
echo "=============================================="
echo "  SSL Certificate Setup"
echo "=============================================="
echo "  Primary Domain:   $PRIMARY_DOMAIN"
echo "  Secondary Domain: $SECONDARY_DOMAIN"
echo "  Email:            $EMAIL"
echo "=============================================="
echo ""

check_prerequisites
get_certificates
show_terraform_config

log_success "SSL setup completed!"
log_info "Re-run terraform apply to update the load balancer with SSL"
