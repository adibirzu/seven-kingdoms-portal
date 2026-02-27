#!/bin/bash
#
# Build and push Docker image to OCI Container Registry
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Defaults
REGISTRY=""
NAMESPACE=""
REGION="fra"
TAG="latest"
PUSH="false"

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Build Docker image for OCI Observability Overview.

Options:
    -r, --registry URL      Full registry URL (e.g., fra.ocir.io/namespace)
    -n, --namespace NS      OCI namespace (tenancy object storage namespace)
    -R, --region REGION     OCI region code (e.g., fra, iad, phx) [default: fra]
    -t, --tag TAG           Image tag [default: latest]
    -p, --push              Push image to registry after build
    -h, --help              Show this help message

Examples:
    # Build locally only
    $(basename "$0")

    # Build and push to OCIR
    $(basename "$0") --namespace mytenancy --region fra --tag v1.0.0 --push

    # Using full registry URL
    $(basename "$0") --registry fra.ocir.io/mytenancy --tag v1.0.0 --push
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--registry) REGISTRY="$2"; shift 2 ;;
        -n|--namespace) NAMESPACE="$2"; shift 2 ;;
        -R|--region) REGION="$2"; shift 2 ;;
        -t|--tag) TAG="$2"; shift 2 ;;
        -p|--push) PUSH="true"; shift ;;
        -h|--help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

# Determine registry URL
if [[ -z "$REGISTRY" && -n "$NAMESPACE" ]]; then
    REGISTRY="${REGION}.ocir.io/${NAMESPACE}"
fi

IMAGE_NAME="observability-app"
LOCAL_TAG="${IMAGE_NAME}:${TAG}"

if [[ -n "$REGISTRY" ]]; then
    REMOTE_TAG="${REGISTRY}/${IMAGE_NAME}:${TAG}"
fi

log_info "Building Docker image..."
log_info "  Local tag: $LOCAL_TAG"
if [[ -n "${REMOTE_TAG:-}" ]]; then
    log_info "  Remote tag: $REMOTE_TAG"
fi

cd "$PROJECT_ROOT"

# Build image
docker build \
    -t "$LOCAL_TAG" \
    -f deploy/docker/Dockerfile \
    --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --build-arg VERSION="$TAG" \
    .

log_success "Image built: $LOCAL_TAG"

# Push if requested
if [[ "$PUSH" == "true" ]]; then
    if [[ -z "$REGISTRY" ]]; then
        log_error "Registry URL required for push. Use --registry or --namespace"
        exit 1
    fi

    log_info "Tagging for remote registry..."
    docker tag "$LOCAL_TAG" "$REMOTE_TAG"

    log_info "Pushing to $REMOTE_TAG..."
    docker push "$REMOTE_TAG"

    log_success "Image pushed: $REMOTE_TAG"
fi

# Show image info
echo ""
log_info "Image details:"
docker images "$IMAGE_NAME" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
