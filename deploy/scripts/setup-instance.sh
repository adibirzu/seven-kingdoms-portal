#!/bin/bash
#
# OCI Observability Overview - Instance Setup Verification
# Run this on the VM (via bastion) after cloud-init to verify setup
# and perform first-time application deployment.
#
# Usage:
#   # Through bastion:
#   ssh -J opc@<bastion-ip> opc@<instance-ip> 'bash -s' < setup-instance.sh
#
#   # Or copy and run:
#   scp -o ProxyJump=opc@<bastion-ip> setup-instance.sh opc@<instance-ip>:/tmp/
#   ssh -J opc@<bastion-ip> opc@<instance-ip> 'bash /tmp/setup-instance.sh'
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC}    $1"; }
log_success() { echo -e "${GREEN}[OK]${NC}      $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $1"; }
log_error()   { echo -e "${RED}[FAIL]${NC}    $1"; }

CHECKS_PASSED=0
CHECKS_FAILED=0

check() {
    local description="$1"
    shift
    if "$@" > /dev/null 2>&1; then
        log_success "$description"
        ((CHECKS_PASSED++))
    else
        log_error "$description"
        ((CHECKS_FAILED++))
    fi
}

echo ""
echo "=============================================="
echo "  OCI Observability - Instance Setup Check"
echo "=============================================="
echo "  Hostname: $(hostname)"
echo "  Date:     $(date)"
echo "  OS:       $(cat /etc/oracle-release 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2)"
echo "=============================================="
echo ""

# 1. Check cloud-init completed
log_info "Checking cloud-init status..."
if [ -f /var/log/cloud-init-app.log ]; then
    if grep -q "Cloud-init completed" /var/log/cloud-init-app.log; then
        log_success "Cloud-init completed successfully"
        ((CHECKS_PASSED++))
    else
        log_warn "Cloud-init log exists but completion marker not found"
        log_info "Check: tail -50 /var/log/cloud-init-app.log"
        ((CHECKS_FAILED++))
    fi
else
    log_warn "Cloud-init app log not found - may still be running"
    log_info "Check: cloud-init status --wait"
    ((CHECKS_FAILED++))
fi

# 2. Check Python 3.11
echo ""
log_info "Checking Python environment..."
check "Python 3.11 installed" command -v python3.11
check "Virtual environment exists" test -d /opt/observability/venv
check "pip in venv works" /opt/observability/venv/bin/pip --version

# Check if core packages are installed
if /opt/observability/venv/bin/pip show fastapi > /dev/null 2>&1; then
    log_success "FastAPI installed in venv"
    ((CHECKS_PASSED++))
else
    log_warn "FastAPI not installed - will be installed during app deployment"
fi

if /opt/observability/venv/bin/pip show uvicorn > /dev/null 2>&1; then
    log_success "Uvicorn installed in venv"
    ((CHECKS_PASSED++))
else
    log_warn "Uvicorn not installed - will be installed during app deployment"
fi

# 3. Check application user
echo ""
log_info "Checking application user..."
check "User 'observability' exists" id observability
check "App directory exists" test -d /opt/observability
check "App directory owned by observability" test "$(stat -c %U /opt/observability)" = "observability"

# 4. Check systemd service
echo ""
log_info "Checking systemd service..."
check "Service unit file exists" test -f /etc/systemd/system/observability-app.service
if systemctl is-enabled observability-app > /dev/null 2>&1; then
    log_success "Service is enabled"
    ((CHECKS_PASSED++))
else
    log_info "Service not yet enabled (normal before first deployment)"
fi

# 5. Check firewall
echo ""
log_info "Checking firewall..."
check "firewalld is running" systemctl is-active firewalld
if sudo firewall-cmd --list-ports 2>/dev/null | grep -q "9010/tcp"; then
    log_success "Port 9010/tcp is open in firewall"
    ((CHECKS_PASSED++))
else
    log_error "Port 9010/tcp is NOT open in firewall"
    ((CHECKS_FAILED++))
fi

# 6. Check network connectivity
echo ""
log_info "Checking network connectivity..."
check "DNS resolution works" host oracle.com
check "NAT Gateway outbound works" curl -sf --max-time 5 -o /dev/null https://pypi.org/simple/

# 7. Check disk space
echo ""
log_info "Checking disk space..."
DISK_AVAIL=$(df -BG /opt/observability | tail -1 | awk '{print $4}' | tr -d 'G')
if [ "$DISK_AVAIL" -gt 5 ]; then
    log_success "Disk space OK: ${DISK_AVAIL}G available on /opt"
    ((CHECKS_PASSED++))
else
    log_warn "Low disk space: ${DISK_AVAIL}G available on /opt"
    ((CHECKS_FAILED++))
fi

# 8. Check if app is already deployed
echo ""
log_info "Checking application status..."
if [ -d /opt/observability/app/server ] && [ -f /opt/observability/app/server/main.py ]; then
    log_success "Application code is deployed"
    ((CHECKS_PASSED++))

    if sudo systemctl is-active --quiet observability-app; then
        log_success "Application service is running"
        ((CHECKS_PASSED++))

        if curl -sf http://127.0.0.1:9010/health > /dev/null 2>&1; then
            HEALTH=$(curl -s http://127.0.0.1:9010/health)
            log_success "Health check passed: $HEALTH"
            ((CHECKS_PASSED++))
        else
            log_error "Health check failed - service running but not responding"
            ((CHECKS_FAILED++))
        fi
    else
        log_info "Application service is not running (start with: sudo systemctl start observability-app)"
    fi
else
    log_info "Application not yet deployed - run deploy-app.sh to deploy"
fi

# Summary
echo ""
echo "=============================================="
echo "  Summary"
echo "=============================================="
echo -e "  ${GREEN}Passed:${NC} $CHECKS_PASSED"
echo -e "  ${RED}Failed:${NC} $CHECKS_FAILED"
echo "=============================================="

if [ "$CHECKS_FAILED" -gt 0 ]; then
    echo ""
    log_warn "Some checks failed. Review the output above."
    log_info "If cloud-init is still running: sudo cloud-init status --wait"
    log_info "Cloud-init log: sudo tail -100 /var/log/cloud-init-app.log"
    exit 1
else
    echo ""
    log_success "Instance is ready for application deployment!"
    log_info "Next step: Run deploy-app.sh from your local machine"
fi
