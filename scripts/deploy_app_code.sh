#!/usr/bin/env bash
# C4 VM Step 2: Deploy app code to VM via bastion SSH.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== C4: App Code Deployment (SSH) ==="

: "${APP_INSTANCE_IP:?APP_INSTANCE_IP is required (deploy app VM first)}"
: "${BASTION_IP:?BASTION_IP is required}"

SSH_PRIVATE_KEY_PATH="${SSH_PRIVATE_KEY_PATH:-$HOME/.ssh/id_rsa}"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30"
APP_USER="opc"
REMOTE_DIR="/opt/observability/app"

echo "  Target: ${APP_USER}@${APP_INSTANCE_IP} via bastion ${BASTION_IP}"

# Wait for SSH availability through bastion
echo "  Waiting for SSH..."
for i in $(seq 1 30); do
    if ssh $SSH_OPTS -i "$SSH_PRIVATE_KEY_PATH" \
        -J "opc@${BASTION_IP}" \
        "${APP_USER}@${APP_INSTANCE_IP}" "echo ok" 2>/dev/null; then
        echo "    SSH ready!"
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "ERROR: SSH timeout after 5 minutes"
        exit 1
    fi
    sleep 10
done

# Tar the app code (excluding node_modules, .state, etc.)
echo "  Packaging app code..."
TARBALL="/tmp/skp-app.tar.gz"
cd "$ROOT_DIR"
tar czf "$TARBALL" \
    --exclude='.state' \
    --exclude='node_modules' \
    --exclude='.git' \
    --exclude='goad' \
    --exclude='deploy/terraform' \
    --exclude='__pycache__' \
    server/ web/ requirements.txt scripts/start.sh .env.local

# Upload via bastion
echo "  Uploading to VM..."
scp $SSH_OPTS -i "$SSH_PRIVATE_KEY_PATH" \
    -o "ProxyJump=opc@${BASTION_IP}" \
    "$TARBALL" "${APP_USER}@${APP_INSTANCE_IP}:/tmp/skp-app.tar.gz"

# Install on VM
echo "  Installing on VM..."
ssh $SSH_OPTS -i "$SSH_PRIVATE_KEY_PATH" \
    -J "opc@${BASTION_IP}" \
    "${APP_USER}@${APP_INSTANCE_IP}" bash <<REMOTE_INSTALL
set -euo pipefail
sudo mkdir -p $REMOTE_DIR
cd $REMOTE_DIR
sudo tar xzf /tmp/skp-app.tar.gz
sudo chown -R $APP_USER:$APP_USER $REMOTE_DIR

# Install Python deps
if [[ ! -d /opt/observability/venv ]]; then
    sudo python3 -m venv /opt/observability/venv
fi
sudo /opt/observability/venv/bin/pip install -r requirements.txt

# Copy .env.local
sudo cp .env.local /opt/observability/.env.local

# Restart service
if sudo systemctl is-enabled observability-app.service &>/dev/null; then
    sudo systemctl restart observability-app.service
    echo "  Service restarted"
else
    echo "  WARNING: observability-app.service not found (cloud-init may not have run)"
fi
REMOTE_INSTALL

rm -f "$TARBALL"

echo ""
echo "  App code deployed to VM!"
