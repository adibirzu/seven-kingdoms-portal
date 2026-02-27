#!/usr/bin/env bash
# C2 Step 2: Provision GOADv3 Active Directory via Ansible through jumpbox.
#
# This script SSHes to the GOAD jumpbox and:
#   1. Clones GOADv3 from GitHub (if not already present)
#   2. Installs Ansible + dependencies, applies OCI-specific patches
#   3. Waits for WinRM on all 5 Windows VMs
#   4. Runs Ansible AD provisioning (3 domains, trusts, users, vulnerabilities)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== C2: GOADv3 AD Provisioning ==="

: "${GOAD_JUMPBOX_IP:?GOAD_JUMPBOX_IP is required (deploy GOAD Terraform first)}"
SSH_PRIVATE_KEY_PATH="${SSH_PRIVATE_KEY_PATH:-$HOME/.ssh/id_rsa}"
JUMPBOX_USER="${GOAD_JUMPBOX_USER:-ubuntu}"
GOAD_REPO_URL="${GOAD_REPO_URL:-https://github.com/Orange-Cyberdefense/GOAD.git}"
GOAD_REPO_BRANCH="${GOAD_REPO_BRANCH:-v3}"

if [[ ! -f "$SSH_PRIVATE_KEY_PATH" ]]; then
    echo "ERROR: SSH key not found: $SSH_PRIVATE_KEY_PATH"
    exit 1
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30"

echo "  Jumpbox: ${JUMPBOX_USER}@${GOAD_JUMPBOX_IP}"

# --- Step 1: Clone GOADv3 + Install Ansible on jumpbox ---
echo "  Step 1: Setting up GOADv3 + Ansible on jumpbox..."
ssh $SSH_OPTS -i "$SSH_PRIVATE_KEY_PATH" "${JUMPBOX_USER}@${GOAD_JUMPBOX_IP}" bash <<REMOTE_SETUP
set -euo pipefail

# --- Clone GOADv3 if not present ---
GOAD_DIR="\$HOME/GOADv3"
if [[ ! -d "\$GOAD_DIR" ]]; then
    echo "  [jumpbox] Cloning GOADv3 from ${GOAD_REPO_URL}..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq git python3-pip python3-venv sshpass >/dev/null
    git clone --branch "${GOAD_REPO_BRANCH}" --depth 1 "${GOAD_REPO_URL}" "\$GOAD_DIR"
    echo "  [jumpbox] GOADv3 cloned to \$GOAD_DIR"
else
    echo "  [jumpbox] GOADv3 already present at \$GOAD_DIR"
    # Ensure system packages are present
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3-pip python3-venv sshpass >/dev/null
fi

# --- Create/reuse Python venv for Ansible ---
VENV_DIR="\$HOME/.goad_venv"
if [[ ! -d "\$VENV_DIR" ]]; then
    echo "  [jumpbox] Creating Python venv..."
    python3 -m venv "\$VENV_DIR"
fi
source "\$VENV_DIR/bin/activate"

# --- Install Ansible + pywinrm ---
if ! command -v ansible-playbook >/dev/null 2>&1; then
    echo "  [jumpbox] Installing ansible-core and pywinrm..."
    pip3 install -q 'ansible-core>=2.17,<2.18' pywinrm
else
    echo "  [jumpbox] Ansible already installed: \$(ansible-playbook --version | head -1)"
    pip3 install -q pywinrm 2>/dev/null || true
fi

# --- Pin collection versions (GOAD requires ansible.windows 2.x, not 3.x) ---
echo "  [jumpbox] Pinning Ansible collections..."
ansible-galaxy collection install \
    ansible.windows:==2.5.0 \
    community.windows:==2.3.0 \
    --force 2>&1 | tail -3

# --- Apply OCI patches ---
# Patch inventory: WinRM timeouts (pywinrm 0.5+ enforces read > operation)
INVENTORY_FILE="\$GOAD_DIR/ad/GOAD/data/inventory"
if [[ -f "\$INVENTORY_FILE" ]]; then
    echo "  [jumpbox] Patching inventory timeouts..."
    if grep -q "ansible_winrm_operation_timeout_sec" "\$INVENTORY_FILE"; then
        sed -i 's/ansible_winrm_operation_timeout_sec=[0-9]*/ansible_winrm_operation_timeout_sec=400/' "\$INVENTORY_FILE"
        sed -i 's/ansible_winrm_read_timeout_sec=[0-9]*/ansible_winrm_read_timeout_sec=600/' "\$INVENTORY_FILE"
    else
        if grep -q '^\[all:vars\]' "\$INVENTORY_FILE"; then
            sed -i '/^\[all:vars\]/a ansible_winrm_operation_timeout_sec=400\nansible_winrm_read_timeout_sec=600' "\$INVENTORY_FILE"
        fi
    fi
fi

# Patch data.yml: OCI single-adapter + Ethernet 2
DATA_YML="\$GOAD_DIR/ansible/data.yml"
if [[ -f "\$DATA_YML" ]]; then
    echo "  [jumpbox] Patching data.yml for OCI..."
    # Force two_adapters: false (OCI VMs have single adapter)
    sed -i 's/two_adapters:.*/two_adapters: false/' "\$DATA_YML"
    # Set nat_adapter to "Ethernet 2" (OCI Windows VM default)
    sed -i 's/nat_adapter:.*/nat_adapter: "Ethernet 2"/' "\$DATA_YML"
fi

echo "  [jumpbox] Setup complete."
REMOTE_SETUP

# --- Step 2: Wait for WinRM on all VMs ---
echo "  Step 2: Waiting for WinRM on GOAD Windows VMs..."
GOAD_VMS="192.168.56.10 192.168.56.11 192.168.56.22 192.168.56.12 192.168.56.23"
MAX_WAIT=900  # 15 minutes
POLL_INTERVAL=30

ssh $SSH_OPTS -i "$SSH_PRIVATE_KEY_PATH" "${JUMPBOX_USER}@${GOAD_JUMPBOX_IP}" bash <<REMOTE_WAIT
set -euo pipefail
VMS="$GOAD_VMS"
elapsed=0
while [[ \$elapsed -lt $MAX_WAIT ]]; do
    all_up=true
    for vm in \$VMS; do
        if ! timeout 5 bash -c "echo | openssl s_client -connect \${vm}:5986 2>/dev/null" | grep -q "CONNECTED"; then
            all_up=false
            echo "  [jumpbox] Waiting for WinRM on \$vm... (\${elapsed}s)"
            break
        fi
    done
    if \$all_up; then
        echo "  [jumpbox] All VMs ready!"
        exit 0
    fi
    sleep $POLL_INTERVAL
    elapsed=\$((elapsed + $POLL_INTERVAL))
done
echo "  [jumpbox] TIMEOUT: Not all VMs ready after ${MAX_WAIT}s"
exit 1
REMOTE_WAIT

# --- Step 3: Run Ansible AD provisioning ---
echo "  Step 3: Running Ansible AD provisioning..."
ssh $SSH_OPTS -i "$SSH_PRIVATE_KEY_PATH" "${JUMPBOX_USER}@${GOAD_JUMPBOX_IP}" bash <<'REMOTE_ANSIBLE'
set -euo pipefail

# Activate venv
source "$HOME/.goad_venv/bin/activate"

cd ~/GOADv3

export ANSIBLE_ALLOW_BROKEN_CONDITIONALS=true
export ANSIBLE_HOST_KEY_CHECKING=False
export ANSIBLE_TIMEOUT=120

echo "  [jumpbox] Starting AD provisioning (this takes 30-60 minutes)..."
ansible-playbook \
    -i ad/GOAD/data/inventory \
    ad/GOAD/providers/oci/ansible/main.yml \
    2>&1 | tee ~/goad-ansible.log

echo "  [jumpbox] AD provisioning complete!"
REMOTE_ANSIBLE

echo ""
echo "  GOADv3 AD provisioning complete!"
echo "    DC01 (kingslanding): 192.168.56.10 — sevenkingdoms.local"
echo "    DC02 (winterfell):   192.168.56.11 — north.sevenkingdoms.local"
echo "    DC03 (meereen):      192.168.56.12 — essos.local"
echo "    SRV02 (castelblack): 192.168.56.22 — MSSQL"
echo "    SRV03 (braavos):     192.168.56.23 — MSSQL"
