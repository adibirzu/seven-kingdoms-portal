# OCI Observability Overview - Deployment Guide

## Overview

Deploy the OCI Observability Overview application on Oracle Cloud Infrastructure. The app runs on a **VM in a private subnet** behind a public Load Balancer with WAF protection.

## Architecture

```
                                  ┌──────────────────────────────────────────────────────────┐
                                  │                   OCI Region (eu-frankfurt-1)              │
                                  │  ┌──────────────────────────────────────────────────────┐ │
    Internet                      │  │                    VCN (10.0.0.0/16)                 │ │
        │                         │  │                                                      │ │
        │     ┌──────────┐        │  │  ┌──────────────────┐    ┌────────────────────────┐  │ │
        ├────►│   WAF    │────────┼──┼──│  Public Subnet   │    │    Private Subnet       │  │ │
        │     │ Policy   │        │  │  │  10.0.1.0/24     │    │    10.0.2.0/24          │  │ │
        │     └──────────┘        │  │  │                  │    │                          │  │ │
        │                         │  │  │  ┌────────────┐  │    │  ┌────────────────────┐  │  │ │
        │                         │  │  │  │ Load       │  │    │  │  App VM            │  │  │ │
        │                         │  │  │  │ Balancer   │──┼────┼──│  (uvicorn:9010)    │  │  │ │
        │                         │  │  │  │ :80/:443   │  │    │  │  Oracle Linux 8    │  │  │ │
        │                         │  │  │  └────────────┘  │    │  └────────────────────┘  │  │ │
        │                         │  │  │                  │    │            │              │  │ │
        │                         │  │  │  ┌────────────┐  │    │    NAT GW ▼ (outbound)   │  │ │
        │                         │  │  │  │ Bastion    │──┼─SSH┼──►Service GW (OCI svc)   │  │ │
        │                         │  │  │  │ (SSH jump) │  │    │                          │  │ │
        │                         │  │  │  └────────────┘  │    │                          │  │ │
        │                         │  │  └──────────────────┘    └────────────────────────┘  │ │
        │                         │  └──────────────────────────────────────────────────────┘ │
        │                         │                                                           │
        │     ┌──────────┐        │  ┌──────────────────────────────────────────────────────┐ │
        └────►│   DNS    │        │  │                   DNS Zone                           │ │
              │  Zones   │────────┼──│  observability.learnoci.cloud → LB Public IP         │ │
              └──────────┘        │  │  observability.cyber-sec.ro   → LB Public IP         │ │
                                  │  └──────────────────────────────────────────────────────┘ │
                                  └──────────────────────────────────────────────────────────┘
```

### Traffic Flow

1. **Inbound**: Internet → DNS → WAF → Load Balancer (public subnet) → App VM (private subnet, port 9010)
2. **SSH Access**: You → Bastion (public subnet) → SSH jump → App VM (private subnet, port 22)
3. **Outbound from VM**: App VM → NAT Gateway → Internet (for updates, pip install)

### Network Security

| Layer | Rule | Purpose |
|-------|------|---------|
| Public Security List | Ingress TCP 22/80/443 from 0.0.0.0/0 | SSH to bastion, HTTP/HTTPS to LB |
| Private Security List | Ingress TCP 9010 from public subnet | LB health checks and traffic |
| Private Security List | Ingress TCP 22 from VCN CIDR | SSH via bastion |
| LB NSG | Ingress 80/443 from 0.0.0.0/0 | Accept HTTP/HTTPS traffic |
| App NSG | Ingress 9010 from LB NSG only | App traffic from LB only |
| App NSG | Ingress 22 from public subnet CIDR | SSH via bastion only |
| OS Firewall (firewalld) | Port 9010/tcp, SSH service | Must match security list rules |

## Prerequisites

1. **OCI CLI** configured with API key authentication
2. **Terraform** >= 1.5.0
3. **SSH key pair** for instance access (RSA or ED25519)
4. **OCI Tenancy** with:
   - Compartment for resources
   - Service limits: 1 LB, 2 VMs (app + bastion), 1 VCN
   - DNS Zone (optional, for custom domains)

## Quick Start (VM Deployment)

### Step 1: Configure Variables

```bash
cd deploy/terraform/environments/prod
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your OCI credentials and SSH key
```

Required variables:
- `compartment_id` — Target compartment OCID
- `ssh_public_key` — Your SSH **public** key (the one you'll use to connect)
- `region` — OCI region (default: eu-frankfurt-1)
- `oci_profile` — OCI CLI config profile name (default: "DEFAULT")
- `use_instance_principals` — Set `true` when running on OCI instances or Resource Manager

> **Authentication**: When running locally, Terraform reads your `~/.oci/config` using the DEFAULT profile.
> When running on an OCI instance or Resource Manager stack, set `use_instance_principals = true`.

### Step 2: Deploy Infrastructure

```bash
cd deploy

# Preview changes
./scripts/deploy.sh --environment prod --mode vm --action plan

# Deploy (will prompt for confirmation)
./scripts/deploy.sh --environment prod --mode vm

# Deploy without confirmation
./scripts/deploy.sh --environment prod --mode vm -y
```

This creates: VCN, subnets, gateways, NSGs, security lists, VM, bastion, load balancer, WAF, and DNS records.

### Step 3: Wait for Cloud-Init

Cloud-init runs on first boot and takes 3-5 minutes. It installs Python 3.11, creates a virtual environment, configures firewalld, and sets up the systemd service unit.

```bash
# Get IPs from Terraform output
cd deploy/terraform/environments/prod
BASTION_IP=$(terraform output -raw bastion_public_ip)
INSTANCE_IP=$(terraform output -raw instance_private_ip)

# Verify cloud-init completed (use your SSH key)
ssh -i ~/.ssh/your_key \
  -o "ProxyCommand=ssh -i ~/.ssh/your_key -W %h:%p opc@$BASTION_IP" \
  opc@$INSTANCE_IP 'sudo cloud-init status'
# Expected output: status: done
```

### Step 4: Deploy Application

```bash
# Set your SSH key path
export SSH_KEY=~/.ssh/your_private_key

# Deploy
./scripts/deploy-app.sh --mode vm --environment prod
```

This will:
1. Create a tarball of the application code (excluding `.git`, `deploy/`, etc.)
2. SCP it to the VM via the bastion host
3. Extract to `/opt/observability/app` and install Python dependencies
4. Enable and restart the `observability-app` systemd service
5. Poll the `/health` endpoint until the app is ready (30s timeout)

### Step 5: Verify

```bash
# Get LB IP
LB_IP=$(cd deploy/terraform/environments/prod && terraform output -raw lb_public_ip)

# Test health endpoint through LB
curl http://$LB_IP/health
# Expected: {"status":"healthy"}

# Test main page
curl -o /dev/null -w "HTTP %{http_code}, %{size_download} bytes\n" http://$LB_IP/

# Test through domain (after DNS propagation)
curl https://observability.learnoci.cloud/health
```

## Current Production Deployment

| Resource | Value |
|----------|-------|
| Load Balancer IP | 193.122.3.181 |
| Bastion Public IP | 141.147.15.181 |
| App VM Private IP | 10.0.2.71 |
| Primary URL | https://observability.learnoci.cloud |
| Secondary URL | https://observability.cyber-sec.ro |
| Health Check | http://193.122.3.181/health |

## SSH Access

SSH to the app VM requires jumping through the bastion host. Always specify your SSH key with `-i`:

```bash
# Set your key
SSH_KEY=~/.ssh/your_private_key

# SSH to bastion only
ssh -i $SSH_KEY opc@$BASTION_IP

# SSH to app VM via bastion (ProxyCommand method — recommended)
ssh -i $SSH_KEY \
  -o "ProxyCommand=ssh -i $SSH_KEY -W %h:%p opc@$BASTION_IP" \
  opc@$INSTANCE_IP

# Once on the app VM:
sudo journalctl -u observability-app -f     # View app logs
sudo systemctl restart observability-app     # Restart app
sudo systemctl status observability-app      # Check status
curl http://127.0.0.1:9010/health            # Local health check
sudo firewall-cmd --list-ports               # Check firewall
```

> **Note**: Use `ProxyCommand` instead of `-J` for the SSH jump. The `-J` flag does not
> forward the `-i` key to the proxy hop, causing authentication failures.

## Starting Stopped Instances

The VM instances may be stopped to save costs. To restart them:

```bash
# Start bastion
oci compute instance action \
  --instance-id <BASTION_OCID> \
  --action START

# Start app VM
oci compute instance action \
  --instance-id <APP_VM_OCID> \
  --action START

# Wait for RUNNING state, then wait ~90 seconds for SSH to become available
```

> **Important**: After an instance transitions to RUNNING, SSH takes approximately
> 60-90 seconds to become available. The OS needs time to boot, initialize networking,
> and start sshd.

## Redeploying Application Updates

After code changes, just re-run the app deployment:

```bash
export SSH_KEY=~/.ssh/your_private_key
./scripts/deploy-app.sh --mode vm --environment prod
```

The script creates a fresh tarball, copies it to the VM, installs dependencies, and restarts the service.

## Deployment Modes

### VM Mode (Current)
- Single compute instance in **private subnet** (no public IP)
- Systemd service with auto-restart (`Restart=always`)
- Access via bastion host SSH jump
- Load Balancer in public subnet handles all inbound traffic
- WAF protection with rate limiting

### OKE Mode (Alternative)
- Kubernetes deployment with HPA (auto-scaling)
- Container image from OCI Container Registry
- Best for: high-availability, multi-replica deployments

```bash
./scripts/deploy.sh --environment prod --mode oke
./scripts/deploy-app.sh --mode oke --registry fra.ocir.io/your-namespace
```

## SSL Setup

After infrastructure is deployed and DNS is propagated:

```bash
./scripts/setup-ssl.sh --email admin@yourdomain.com
# Then re-apply Terraform to update LB with certificate
./scripts/deploy.sh --environment prod --mode vm -y
```

## Directory Structure

```
deploy/
├── terraform/
│   ├── modules/
│   │   ├── network/        # VCN, subnets, gateways, NSGs, security lists
│   │   ├── compute/        # App VM (private) + bastion (public), cloud-init
│   │   ├── oke/            # OKE cluster + node pool
│   │   ├── loadbalancer/   # LB, backend set, health check on /health
│   │   ├── waf/            # WAF policy, rate limiting, logging
│   │   └── dns/            # DNS zones, A records, health checks
│   └── environments/
│       ├── dev/            # Dev config (1 OCPU, 8GB, smaller LB)
│       └── prod/           # Prod config (2 OCPU, 16GB, WAF enabled)
├── kubernetes/
│   ├── base/               # K8s manifests (deploy, svc, hpa, pdb, netpol)
│   └── overlays/           # Environment-specific kustomize patches
├── docker/
│   ├── Dockerfile          # Multi-stage Python 3.11 slim image
│   └── .dockerignore
└── scripts/
    ├── deploy.sh           # Infrastructure deployment (terraform)
    ├── deploy-app.sh       # Application deployment (to VM or OKE)
    ├── setup-instance.sh   # VM setup verification script
    ├── setup-ssl.sh        # Let's Encrypt certificate generation
    ├── build-image.sh      # Docker image build + push to OCIR
    └── cleanup.sh          # Destroy all resources
```

## Application on the VM

| Item | Detail |
|------|--------|
| OS | Oracle Linux 8 |
| Python | 3.11 (venv at `/opt/observability/venv`) |
| App directory | `/opt/observability/app` |
| Service user | `observability` (system user, no login shell) |
| Systemd unit | `observability-app.service` |
| App server | uvicorn with 2 workers on `0.0.0.0:9010` |
| Health endpoint | `GET /health` → `{"status":"healthy"}` |
| Logs | `journalctl -u observability-app` |
| Firewall | firewalld with port 9010/tcp open |

## Cleanup

```bash
# Destroy all infrastructure (will prompt for confirmation)
./scripts/cleanup.sh --environment prod

# Force destroy without confirmation
./scripts/cleanup.sh --environment prod --force

# Full cleanup including Docker images and K8s resources
./scripts/cleanup.sh --environment prod --force --docker --k8s
```

## Troubleshooting

### Can't SSH to bastion

```bash
# 1. Check instance is RUNNING
oci compute instance get --instance-id <BASTION_OCID> \
  --query 'data."lifecycle-state"'

# 2. If STOPPED, start it and wait 90s
oci compute instance action --instance-id <BASTION_OCID> --action START
sleep 90

# 3. Verify public IP hasn't changed
oci compute instance list-vnics --instance-id <BASTION_OCID> \
  --query 'data[0]."public-ip"'

# 4. Verify security list allows SSH (port 22) from 0.0.0.0/0
oci network security-list get --security-list-id <PUBLIC_SL_OCID> \
  --query 'data."ingress-security-rules"'

# 5. Make sure you're using the correct SSH key
ssh -v -i ~/.ssh/your_key opc@$BASTION_IP
```

### Cloud-init failed or incomplete

```bash
ssh -i $SSH_KEY -o "ProxyCommand=ssh -i $SSH_KEY -W %h:%p opc@$BASTION_IP" opc@$INSTANCE_IP
sudo tail -100 /var/log/cloud-init-app.log
sudo cloud-init status
```

### Service won't start (exit code 203/EXEC)

This means uvicorn is not installed. Fix the venv permissions and reinstall:

```bash
sudo chown -R observability:observability /opt/observability
sudo -H -u observability /opt/observability/venv/bin/pip install -r /opt/observability/app/requirements.txt
sudo systemctl restart observability-app
```

### Service won't start (exit code 226/NAMESPACE)

The systemd service has namespace-based hardening directives that are incompatible with the kernel. Remove `ProtectSystem=strict`, `ProtectHome=true`, and `PrivateTmp=true` from the service unit:

```bash
sudo systemctl edit observability-app  # Override problematic directives
sudo systemctl daemon-reload
sudo systemctl restart observability-app
```

### LB health check failing (502 Bad Gateway)

```bash
# 1. Check if app responds locally on the VM
curl http://127.0.0.1:9010/health

# 2. Check firewall allows port 9010
sudo firewall-cmd --list-ports
# If 9010/tcp is missing:
sudo firewall-cmd --permanent --add-port=9010/tcp
sudo firewall-cmd --reload

# 3. Check LB backend health via OCI CLI
oci lb backend-health get \
  --load-balancer-id <LB_OCID> \
  --backend-set-name observability-backend-set \
  --backend-name "<APP_VM_IP>:9010"

# 4. Check NSG allows traffic from LB
# (OCI Console > Networking > Network Security Groups > app NSG)
```

### pip install fails with "Permission denied"

The venv directory is owned by root instead of the `observability` user:

```bash
sudo chown -R observability:observability /opt/observability
sudo -H -u observability /opt/observability/venv/bin/pip install \
  --no-cache-dir -r /opt/observability/app/requirements.txt
```
