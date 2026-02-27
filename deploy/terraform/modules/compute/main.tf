# Compute Module - VM Instance for Application

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

# Get latest Oracle Linux 8 image
data "oci_core_images" "oracle_linux" {
  compartment_id           = var.compartment_id
  operating_system         = "Oracle Linux"
  operating_system_version = "8"
  shape                    = var.instance_shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"

  filter {
    name   = "display_name"
    values = ["^Oracle-Linux-8\\.[0-9]+-[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}-[0-9]+$"]
    regex  = true
  }
}

# Cloud-init script for application setup
locals {
  cloud_init_script = <<-CLOUDINIT
#!/bin/bash
set -e
exec > /var/log/cloud-init-app.log 2>&1
echo "=== Cloud-init started at $(date) ==="

# Update system
dnf update -y

# Install Python 3.11, git, and firewall
dnf install -y python3.11 python3.11-pip git firewalld

# Create application user (login disabled)
useradd -r -m -d /opt/observability -s /sbin/nologin observability || true

# Create directory structure
mkdir -p /opt/observability/{app,venv,logs}
chown -R observability:observability /opt/observability

# Create Python virtual environment
sudo -u observability python3.11 -m venv /opt/observability/venv

# Pre-install core dependencies so deploy-app.sh is faster
sudo -H -u observability /opt/observability/venv/bin/pip install --no-cache-dir \
  'fastapi>=0.110' 'uvicorn[standard]>=0.24'

# Configure firewall - wait for dbus/firewalld to be ready (avoids dbus timeout during cloud-init)
for i in 1 2 3 4 5; do
  systemctl enable --now firewalld && break
  echo "Waiting for firewalld (attempt $i)..."
  sleep 10
done
sleep 5
firewall-cmd --permanent --add-port=9010/tcp
firewall-cmd --reload

# Create systemd service unit
cat > /etc/systemd/system/observability-app.service << 'SERVICEEOF'
[Unit]
Description=OCI Observability Overview Application
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=observability
Group=observability
WorkingDirectory=/opt/observability/app
Environment=PATH=/opt/observability/venv/bin:/usr/local/bin:/usr/bin
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/observability/venv/bin/uvicorn server.main:app --host 0.0.0.0 --port 9010 --workers 2 --access-log
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=observability-app

# Hardening (namespace-based options like ProtectSystem=strict removed for OL8 compatibility)
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload

# Create logrotate config
cat > /etc/logrotate.d/observability-app << 'LOGEOF'
/opt/observability/logs/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    copytruncate
}
LOGEOF

echo "=== Cloud-init completed at $(date) ==="
CLOUDINIT
}

# Compute Instance
resource "oci_core_instance" "app" {
  compartment_id      = var.compartment_id
  availability_domain = var.availability_domain
  display_name        = "${var.project_name}-app-vm"
  shape               = var.instance_shape

  dynamic "shape_config" {
    for_each = var.instance_shape == "VM.Standard.E4.Flex" || var.instance_shape == "VM.Standard.E5.Flex" || var.instance_shape == "VM.Standard.A1.Flex" ? [1] : []
    content {
      ocpus         = var.instance_ocpus
      memory_in_gbs = var.instance_memory_gb
    }
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.oracle_linux.images[0].id
    boot_volume_size_in_gbs = var.boot_volume_size_gb
  }

  create_vnic_details {
    subnet_id        = var.subnet_id
    assign_public_ip = false
    nsg_ids          = var.nsg_ids
    display_name     = "${var.project_name}-app-vnic"
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data           = base64encode(local.cloud_init_script)
  }

  freeform_tags = var.tags

  lifecycle {
    ignore_changes = [
      source_details[0].source_id,
      metadata["user_data"]
    ]
  }
}

# Optional: Bastion for SSH access (if needed)
resource "oci_core_instance" "bastion" {
  count = var.create_bastion ? 1 : 0

  compartment_id      = var.compartment_id
  availability_domain = var.availability_domain
  display_name        = "${var.project_name}-bastion"
  shape               = "VM.Standard.E5.Flex"

  shape_config {
    ocpus         = 1
    memory_in_gbs = 6
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.oracle_linux.images[0].id
    boot_volume_size_in_gbs = 50
  }

  create_vnic_details {
    subnet_id        = var.bastion_subnet_id
    assign_public_ip = true
    display_name     = "${var.project_name}-bastion-vnic"
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
  }

  lifecycle {
    ignore_changes = [
      source_details[0].source_id
    ]
  }

  freeform_tags = var.tags
}
