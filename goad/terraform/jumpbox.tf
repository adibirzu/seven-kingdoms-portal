# GOAD Jumpbox — Ubuntu VM with public IP for SSH access to private VMs.

resource "oci_core_instance" "jumpbox" {
  availability_domain = var.availability_domain
  compartment_id      = var.compartment_ocid
  display_name        = "goad-jumpbox"
  shape               = var.jumpbox_shape

  shape_config {
    baseline_ocpu_utilization = "BASELINE_1_1"
    memory_in_gbs             = var.jumpbox_memory_gbs
    ocpus                     = var.jumpbox_ocpus
  }

  source_details {
    source_id   = var.jumpbox_image_ocid
    source_type = "image"
  }

  create_vnic_details {
    assign_ipv6ip             = false
    assign_private_dns_record = true
    assign_public_ip          = true
    subnet_id                 = oci_core_subnet.public.id
  }

  metadata = {
    ssh_authorized_keys = var.ssh_authorized_keys
  }

  agent_config {
    is_management_disabled = false
    is_monitoring_disabled = false
    plugins_config {
      desired_state = "ENABLED"
      name          = "Management Agent"
    }
    plugins_config {
      desired_state = "ENABLED"
      name          = "Custom Logs Monitoring"
    }
    plugins_config {
      desired_state = "ENABLED"
      name          = "Vulnerability Scanning"
    }
    plugins_config {
      desired_state = "ENABLED"
      name          = "Compute Instance Run Command"
    }
    plugins_config {
      desired_state = "ENABLED"
      name          = "Compute Instance Monitoring"
    }
  }

  availability_config {
    is_live_migration_preferred = true
    recovery_action             = "RESTORE_INSTANCE"
  }

  freeform_tags = var.freeform_tags
}
