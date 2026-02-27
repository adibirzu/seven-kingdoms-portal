# GOAD Windows VMs — 3 Domain Controllers + 2 Member Servers.
#
# VM Map:
#   kingslanding (dc01) — 192.168.56.10 — sevenkingdoms.local (root domain)
#   winterfell   (dc02) — 192.168.56.11 — north.sevenkingdoms.local (child domain)
#   castelblack  (srv02) — 192.168.56.22 — north member server (MSSQL)
#   meereen      (dc03) — 192.168.56.12 — essos.local (external trust)
#   braavos      (srv03) — 192.168.56.23 — essos member server (MSSQL)

resource "oci_core_instance" "windows" {
  for_each = {
    kingslanding = {
      name       = "kingslanding"
      private_ip = "192.168.56.10"
      password   = "8dCT-DJjgScp"
      image_ocid = var.windows2019_image_ocid
    }
    winterfell = {
      name       = "winterfell"
      private_ip = "192.168.56.11"
      password   = "NgtI75cKV+Pu"
      image_ocid = var.windows2019_image_ocid
    }
    castelblack = {
      name       = "castelblack"
      private_ip = "192.168.56.22"
      password   = "NgtI75cKV+Pu"
      image_ocid = var.windows2019_image_ocid
    }
    meereen = {
      name       = "meereen"
      private_ip = "192.168.56.12"
      password   = "Ufe-bVXSx9rk"
      image_ocid = var.windows2016_image_ocid
    }
    braavos = {
      name       = "braavos"
      private_ip = "192.168.56.23"
      password   = "978i2pF43UJ-"
      image_ocid = var.windows2016_image_ocid
    }
  }

  availability_domain = var.availability_domain
  compartment_id      = var.compartment_ocid
  display_name        = each.value.name
  shape               = var.windows_shape

  shape_config {
    ocpus         = var.windows_ocpus
    memory_in_gbs = var.windows_memory_gbs
  }

  source_details {
    source_id   = each.value.image_ocid
    source_type = "image"
  }

  create_vnic_details {
    assign_ipv6ip             = false
    assign_private_dns_record = true
    assign_public_ip          = false
    subnet_id                 = oci_core_subnet.private.id
    hostname_label            = each.value.name
    private_ip                = each.value.private_ip
  }

  metadata = {
    user_data      = base64encode(file("${path.module}/windows_cloud_init.ps1"))
    admin_password = each.value.password
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

  freeform_tags = var.freeform_tags
}
