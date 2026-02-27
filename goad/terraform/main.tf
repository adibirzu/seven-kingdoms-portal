# GOADv3 Active Directory Lab — Terraform for OCI.
#
# Adapted from GOADv3 OCI provider for standalone Seven Kingdoms Portal.
# Creates: VCN (192.168.0.0/16), 5 Windows VMs, Ubuntu jumpbox, LPG peering.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

provider "oci" {
  config_file_profile = var.oci_profile
  region              = var.region
}
