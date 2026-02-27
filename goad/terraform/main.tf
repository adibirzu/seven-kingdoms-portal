# GOADv3 Active Directory Lab — Terraform for OCI.
#
# Adapted from GOADv3 OCI provider for standalone Seven Kingdoms Portal.
# Creates: VCN (192.168.0.0/16), 5 Windows VMs, Ubuntu jumpbox, LPG peering.
#
# Can be used standalone (with provider block) or as a module (inherits provider).
# When used as a module, the caller must configure the OCI provider.

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}
