# LPG Peering — connects GOAD VCN (192.0.2.42/16) to App VCN (192.0.2.1/16).
#
# This enables the vulnerable app to reach GOAD AD domain controllers and
# MSSQL servers for real LDAP/SQL integration.
#
# Only created when app_lpg_id is provided (set by C1 infrastructure).

resource "oci_core_local_peering_gateway" "goad_to_app" {
  count = var.app_lpg_id != "" ? 1 : 0

  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.goad.id
  display_name   = "goad-to-app-lpg"
  peer_id        = var.app_lpg_id

  freeform_tags = var.freeform_tags
}
