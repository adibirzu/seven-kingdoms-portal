# GOAD Network — VCN, subnets, gateways, security lists, DHCP.
#
# Network: 192.168.0.0/16
#   - 192.168.57.0/24  public  (jumpbox)
#   - 192.168.56.0/24  private (Windows AD VMs)
#   - 192.168.100.0/24 private (attack subnet — Kali, Caldera)

resource "oci_core_vcn" "goad" {
  cidr_block     = "192.168.0.0/16"
  compartment_id = var.compartment_ocid
  display_name   = "goad-vcn"
  dns_label      = "goadvcn"

  freeform_tags = var.freeform_tags
}

# --- Subnets ---

resource "oci_core_subnet" "public" {
  cidr_block     = "192.168.57.0/24"
  compartment_id = var.compartment_ocid
  display_name   = "goad-public-subnet"
  dns_label      = "publicsubnet"
  vcn_id         = oci_core_vcn.goad.id
  route_table_id = oci_core_route_table.public.id

  freeform_tags = var.freeform_tags
}

resource "oci_core_subnet" "private" {
  cidr_block                 = "192.168.56.0/24"
  compartment_id             = var.compartment_ocid
  display_name               = "goad-private-subnet"
  dns_label                  = "privatesubnet"
  vcn_id                     = oci_core_vcn.goad.id
  route_table_id             = oci_core_route_table.private.id
  prohibit_internet_ingress  = true
  prohibit_public_ip_on_vnic = true
  security_list_ids          = [oci_core_security_list.internal.id]

  freeform_tags = var.freeform_tags
}

resource "oci_core_subnet" "attack" {
  cidr_block                 = "192.168.100.0/24"
  compartment_id             = var.compartment_ocid
  display_name               = "goad-attack-subnet"
  dns_label                  = "attacksubnet"
  vcn_id                     = oci_core_vcn.goad.id
  route_table_id             = oci_core_route_table.private.id
  prohibit_internet_ingress  = true
  prohibit_public_ip_on_vnic = true
  security_list_ids          = [oci_core_security_list.internal.id]

  freeform_tags = var.freeform_tags
}

# --- Gateways ---

resource "oci_core_internet_gateway" "goad" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.goad.id
  display_name   = "goad-igw"
  enabled        = true

  freeform_tags = var.freeform_tags
}

resource "oci_core_nat_gateway" "goad" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.goad.id
  display_name   = "goad-natgw"

  freeform_tags = var.freeform_tags
}

# --- Route Tables ---

resource "oci_core_route_table" "public" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.goad.id
  display_name   = "goad-public-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.goad.id
  }

  freeform_tags = var.freeform_tags
}

resource "oci_core_route_table" "private" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.goad.id
  display_name   = "goad-private-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_nat_gateway.goad.id
  }

  # Route to app VCN via LPG (added dynamically if peering is enabled)
  dynamic "route_rules" {
    for_each = var.app_lpg_id != "" ? [1] : []
    content {
      destination       = "10.0.0.0/16"
      destination_type  = "CIDR_BLOCK"
      network_entity_id = oci_core_local_peering_gateway.goad_to_app[0].id
    }
  }

  freeform_tags = var.freeform_tags
}

# --- DHCP Options ---

resource "oci_core_default_dhcp_options" "goad" {
  manage_default_resource_id = oci_core_vcn.goad.default_dhcp_options_id

  options {
    type               = "DomainNameServer"
    server_type        = "CustomDnsServer"
    custom_dns_servers = ["192.168.56.10", "8.8.8.8"]
  }

  options {
    type                = "SearchDomain"
    search_domain_names = ["sevenkingdoms.local"]
  }
}

# --- Security List ---

resource "oci_core_security_list" "internal" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.goad.id
  display_name   = "goad-internal-sl"

  # Allow all intra-VCN traffic
  ingress_security_rules {
    protocol  = "all"
    source    = "192.168.0.0/16"
    stateless = false
  }

  # Allow traffic from app VCN (peered via LPG)
  ingress_security_rules {
    protocol  = "all"
    source    = "10.0.0.0/16"
    stateless = false
  }

  # Allow all outbound
  egress_security_rules {
    protocol    = "all"
    destination = "0.0.0.0/0"
    stateless   = false
  }

  freeform_tags = var.freeform_tags
}
