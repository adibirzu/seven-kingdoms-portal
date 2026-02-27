# Network Module Outputs

output "vcn_id" {
  description = "VCN OCID"
  value       = oci_core_vcn.main.id
}

output "vcn_cidr" {
  description = "VCN CIDR block"
  value       = var.vcn_cidr
}

output "public_subnet_id" {
  description = "Public subnet OCID"
  value       = oci_core_subnet.public.id
}

output "private_subnet_id" {
  description = "Private subnet OCID"
  value       = oci_core_subnet.private.id
}

output "oke_api_subnet_id" {
  description = "OKE API endpoint subnet OCID"
  value       = var.create_oke_subnets ? oci_core_subnet.oke_api[0].id : null
}

output "lb_nsg_id" {
  description = "Load Balancer Network Security Group OCID"
  value       = oci_core_network_security_group.lb.id
}

output "app_nsg_id" {
  description = "Application Network Security Group OCID"
  value       = oci_core_network_security_group.app.id
}

output "internet_gateway_id" {
  description = "Internet Gateway OCID"
  value       = oci_core_internet_gateway.main.id
}

output "nat_gateway_id" {
  description = "NAT Gateway OCID"
  value       = oci_core_nat_gateway.main.id
}

output "service_gateway_id" {
  description = "Service Gateway OCID"
  value       = oci_core_service_gateway.main.id
}

output "private_route_table_id" {
  description = "Private subnet route table OCID (used for LPG peering post-apply)"
  value       = oci_core_route_table.private.id
}

output "app_lpg_id" {
  description = "App-side LPG OCID for GOAD peering (null if peering disabled)"
  value       = var.enable_goad_peering ? oci_core_local_peering_gateway.app_to_goad[0].id : null
}
