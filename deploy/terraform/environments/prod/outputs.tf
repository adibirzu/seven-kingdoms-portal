# Production Environment Outputs

# Network
output "vcn_id" {
  description = "VCN OCID"
  value       = module.network.vcn_id
}

output "public_subnet_id" {
  description = "Public subnet OCID"
  value       = module.network.public_subnet_id
}

output "private_subnet_id" {
  description = "Private subnet OCID"
  value       = module.network.private_subnet_id
}

output "private_route_table_id" {
  description = "Private subnet route table OCID"
  value       = module.network.private_route_table_id
}

# Compute (VM Mode)
output "instance_id" {
  description = "VM instance OCID"
  value       = var.deployment_mode == "vm" || var.deployment_mode == "hybrid" ? module.compute[0].instance_id : null
}

output "instance_private_ip" {
  description = "VM private IP"
  value       = var.deployment_mode == "vm" || var.deployment_mode == "hybrid" ? module.compute[0].instance_private_ip : null
}

output "bastion_public_ip" {
  description = "Bastion public IP"
  value       = var.deployment_mode == "vm" || var.deployment_mode == "hybrid" ? module.compute[0].bastion_public_ip : null
}

# OKE
output "oke_cluster_id" {
  description = "OKE cluster OCID"
  value       = var.deployment_mode == "oke" || var.deployment_mode == "hybrid" ? module.oke[0].cluster_id : null
}

output "oke_cluster_endpoints" {
  description = "OKE cluster endpoints"
  value       = var.deployment_mode == "oke" || var.deployment_mode == "hybrid" ? module.oke[0].cluster_endpoints : null
}

output "kubeconfig_command" {
  description = "Command to get kubeconfig"
  value       = var.deployment_mode == "oke" || var.deployment_mode == "hybrid" ? module.oke[0].kubeconfig_command : null
}

# Load Balancer
output "lb_id" {
  description = "Load balancer OCID"
  value       = module.loadbalancer.lb_id
}

output "lb_public_ip" {
  description = "Load balancer public IP"
  value       = module.loadbalancer.lb_public_ip
}

output "backend_set_name" {
  description = "Load balancer backend set name"
  value       = module.loadbalancer.backend_set_name
}

# WAF
output "waf_policy_id" {
  description = "WAF policy OCID"
  value       = null
}

output "waf_id" {
  description = "WAF instance OCID"
  value       = null
}

# DNS
output "primary_hostname" {
  description = "Primary hostname"
  value       = module.dns.primary_hostname
}

output "secondary_hostname" {
  description = "Secondary hostname"
  value       = module.dns.secondary_hostname
}

# Connection Information
output "access_urls" {
  description = "Application access URLs"
  value = {
    primary   = "https://${var.primary_hostname}"
    secondary = "https://${var.secondary_hostname}"
    direct_ip = "http://${module.loadbalancer.lb_public_ip}"
  }
}

output "ssh_connection" {
  description = "SSH connection command (VM mode)"
  value = var.deployment_mode == "vm" || var.deployment_mode == "hybrid" ? (
    var.create_bastion ?
    "ssh -J opc@${module.compute[0].bastion_public_ip} opc@${module.compute[0].instance_private_ip}" :
    "Direct SSH not available - use bastion or VPN"
  ) : null
}
