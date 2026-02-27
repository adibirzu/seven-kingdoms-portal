# DNS Module Outputs

output "primary_zone_id" {
  description = "Primary DNS zone OCID"
  value       = var.create_primary_zone ? oci_dns_zone.primary[0].id : var.primary_zone_id
}

output "primary_zone_nameservers" {
  description = "Primary zone nameservers"
  value       = var.create_primary_zone ? oci_dns_zone.primary[0].nameservers : []
}

output "secondary_zone_id" {
  description = "Secondary DNS zone OCID"
  value       = var.create_secondary_zone ? oci_dns_zone.secondary[0].id : var.secondary_zone_id
}

output "secondary_zone_nameservers" {
  description = "Secondary zone nameservers"
  value       = var.create_secondary_zone ? oci_dns_zone.secondary[0].nameservers : []
}

output "primary_hostname" {
  description = "Primary hostname"
  value       = var.primary_hostname
}

output "secondary_hostname" {
  description = "Secondary hostname"
  value       = var.secondary_hostname
}

output "health_check_id" {
  description = "Health check OCID"
  value       = var.enable_health_check ? oci_health_checks_http_monitor.main[0].id : null
}
