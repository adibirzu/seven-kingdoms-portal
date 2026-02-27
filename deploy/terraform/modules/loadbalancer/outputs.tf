# Load Balancer Module Outputs

output "lb_id" {
  description = "Load balancer OCID"
  value       = oci_load_balancer_load_balancer.main.id
}

output "lb_ip_addresses" {
  description = "Load balancer IP addresses"
  value       = oci_load_balancer_load_balancer.main.ip_address_details
}

output "lb_public_ip" {
  description = "Load balancer public IP"
  value       = [for ip in oci_load_balancer_load_balancer.main.ip_address_details : ip.ip_address if ip.is_public][0]
}

output "backend_set_name" {
  description = "Backend set name"
  value       = oci_load_balancer_backend_set.main.name
}

output "https_listener_name" {
  description = "HTTPS listener name"
  value       = var.certificate_name != "" ? oci_load_balancer_listener.https[0].name : null
}

output "http_listener_name" {
  description = "HTTP listener name"
  value       = oci_load_balancer_listener.http.name
}
