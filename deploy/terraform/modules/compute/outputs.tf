# Compute Module Outputs

output "instance_id" {
  description = "Compute instance OCID"
  value       = oci_core_instance.app.id
}

output "instance_private_ip" {
  description = "Private IP address of the instance"
  value       = oci_core_instance.app.private_ip
}

output "instance_display_name" {
  description = "Display name of the instance"
  value       = oci_core_instance.app.display_name
}

output "bastion_public_ip" {
  description = "Public IP of bastion host (if created)"
  value       = var.create_bastion ? oci_core_instance.bastion[0].public_ip : null
}
