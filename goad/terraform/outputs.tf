# GOAD Terraform Outputs

output "jumpbox_public_ip" {
  description = "Public IP of the GOAD jumpbox"
  value       = oci_core_instance.jumpbox.public_ip
}

output "goad_vcn_id" {
  description = "GOAD VCN OCID"
  value       = oci_core_vcn.goad.id
}

output "goad_lpg_id" {
  description = "GOAD-side LPG OCID (empty if peering not enabled)"
  value       = length(oci_core_local_peering_gateway.goad_to_app) > 0 ? oci_core_local_peering_gateway.goad_to_app[0].id : ""
}

output "windows_passwords" {
  description = "Windows VM admin passwords"
  value       = { for k, v in oci_core_instance.windows : k => v.metadata.admin_password }
  sensitive   = true
}

output "windows_ips" {
  description = "Windows VM private IPs"
  value = {
    kingslanding = "192.168.56.10"
    winterfell   = "192.168.56.11"
    castelblack  = "192.168.56.22"
    meereen      = "192.168.56.12"
    braavos      = "192.168.56.23"
  }
}

output "goad_private_subnet_id" {
  description = "GOAD private subnet OCID"
  value       = oci_core_subnet.private.id
}

output "goad_attack_subnet_id" {
  description = "GOAD attack subnet OCID"
  value       = oci_core_subnet.attack.id
}
