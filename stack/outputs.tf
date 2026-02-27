# ═══════════════════════════════════════════════════════════════
# Seven Kingdoms Portal — ORM Stack Outputs
# ═══════════════════════════════════════════════════════════════

# --- Deployer VM ---

output "deployer_public_ip" {
  description = "Public IP of the deployer VM"
  value       = oci_core_instance.deployer.public_ip
}

output "deployer_ssh" {
  description = "SSH command to the deployer VM"
  value       = "ssh opc@${oci_core_instance.deployer.public_ip}"
}

output "deploy_log" {
  description = "Command to view deployment progress"
  value       = "ssh opc@${oci_core_instance.deployer.public_ip} 'tail -f /opt/skp/stack-deploy.log'"
}

# --- Network ---

output "vcn_id" {
  description = "App VCN OCID"
  value       = module.network.vcn_id
}

# --- OKE ---

output "oke_cluster_id" {
  description = "OKE Cluster OCID (if OKE mode)"
  value       = var.app_deploy_mode == "oke" ? module.oke[0].cluster_id : null
}

output "kubeconfig_command" {
  description = "Command to get kubeconfig (if OKE mode)"
  value       = var.app_deploy_mode == "oke" ? module.oke[0].kubeconfig_command : null
}

# --- GOAD ---

output "goad_jumpbox_ip" {
  description = "GOAD jumpbox public IP (if GOAD enabled)"
  value       = var.deploy_goad ? module.goad[0].jumpbox_public_ip : null
}

output "goad_jumpbox_ssh" {
  description = "SSH command to GOAD jumpbox"
  value       = var.deploy_goad ? "ssh ubuntu@${module.goad[0].jumpbox_public_ip}" : null
}

# --- Access Information ---

output "deployment_info" {
  description = "Deployment information"
  value = <<-EOT
    ═══════════════════════════════════════════════════════════════
    Seven Kingdoms Portal — Deployment Started
    ═══════════════════════════════════════════════════════════════

    Deployer VM: ssh opc@${oci_core_instance.deployer.public_ip}
    Deploy Log:  ssh opc@${oci_core_instance.deployer.public_ip} 'tail -f /opt/skp/stack-deploy.log'

    The deployer VM is now orchestrating the remaining deployment:
    ${var.deploy_goad ? "  - GOAD AD provisioning (5 Windows VMs — takes 30-60 min)" : ""}
    ${var.deploy_observability ? "  - Observability (APM, Logging, Monitoring)" : ""}
      - Application deployment (${var.app_deploy_mode} mode)
    ${var.deploy_waf ? "  - WAF (Web Application Firewall)" : ""}

    Once complete, the portal URL will be shown in the deploy log.
    ═══════════════════════════════════════════════════════════════
  EOT
}
