# WAF Module Outputs

output "waf_policy_id" {
  description = "WAF policy OCID"
  value       = oci_waf_web_app_firewall_policy.main.id
}

output "waf_id" {
  description = "WAF instance OCID"
  value       = var.attach_to_lb ? oci_waf_web_app_firewall.main[0].id : null
}

output "waf_log_group_id" {
  description = "WAF log group OCID"
  value       = var.enable_logging && var.attach_to_lb ? oci_logging_log_group.waf[0].id : null
}

output "waf_access_log_id" {
  description = "WAF access log OCID"
  value       = var.enable_logging && var.attach_to_lb ? oci_logging_log.waf_access[0].id : null
}
