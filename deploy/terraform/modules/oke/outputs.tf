# OKE Module Outputs

output "cluster_id" {
  description = "OKE cluster OCID"
  value       = oci_containerengine_cluster.main.id
}

output "cluster_name" {
  description = "OKE cluster name"
  value       = oci_containerengine_cluster.main.name
}

output "cluster_kubernetes_version" {
  description = "Kubernetes version"
  value       = oci_containerengine_cluster.main.kubernetes_version
}

output "cluster_endpoints" {
  description = "Cluster endpoints"
  value       = oci_containerengine_cluster.main.endpoints
}

output "node_pool_id" {
  description = "Node pool OCID"
  value       = oci_containerengine_node_pool.main.id
}

output "virtual_node_pool_id" {
  description = "Virtual node pool OCID"
  value       = var.create_virtual_node_pool ? oci_containerengine_virtual_node_pool.virtual[0].id : null
}

# Kubeconfig data
output "kubeconfig_command" {
  description = "Command to get kubeconfig"
  value       = "oci ce cluster create-kubeconfig --cluster-id ${oci_containerengine_cluster.main.id} --file $HOME/.kube/config --region ${data.oci_identity_regions.current.regions[0].name} --token-version 2.0.0"
}

data "oci_identity_regions" "current" {}
