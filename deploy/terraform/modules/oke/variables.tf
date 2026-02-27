# OKE Module Variables

variable "compartment_id" {
  description = "OCI Compartment OCID"
  type        = string
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "observability"
}

variable "vcn_id" {
  description = "VCN OCID"
  type        = string
}

variable "kubernetes_version" {
  description = "Kubernetes version (empty for latest)"
  type        = string
  default     = ""
}

variable "cni_type" {
  description = "CNI type: OCI_VCN_IP_NATIVE or FLANNEL_OVERLAY"
  type        = string
  default     = "OCI_VCN_IP_NATIVE"
}

variable "public_api_endpoint" {
  description = "Whether API endpoint is public"
  type        = bool
  default     = true
}

variable "api_endpoint_subnet_id" {
  description = "Subnet for API endpoint"
  type        = string
}

variable "api_endpoint_nsg_ids" {
  description = "NSG IDs for API endpoint"
  type        = list(string)
  default     = []
}

variable "node_subnet_id" {
  description = "Subnet for worker nodes"
  type        = string
}

variable "node_nsg_ids" {
  description = "NSG IDs for worker nodes"
  type        = list(string)
  default     = []
}

variable "service_lb_subnet_id" {
  description = "Subnet for service load balancers"
  type        = string
}

variable "pods_cidr" {
  description = "CIDR for pods"
  type        = string
  default     = "10.244.0.0/16"
}

variable "services_cidr" {
  description = "CIDR for services"
  type        = string
  default     = "10.96.0.0/16"
}

variable "availability_domain" {
  description = "Availability domain for nodes"
  type        = string
}

variable "node_pool_size" {
  description = "Number of nodes in node pool"
  type        = number
  default     = 3
}

variable "node_shape" {
  description = "Node shape"
  type        = string
  default     = "VM.Standard.E4.Flex"
}

variable "node_ocpus" {
  description = "OCPUs per node (flex shapes)"
  type        = number
  default     = 2
}

variable "node_memory_gb" {
  description = "Memory per node in GB (flex shapes)"
  type        = number
  default     = 16
}

variable "node_image_id" {
  description = "Node image OCID (empty for default)"
  type        = string
  default     = ""
}

variable "ssh_public_key" {
  description = "SSH public key for nodes"
  type        = string
}

variable "create_virtual_node_pool" {
  description = "Create virtual node pool for serverless"
  type        = bool
  default     = false
}

variable "virtual_node_pool_size" {
  description = "Size of virtual node pool"
  type        = number
  default     = 3
}

variable "tags" {
  description = "Freeform tags for resources"
  type        = map(string)
  default     = {}
}
