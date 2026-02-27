# Production Environment Variables

# OCI Authentication
variable "oci_profile" {
  description = "OCI CLI config profile name (used when running locally)"
  type        = string
  default     = "DEFAULT"
}

variable "use_instance_principals" {
  description = "Use Instance Principals for auth (set true when running on OCI instances or Resource Manager)"
  type        = bool
  default     = false
}

variable "oci_auth_mode" {
  description = "OCI authentication mode: APIKey, SecurityToken, InstancePrincipal, ResourcePrincipal. When set, overrides use_instance_principals."
  type        = string
  default     = ""
}

variable "tenancy_ocid" {
  description = "OCI Tenancy OCID (optional — read from OCI CLI profile when running locally)"
  type        = string
  default     = ""
}

variable "region" {
  description = "OCI Region"
  type        = string
  default     = "eu-frankfurt-1"
}

variable "compartment_id" {
  description = "Compartment OCID for resources"
  type        = string
}

# Project Settings
variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "observability"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

# Deployment Mode
variable "deployment_mode" {
  description = "Deployment mode: vm, oke, or hybrid"
  type        = string
  default     = "vm"

  validation {
    condition     = contains(["vm", "oke", "hybrid"], var.deployment_mode)
    error_message = "Deployment mode must be 'vm', 'oke', or 'hybrid'."
  }
}

# Network Settings
variable "vcn_cidr" {
  description = "VCN CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "Public subnet CIDR"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "Private subnet CIDR"
  type        = string
  default     = "10.0.2.0/24"
}

variable "oke_api_subnet_cidr" {
  description = "OKE API endpoint subnet CIDR"
  type        = string
  default     = "10.0.3.0/24"
}

# VM Settings
variable "instance_shape" {
  description = "Compute instance shape"
  type        = string
  default     = "VM.Standard.E4.Flex"
}

variable "instance_ocpus" {
  description = "Number of OCPUs"
  type        = number
  default     = 2
}

variable "instance_memory_gb" {
  description = "Memory in GB"
  type        = number
  default     = 16
}

variable "boot_volume_size_gb" {
  description = "Boot volume size in GB"
  type        = number
  default     = 50
}

variable "ssh_public_key" {
  description = "SSH public key for instance access"
  type        = string
}

variable "create_bastion" {
  description = "Create bastion host"
  type        = bool
  default     = false
}

# OKE Settings
variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = ""
}

variable "node_pool_size" {
  description = "Number of worker nodes"
  type        = number
  default     = 3
}

variable "node_shape" {
  description = "Node shape"
  type        = string
  default     = "VM.Standard.E4.Flex"
}

variable "node_ocpus" {
  description = "OCPUs per node"
  type        = number
  default     = 2
}

variable "node_memory_gb" {
  description = "Memory per node in GB"
  type        = number
  default     = 16
}

# Load Balancer Settings
variable "lb_shape" {
  description = "Load balancer shape"
  type        = string
  default     = "flexible"
}

variable "lb_min_bandwidth" {
  description = "Minimum bandwidth (Mbps)"
  type        = number
  default     = 10
}

variable "lb_max_bandwidth" {
  description = "Maximum bandwidth (Mbps)"
  type        = number
  default     = 100
}

variable "backend_port" {
  description = "Backend application port"
  type        = number
  default     = 9010
}

variable "health_check_path" {
  description = "Health check path"
  type        = string
  default     = "/health"
}

# SSL Certificate
variable "ssl_certificate_name" {
  description = "SSL certificate name"
  type        = string
  default     = ""
}

variable "ssl_public_certificate" {
  description = "SSL public certificate (PEM)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "ssl_private_key" {
  description = "SSL private key (PEM)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "ssl_ca_certificate" {
  description = "SSL CA certificate (PEM)"
  type        = string
  default     = ""
  sensitive   = true
}

# DNS Settings
variable "primary_hostname" {
  description = "Primary hostname"
  type        = string
  default     = "observability.learnoci.cloud"
}

variable "secondary_hostname" {
  description = "Secondary hostname"
  type        = string
  default     = "observability.cyber-sec.ro"
}

variable "create_primary_dns_zone" {
  description = "Create primary DNS zone"
  type        = bool
  default     = false
}

variable "primary_zone_name" {
  description = "Primary DNS zone name"
  type        = string
  default     = "learnoci.cloud"
}

variable "primary_zone_id" {
  description = "Existing primary zone OCID"
  type        = string
  default     = ""
}

variable "create_secondary_dns_zone" {
  description = "Create secondary DNS zone"
  type        = bool
  default     = false
}

variable "secondary_zone_name" {
  description = "Secondary DNS zone name"
  type        = string
  default     = "cyber-sec.ro"
}

variable "secondary_zone_id" {
  description = "Existing secondary zone OCID"
  type        = string
  default     = ""
}

variable "dns_ttl" {
  description = "DNS record TTL"
  type        = number
  default     = 300
}

variable "create_caa_records" {
  description = "Create CAA records"
  type        = bool
  default     = true
}

variable "enable_dns_health_check" {
  description = "Enable DNS health check"
  type        = bool
  default     = false
}

# WAF Settings
variable "waf_enable_access_control" {
  description = "Enable WAF access control"
  type        = bool
  default     = true
}

variable "waf_enable_rate_limiting" {
  description = "Enable WAF rate limiting"
  type        = bool
  default     = true
}

variable "waf_rate_limit" {
  description = "WAF rate limit (requests/minute)"
  type        = number
  default     = 1000
}

variable "waf_enable_protection" {
  description = "Enable WAF OWASP protection"
  type        = bool
  default     = true
}

variable "waf_block_countries" {
  description = "Block suspicious countries"
  type        = bool
  default     = false
}

variable "waf_enable_logging" {
  description = "Enable WAF logging"
  type        = bool
  default     = true
}

variable "waf_log_retention_days" {
  description = "WAF log retention days"
  type        = number
  default     = 30
}
