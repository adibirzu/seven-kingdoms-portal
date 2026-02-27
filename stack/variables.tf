# ═══════════════════════════════════════════════════════════════
# Seven Kingdoms Portal — ORM Stack Variables
# ═══════════════════════════════════════════════════════════════

# --- OCI Configuration ---

variable "tenancy_ocid" {
  type        = string
  description = "OCI Tenancy OCID"
}

variable "region" {
  type        = string
  description = "OCI Region"
}

variable "compartment_ocid" {
  type        = string
  description = "Compartment for all resources"
}

variable "current_user_ocid" {
  type        = string
  description = "OCID of the user running this stack (auto-populated by ORM)"
}

# --- Platform Mode ---

variable "app_deploy_mode" {
  type        = string
  description = "Application deployment mode: oke, vm, or docker"
  default     = "oke"

  validation {
    condition     = contains(["oke", "vm", "docker"], var.app_deploy_mode)
    error_message = "app_deploy_mode must be 'oke', 'vm', or 'docker'."
  }
}

variable "deploy_goad" {
  type        = bool
  description = "Deploy GOADv3 Active Directory lab"
  default     = true
}

variable "deploy_waf" {
  type        = bool
  description = "Deploy WAF on the load balancer"
  default     = true
}

variable "deploy_observability" {
  type        = bool
  description = "Deploy APM, Logging, Monitoring"
  default     = true
}

# --- Compute ---

variable "ssh_public_key" {
  type        = string
  description = "SSH public key for all instances"
}

variable "deployer_shape" {
  type        = string
  description = "Compute shape for the deployer VM"
  default     = "VM.Standard.E4.Flex"
}

variable "deployer_ocpus" {
  type        = number
  description = "OCPUs for the deployer VM"
  default     = 2
}

variable "deployer_memory_gb" {
  type        = number
  description = "Memory in GB for the deployer VM"
  default     = 16
}

# --- Network ---

variable "vcn_cidr" {
  type        = string
  description = "App VCN CIDR"
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  type        = string
  description = "Public subnet CIDR"
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  type        = string
  description = "Private subnet CIDR"
  default     = "10.0.2.0/24"
}

# --- OKE ---

variable "oke_node_pool_size" {
  type        = number
  description = "Number of OKE worker nodes"
  default     = 2
}

variable "oke_node_shape" {
  type        = string
  description = "OKE node shape"
  default     = "VM.Standard.E4.Flex"
}

variable "oke_node_ocpus" {
  type        = number
  description = "OCPUs per OKE node"
  default     = 2
}

variable "oke_node_memory_gb" {
  type        = number
  description = "Memory per OKE node in GB"
  default     = 16
}

# --- GOAD ---

variable "goad_vcn_cidr" {
  type        = string
  description = "GOAD VCN CIDR"
  default     = "192.168.0.0/16"
}

variable "goad_vm_shape" {
  type        = string
  description = "GOAD Windows VM shape"
  default     = "VM.Standard.E5.Flex"
}

variable "goad_vm_ocpus" {
  type        = number
  description = "OCPUs per GOAD Windows VM"
  default     = 2
}

variable "goad_vm_memory_gb" {
  type        = number
  description = "Memory per GOAD Windows VM in GB"
  default     = 32
}

# --- App ---

variable "app_port" {
  type        = number
  description = "Application port"
  default     = 9010
}

variable "portal_jwt_secret" {
  type        = string
  description = "JWT secret for the portal"
  default     = ""
  sensitive   = true
}
