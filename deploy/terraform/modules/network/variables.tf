# Network Module Variables

variable "compartment_id" {
  description = "OCI Compartment OCID"
  type        = string
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "observability"
}

variable "vcn_cidr" {
  description = "CIDR block for VCN"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR block for private subnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "oke_api_subnet_cidr" {
  description = "CIDR block for OKE API endpoint subnet"
  type        = string
  default     = "10.0.3.0/24"
}

variable "dns_label" {
  description = "DNS label for VCN"
  type        = string
  default     = "obsvcn"
}

variable "create_oke_subnets" {
  description = "Whether to create OKE-specific subnets"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Freeform tags for resources"
  type        = map(string)
  default     = {}
}

# --- GOAD Peering ---

variable "enable_goad_peering" {
  description = "Whether to create an LPG for peering with GOAD VCN"
  type        = bool
  default     = false
}

variable "goad_vcn_cidr" {
  description = "CIDR block of the GOAD VCN (for route rules and security lists)"
  type        = string
  default     = "192.168.0.0/16"
}
