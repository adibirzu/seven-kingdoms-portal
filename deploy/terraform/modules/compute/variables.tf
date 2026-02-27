# Compute Module Variables

variable "compartment_id" {
  description = "OCI Compartment OCID"
  type        = string
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "observability"
}

variable "availability_domain" {
  description = "Availability domain for instance"
  type        = string
}

variable "subnet_id" {
  description = "Subnet OCID for instance"
  type        = string
}

variable "bastion_subnet_id" {
  description = "Public subnet OCID for bastion host"
  type        = string
  default     = ""
}

variable "nsg_ids" {
  description = "Network Security Group OCIDs"
  type        = list(string)
  default     = []
}

variable "instance_shape" {
  description = "Compute instance shape"
  type        = string
  default     = "VM.Standard.E4.Flex"
}

variable "instance_ocpus" {
  description = "Number of OCPUs for flex shapes"
  type        = number
  default     = 2
}

variable "instance_memory_gb" {
  description = "Memory in GB for flex shapes"
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
  description = "Whether to create a bastion host"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Freeform tags for resources"
  type        = map(string)
  default     = {}
}
