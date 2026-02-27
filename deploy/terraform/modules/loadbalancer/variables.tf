# Load Balancer Module Variables

variable "compartment_id" {
  description = "OCI Compartment OCID"
  type        = string
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "observability"
}

variable "subnet_id" {
  description = "Public subnet OCID for load balancer"
  type        = string
}

variable "nsg_ids" {
  description = "Network Security Group OCIDs"
  type        = list(string)
  default     = []
}

variable "lb_shape" {
  description = "Load balancer shape: flexible, 100Mbps, 400Mbps, 8000Mbps"
  type        = string
  default     = "flexible"
}

variable "lb_min_bandwidth" {
  description = "Minimum bandwidth for flexible shape (Mbps)"
  type        = number
  default     = 10
}

variable "lb_max_bandwidth" {
  description = "Maximum bandwidth for flexible shape (Mbps)"
  type        = number
  default     = 100
}

variable "backend_port" {
  description = "Backend application port"
  type        = number
  default     = 9010
}

variable "backend_ip" {
  description = "Backend IP address (for VM mode) - registers instance with the backend set"
  type        = string
  default     = ""
}

variable "create_backend" {
  description = "Whether to create a backend (must be known at plan time, unlike backend_ip)"
  type        = bool
  default     = false
}

variable "health_check_path" {
  description = "Health check URL path"
  type        = string
  default     = "/health"
}

variable "certificate_name" {
  description = "SSL certificate name (empty to skip SSL)"
  type        = string
  default     = ""
}

variable "public_certificate" {
  description = "Public SSL certificate (PEM format)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "private_key" {
  description = "SSL private key (PEM format)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "ca_certificate" {
  description = "CA certificate chain (PEM format)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "primary_hostname" {
  description = "Primary hostname (e.g., observability.learnoci.cloud)"
  type        = string
  default     = ""
}

variable "secondary_hostname" {
  description = "Secondary hostname (e.g., observability.cyber-sec.ro)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Freeform tags for resources"
  type        = map(string)
  default     = {}
}
