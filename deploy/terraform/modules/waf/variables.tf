# WAF Module Variables

variable "compartment_id" {
  description = "OCI Compartment OCID"
  type        = string
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "observability"
}

variable "load_balancer_id" {
  description = "Load balancer OCID to attach WAF"
  type        = string
  default     = ""
}

variable "attach_to_lb" {
  description = "Whether to attach WAF to load balancer"
  type        = bool
  default     = true
}

variable "enable_access_control" {
  description = "Enable access control rules"
  type        = bool
  default     = true
}

variable "enable_rate_limiting" {
  description = "Enable rate limiting"
  type        = bool
  default     = true
}

variable "rate_limit_requests_per_minute" {
  description = "Maximum requests per minute before rate limiting"
  type        = number
  default     = 1000
}

variable "enable_request_protection" {
  description = "Enable OWASP protection rules"
  type        = bool
  default     = true
}

variable "block_suspicious_countries" {
  description = "Block requests from suspicious countries"
  type        = bool
  default     = false
}

variable "enable_logging" {
  description = "Enable WAF logging"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Log retention period in days"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Freeform tags for resources"
  type        = map(string)
  default     = {}
}
