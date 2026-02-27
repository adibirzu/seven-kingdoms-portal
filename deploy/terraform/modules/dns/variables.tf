# DNS Module Variables

variable "compartment_id" {
  description = "OCI Compartment OCID"
  type        = string
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "observability"
}

variable "lb_public_ip" {
  description = "Load balancer public IP address"
  type        = string
  default     = ""
}

variable "create_dns_records" {
  description = "Whether to create DNS A records"
  type        = bool
  default     = false
}

# Primary zone (learnoci.cloud)
variable "create_primary_zone" {
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
  description = "Existing primary DNS zone OCID (if not creating)"
  type        = string
  default     = ""
}

variable "primary_hostname" {
  description = "Primary hostname (FQDN)"
  type        = string
  default     = "observability.learnoci.cloud"
}

variable "primary_verification_txt" {
  description = "TXT record for primary domain verification"
  type        = string
  default     = ""
}

# Secondary zone (cyber-sec.ro)
variable "create_secondary_zone" {
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
  description = "Existing secondary DNS zone OCID (if not creating)"
  type        = string
  default     = ""
}

variable "secondary_hostname" {
  description = "Secondary hostname (FQDN)"
  type        = string
  default     = "observability.cyber-sec.ro"
}

variable "secondary_verification_txt" {
  description = "TXT record for secondary domain verification"
  type        = string
  default     = ""
}

# DNS settings
variable "dns_ttl" {
  description = "DNS record TTL in seconds"
  type        = number
  default     = 300
}

variable "create_caa_records" {
  description = "Create CAA records for Let's Encrypt"
  type        = bool
  default     = true
}

# Health check
variable "enable_health_check" {
  description = "Enable DNS health check"
  type        = bool
  default     = false
}

variable "health_check_path" {
  description = "Health check URL path"
  type        = string
  default     = "/"
}

variable "tags" {
  description = "Freeform tags for resources"
  type        = map(string)
  default     = {}
}
