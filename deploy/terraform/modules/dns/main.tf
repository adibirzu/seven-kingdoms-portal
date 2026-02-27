# DNS Module - DNS Zones and Records

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

# Primary DNS Zone (learnoci.cloud)
resource "oci_dns_zone" "primary" {
  count = var.create_primary_zone ? 1 : 0

  compartment_id = var.compartment_id
  name           = var.primary_zone_name
  zone_type      = "PRIMARY"

  freeform_tags = var.tags
}

# Secondary DNS Zone (cyber-sec.ro)
resource "oci_dns_zone" "secondary" {
  count = var.create_secondary_zone ? 1 : 0

  compartment_id = var.compartment_id
  name           = var.secondary_zone_name
  zone_type      = "PRIMARY"

  freeform_tags = var.tags
}

# A Record for primary domain
resource "oci_dns_rrset" "primary_a" {
  count = var.create_dns_records && (var.create_primary_zone || var.primary_zone_id != "") ? 1 : 0

  domain          = var.primary_hostname
  rtype           = "A"
  zone_name_or_id = var.create_primary_zone ? oci_dns_zone.primary[0].id : var.primary_zone_id
  compartment_id  = var.compartment_id

  items {
    domain = var.primary_hostname
    rtype  = "A"
    rdata  = var.lb_public_ip
    ttl    = var.dns_ttl
  }
}

# A Record for secondary domain
resource "oci_dns_rrset" "secondary_a" {
  count = var.create_dns_records && (var.create_secondary_zone || var.secondary_zone_id != "") ? 1 : 0

  domain          = var.secondary_hostname
  rtype           = "A"
  zone_name_or_id = var.create_secondary_zone ? oci_dns_zone.secondary[0].id : var.secondary_zone_id
  compartment_id  = var.compartment_id

  items {
    domain = var.secondary_hostname
    rtype  = "A"
    rdata  = var.lb_public_ip
    ttl    = var.dns_ttl
  }
}

# CAA Records for certificate authority authorization
resource "oci_dns_rrset" "primary_caa" {
  count = var.create_caa_records && (var.create_primary_zone || var.primary_zone_id != "") ? 1 : 0

  domain          = var.primary_zone_name
  rtype           = "CAA"
  zone_name_or_id = var.create_primary_zone ? oci_dns_zone.primary[0].id : var.primary_zone_id
  compartment_id  = var.compartment_id

  items {
    domain = var.primary_zone_name
    rtype  = "CAA"
    rdata  = "0 issue \"letsencrypt.org\""
    ttl    = var.dns_ttl
  }

  items {
    domain = var.primary_zone_name
    rtype  = "CAA"
    rdata  = "0 issuewild \"letsencrypt.org\""
    ttl    = var.dns_ttl
  }
}

resource "oci_dns_rrset" "secondary_caa" {
  count = var.create_caa_records && (var.create_secondary_zone || var.secondary_zone_id != "") ? 1 : 0

  domain          = var.secondary_zone_name
  rtype           = "CAA"
  zone_name_or_id = var.create_secondary_zone ? oci_dns_zone.secondary[0].id : var.secondary_zone_id
  compartment_id  = var.compartment_id

  items {
    domain = var.secondary_zone_name
    rtype  = "CAA"
    rdata  = "0 issue \"letsencrypt.org\""
    ttl    = var.dns_ttl
  }

  items {
    domain = var.secondary_zone_name
    rtype  = "CAA"
    rdata  = "0 issuewild \"letsencrypt.org\""
    ttl    = var.dns_ttl
  }
}

# TXT Record for domain verification (optional)
resource "oci_dns_rrset" "primary_txt" {
  count = var.primary_verification_txt != "" && (var.create_primary_zone || var.primary_zone_id != "") ? 1 : 0

  domain          = var.primary_zone_name
  rtype           = "TXT"
  zone_name_or_id = var.create_primary_zone ? oci_dns_zone.primary[0].id : var.primary_zone_id
  compartment_id  = var.compartment_id

  items {
    domain = var.primary_zone_name
    rtype  = "TXT"
    rdata  = "\"${var.primary_verification_txt}\""
    ttl    = var.dns_ttl
  }
}

resource "oci_dns_rrset" "secondary_txt" {
  count = var.secondary_verification_txt != "" && (var.create_secondary_zone || var.secondary_zone_id != "") ? 1 : 0

  domain          = var.secondary_zone_name
  rtype           = "TXT"
  zone_name_or_id = var.create_secondary_zone ? oci_dns_zone.secondary[0].id : var.secondary_zone_id
  compartment_id  = var.compartment_id

  items {
    domain = var.secondary_zone_name
    rtype  = "TXT"
    rdata  = "\"${var.secondary_verification_txt}\""
    ttl    = var.dns_ttl
  }
}

# Health Check for DNS failover (optional)
resource "oci_health_checks_http_monitor" "main" {
  count = var.enable_health_check && var.create_dns_records ? 1 : 0

  compartment_id      = var.compartment_id
  display_name        = "${var.project_name}-health-check"
  interval_in_seconds = 30
  protocol            = "HTTP"
  targets             = [var.lb_public_ip]
  port                = 80
  path                = var.health_check_path
  method              = "GET"
  timeout_in_seconds  = 10
  is_enabled          = true

  freeform_tags = var.tags
}
