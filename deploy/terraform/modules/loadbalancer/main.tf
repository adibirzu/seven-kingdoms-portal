# Load Balancer Module - LB with SSL and WAF integration

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

# Load Balancer
resource "oci_load_balancer_load_balancer" "main" {
  compartment_id = var.compartment_id
  display_name   = "${var.project_name}-lb"
  shape          = var.lb_shape

  dynamic "shape_details" {
    for_each = var.lb_shape == "flexible" ? [1] : []
    content {
      minimum_bandwidth_in_mbps = var.lb_min_bandwidth
      maximum_bandwidth_in_mbps = var.lb_max_bandwidth
    }
  }

  subnet_ids = [var.subnet_id]

  network_security_group_ids = var.nsg_ids

  is_private = false

  freeform_tags = var.tags
}

# Backend Set
resource "oci_load_balancer_backend_set" "main" {
  load_balancer_id = oci_load_balancer_load_balancer.main.id
  name             = "${var.project_name}-backend-set"
  policy           = "ROUND_ROBIN"

  health_checker {
    protocol          = "HTTP"
    port              = var.backend_port
    url_path          = var.health_check_path
    return_code       = 200
    interval_ms       = 10000
    timeout_in_millis = 3000
    retries           = 3
  }

  session_persistence_configuration {
    cookie_name      = "lb-session"
    disable_fallback = false
  }
}

# Backend (VM mode) - register backend instance with the load balancer
resource "oci_load_balancer_backend" "vm" {
  count = var.create_backend ? 1 : 0

  load_balancer_id = oci_load_balancer_load_balancer.main.id
  backendset_name  = oci_load_balancer_backend_set.main.name
  ip_address       = var.backend_ip
  port             = var.backend_port
}

# Certificate (if provided)
resource "oci_load_balancer_certificate" "main" {
  count = var.certificate_name != "" ? 1 : 0

  certificate_name   = var.certificate_name
  load_balancer_id   = oci_load_balancer_load_balancer.main.id
  public_certificate = var.public_certificate
  private_key        = var.private_key
  ca_certificate     = var.ca_certificate

  lifecycle {
    create_before_destroy = true
  }
}

# HTTPS Listener
resource "oci_load_balancer_listener" "https" {
  count = var.certificate_name != "" ? 1 : 0

  load_balancer_id         = oci_load_balancer_load_balancer.main.id
  name                     = "https-listener"
  default_backend_set_name = oci_load_balancer_backend_set.main.name
  port                     = 443
  protocol                 = "HTTP"

  ssl_configuration {
    certificate_name        = oci_load_balancer_certificate.main[0].certificate_name
    verify_peer_certificate = false
    protocols               = ["TLSv1.2", "TLSv1.3"]
    cipher_suite_name       = "oci-modern-ssl-cipher-suite-v1"
  }

  connection_configuration {
    idle_timeout_in_seconds = 300
  }
}

# HTTP Listener (redirect to HTTPS or direct access)
resource "oci_load_balancer_listener" "http" {
  load_balancer_id         = oci_load_balancer_load_balancer.main.id
  name                     = "http-listener"
  default_backend_set_name = oci_load_balancer_backend_set.main.name
  port                     = 80
  protocol                 = "HTTP"

  connection_configuration {
    idle_timeout_in_seconds = 60
  }
}

# HTTP to HTTPS Redirect Rule Set (if SSL enabled)
resource "oci_load_balancer_rule_set" "redirect_to_https" {
  count = var.certificate_name != "" ? 1 : 0

  load_balancer_id = oci_load_balancer_load_balancer.main.id
  name             = "redirect-to-https"

  items {
    action = "REDIRECT"

    redirect_uri {
      protocol = "HTTPS"
      host     = "{host}"
      port     = 443
      path     = "{path}"
      query    = "{query}"
    }

    response_code = 301
  }
}

# Host-based routing rule set
resource "oci_load_balancer_rule_set" "host_routing" {
  load_balancer_id = oci_load_balancer_load_balancer.main.id
  name             = "host_routing"

  items {
    action = "ADD_HTTP_RESPONSE_HEADER"
    header = "X-Served-By"
    value  = "OCI-LB"
  }

  items {
    action = "ADD_HTTP_RESPONSE_HEADER"
    header = "X-Frame-Options"
    value  = "DENY"
  }

  items {
    action = "ADD_HTTP_RESPONSE_HEADER"
    header = "X-Content-Type-Options"
    value  = "nosniff"
  }

  items {
    action = "ADD_HTTP_RESPONSE_HEADER"
    header = "Strict-Transport-Security"
    value  = "max-age=31536000; includeSubDomains"
  }
}

# Hostname for primary domain
resource "oci_load_balancer_hostname" "primary" {
  count = var.primary_hostname != "" ? 1 : 0

  hostname         = var.primary_hostname
  load_balancer_id = oci_load_balancer_load_balancer.main.id
  name             = "primary-hostname"
}

# Hostname for secondary domain
resource "oci_load_balancer_hostname" "secondary" {
  count = var.secondary_hostname != "" ? 1 : 0

  hostname         = var.secondary_hostname
  load_balancer_id = oci_load_balancer_load_balancer.main.id
  name             = "secondary-hostname"
}
