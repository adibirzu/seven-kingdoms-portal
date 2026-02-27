# WAF Module - Web Application Firewall Policy

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

# WAF Policy
resource "oci_waf_web_app_firewall_policy" "main" {
  compartment_id = var.compartment_id
  display_name   = "${var.project_name}-waf-policy"

  # Request Access Control
  dynamic "request_access_control" {
    for_each = var.enable_access_control ? [1] : []
    content {
      default_action_name = "allowAction"

      rules {
        name               = "blockSuspiciousCountries"
        action_name        = var.block_suspicious_countries ? "blockAction" : "allowAction"
        type               = "ACCESS_CONTROL"
        condition          = "i_contains(`[\"CN\", \"RU\", \"KP\"]`, connection.source.geo.countryCode)"
        condition_language = "JMESPATH"
      }
    }
  }

  # Request Rate Limiting
  dynamic "request_rate_limiting" {
    for_each = var.enable_rate_limiting ? [1] : []
    content {
      rules {
        name        = "requestRateLimit"
        action_name = "rateLimitAction"
        type        = "REQUEST_RATE_LIMITING"

        configurations {
          period_in_seconds          = 60
          requests_limit             = var.rate_limit_requests_per_minute
          action_duration_in_seconds = 600
        }
      }
    }
  }

  # Request Protection - simplified for initial deployment
  # Full OWASP protection capabilities can be configured after deployment

  # Actions
  actions {
    name = "allowAction"
    type = "ALLOW"
  }

  actions {
    name = "blockAction"
    type = "RETURN_HTTP_RESPONSE"
    body {
      type = "STATIC_TEXT"
      text = "{\"error\": \"Request blocked by WAF\", \"code\": 403}"
    }
    code = 403
    headers {
      name  = "Content-Type"
      value = "application/json"
    }
  }

  actions {
    name = "rateLimitAction"
    type = "RETURN_HTTP_RESPONSE"
    body {
      type = "STATIC_TEXT"
      text = "{\"error\": \"Rate limit exceeded\", \"code\": 429}"
    }
    code = 429
    headers {
      name  = "Content-Type"
      value = "application/json"
    }
    headers {
      name  = "Retry-After"
      value = "600"
    }
  }

  freeform_tags = var.tags
}

# WAF Web App Firewall (attach to LB)
resource "oci_waf_web_app_firewall" "main" {
  count = var.attach_to_lb ? 1 : 0

  compartment_id             = var.compartment_id
  display_name               = "${var.project_name}-waf"
  backend_type               = "LOAD_BALANCER"
  load_balancer_id           = var.load_balancer_id
  web_app_firewall_policy_id = oci_waf_web_app_firewall_policy.main.id

  freeform_tags = var.tags
}

# WAF Logging (Optional)
resource "oci_logging_log_group" "waf" {
  count = var.enable_logging && var.attach_to_lb ? 1 : 0

  compartment_id = var.compartment_id
  display_name   = "${var.project_name}-waf-logs"
  description    = "Log group for WAF logs"

  freeform_tags = var.tags
}

resource "oci_logging_log" "waf_access" {
  count = var.enable_logging && var.attach_to_lb ? 1 : 0

  display_name = "${var.project_name}-waf-access-log"
  log_group_id = oci_logging_log_group.waf[0].id
  log_type     = "SERVICE"

  configuration {
    source {
      category    = "all"
      resource    = oci_waf_web_app_firewall.main[0].id
      service     = "waf"
      source_type = "OCISERVICE"
    }
    compartment_id = var.compartment_id
  }

  is_enabled         = true
  retention_duration = var.log_retention_days

  freeform_tags = var.tags
}
