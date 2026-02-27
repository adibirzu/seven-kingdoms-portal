# Production Environment - Main Configuration
# OCI Observability Overview Application

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }

  # Uncomment for remote state storage
  # backend "s3" {
  #   bucket                      = "terraform-state"
  #   key                         = "observability/prod/terraform.tfstate"
  #   region                      = "us-ashburn-1"
  #   endpoint                    = "https://<namespace>.compat.objectstorage.<region>.oraclecloud.com"
  #   skip_region_validation      = true
  #   skip_credentials_validation = true
  #   skip_metadata_api_check     = true
  #   force_path_style            = true
  # }
}

# OCI Provider
# - Local usage: reads ~/.oci/config [DEFAULT] profile automatically
# - Control plane / OCI Instance: oci_auth_mode = "InstancePrincipal" (or use_instance_principals = true)
locals {
  # oci_auth_mode takes precedence when set; falls back to use_instance_principals boolean
  effective_auth = var.oci_auth_mode != "" ? var.oci_auth_mode : (var.use_instance_principals ? "InstancePrincipal" : "APIKey")
  needs_config   = contains(["APIKey", "SecurityToken"], local.effective_auth)
}

provider "oci" {
  region              = var.region
  config_file_profile = local.needs_config ? var.oci_profile : null
  auth                = local.effective_auth
}

# Get availability domains (compartment_id can be any compartment — ADs are tenancy-level)
data "oci_identity_availability_domains" "ads" {
  compartment_id = var.compartment_id
}

locals {
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name

  common_tags = {
    Project     = "observability-overview"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Network Module
module "network" {
  source = "../../modules/network"

  compartment_id      = var.compartment_id
  project_name        = var.project_name
  vcn_cidr            = var.vcn_cidr
  public_subnet_cidr  = var.public_subnet_cidr
  private_subnet_cidr = var.private_subnet_cidr
  oke_api_subnet_cidr = var.oke_api_subnet_cidr
  create_oke_subnets  = var.deployment_mode == "oke" || var.deployment_mode == "hybrid"
  tags                = local.common_tags
}

# Compute Module (VM Mode)
module "compute" {
  count  = var.deployment_mode == "vm" || var.deployment_mode == "hybrid" ? 1 : 0
  source = "../../modules/compute"

  compartment_id      = var.compartment_id
  project_name        = var.project_name
  availability_domain = local.availability_domain
  subnet_id           = module.network.private_subnet_id
  bastion_subnet_id   = module.network.public_subnet_id
  nsg_ids             = [module.network.app_nsg_id]
  instance_shape      = var.instance_shape
  instance_ocpus      = var.instance_ocpus
  instance_memory_gb  = var.instance_memory_gb
  boot_volume_size_gb = var.boot_volume_size_gb
  ssh_public_key      = var.ssh_public_key
  create_bastion      = var.create_bastion
  tags                = local.common_tags
}

# OKE Module (Kubernetes Mode)
module "oke" {
  count  = var.deployment_mode == "oke" || var.deployment_mode == "hybrid" ? 1 : 0
  source = "../../modules/oke"

  compartment_id         = var.compartment_id
  project_name           = var.project_name
  vcn_id                 = module.network.vcn_id
  availability_domain    = local.availability_domain
  api_endpoint_subnet_id = module.network.oke_api_subnet_id
  node_subnet_id         = module.network.private_subnet_id
  service_lb_subnet_id   = module.network.public_subnet_id
  node_nsg_ids           = [module.network.app_nsg_id]
  kubernetes_version     = var.kubernetes_version
  node_pool_size         = var.node_pool_size
  node_shape             = var.node_shape
  node_ocpus             = var.node_ocpus
  node_memory_gb         = var.node_memory_gb
  ssh_public_key         = var.ssh_public_key
  tags                   = local.common_tags
}

# Load Balancer Module
module "loadbalancer" {
  source = "../../modules/loadbalancer"

  compartment_id     = var.compartment_id
  project_name       = var.project_name
  subnet_id          = module.network.public_subnet_id
  nsg_ids            = [module.network.lb_nsg_id]
  lb_shape           = var.lb_shape
  lb_min_bandwidth   = var.lb_min_bandwidth
  lb_max_bandwidth   = var.lb_max_bandwidth
  backend_port       = var.backend_port
  create_backend     = var.deployment_mode == "vm" || var.deployment_mode == "hybrid"
  backend_ip         = var.deployment_mode == "vm" || var.deployment_mode == "hybrid" ? module.compute[0].instance_private_ip : ""
  health_check_path  = var.health_check_path
  certificate_name   = var.ssl_certificate_name
  public_certificate = var.ssl_public_certificate
  private_key        = var.ssl_private_key
  ca_certificate     = var.ssl_ca_certificate
  primary_hostname   = var.primary_hostname
  secondary_hostname = var.secondary_hostname
  tags               = local.common_tags
}

# WAF Module disabled by OCI-DEMO orchestrator

# DNS Module
module "dns" {
  source = "../../modules/dns"

  compartment_id        = var.compartment_id
  project_name          = var.project_name
  lb_public_ip          = module.loadbalancer.lb_public_ip
  create_dns_records    = var.create_primary_dns_zone || var.create_secondary_dns_zone || var.primary_zone_id != "" || var.secondary_zone_id != ""
  create_primary_zone   = var.create_primary_dns_zone
  primary_zone_name     = var.primary_zone_name
  primary_zone_id       = var.primary_zone_id
  primary_hostname      = var.primary_hostname
  create_secondary_zone = var.create_secondary_dns_zone
  secondary_zone_name   = var.secondary_zone_name
  secondary_zone_id     = var.secondary_zone_id
  secondary_hostname    = var.secondary_hostname
  dns_ttl               = var.dns_ttl
  create_caa_records    = var.create_caa_records
  enable_health_check   = var.enable_dns_health_check
  health_check_path     = var.health_check_path
  tags                  = local.common_tags
}
