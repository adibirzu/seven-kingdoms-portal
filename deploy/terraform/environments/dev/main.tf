# Development Environment - Main Configuration
# Simplified version for development/testing

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

provider "oci" {
  region              = var.region
  config_file_profile = var.use_instance_principals ? null : var.oci_profile
  auth                = var.use_instance_principals ? "InstancePrincipal" : "APIKey"
}

data "oci_identity_availability_domains" "ads" {
  compartment_id = var.compartment_id
}

locals {
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name

  common_tags = {
    Project     = "observability-overview"
    Environment = "dev"
    ManagedBy   = "terraform"
  }
}

# Network
module "network" {
  source = "../../modules/network"

  compartment_id      = var.compartment_id
  project_name        = "${var.project_name}-dev"
  vcn_cidr            = var.vcn_cidr
  public_subnet_cidr  = var.public_subnet_cidr
  private_subnet_cidr = var.private_subnet_cidr
  create_oke_subnets  = false
  tags                = local.common_tags
}

# Single VM for development
module "compute" {
  source = "../../modules/compute"

  compartment_id      = var.compartment_id
  project_name        = "${var.project_name}-dev"
  availability_domain = local.availability_domain
  subnet_id           = module.network.private_subnet_id
  bastion_subnet_id   = module.network.public_subnet_id
  nsg_ids             = [module.network.app_nsg_id]
  instance_shape      = "VM.Standard.E4.Flex"
  instance_ocpus      = 1
  instance_memory_gb  = 8
  boot_volume_size_gb = 50
  ssh_public_key      = var.ssh_public_key
  create_bastion      = true
  tags                = local.common_tags
}

# Simple Load Balancer (no WAF for dev)
module "loadbalancer" {
  source = "../../modules/loadbalancer"

  compartment_id    = var.compartment_id
  project_name      = "${var.project_name}-dev"
  subnet_id         = module.network.public_subnet_id
  nsg_ids           = [module.network.lb_nsg_id]
  lb_shape          = "flexible"
  lb_min_bandwidth  = 10
  lb_max_bandwidth  = 10
  backend_port      = 9010
  create_backend    = true
  backend_ip        = module.compute.instance_private_ip
  health_check_path = "/health"
  tags              = local.common_tags
}

# Variables
variable "oci_profile" {
  type    = string
  default = "DEFAULT"
}
variable "use_instance_principals" {
  type    = bool
  default = false
}
variable "region" { type = string }
variable "compartment_id" { type = string }

variable "project_name" {
  type    = string
  default = "observability"
}

variable "ssh_public_key" { type = string }

variable "vcn_cidr" {
  type    = string
  default = "10.1.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.1.1.0/24"
}

variable "private_subnet_cidr" {
  type    = string
  default = "10.1.2.0/24"
}

# Outputs
output "lb_public_ip" { value = module.loadbalancer.lb_public_ip }
output "instance_private_ip" { value = module.compute.instance_private_ip }
output "bastion_public_ip" { value = module.compute.bastion_public_ip }
output "access_url" { value = "http://${module.loadbalancer.lb_public_ip}" }
