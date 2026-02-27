# ═══════════════════════════════════════════════════════════════
# Seven Kingdoms Portal — ORM Stack
#
# Creates all infrastructure and a deployer VM that orchestrates
# the remaining deployment (Docker build, OCIR push, app deploy,
# GOAD AD provisioning, observability, WAF).
#
# Usage:
#   OCI Console → Resource Manager → Create Stack → point to this repo
#   Working Directory: stack/
# ═══════════════════════════════════════════════════════════════

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0"
    }
  }
}

provider "oci" {
  tenancy_ocid = var.tenancy_ocid
  region       = var.region
}

# ── Data Sources ──

data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

data "oci_core_images" "oracle_linux" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Oracle Linux"
  operating_system_version = "8"
  shape                    = var.deployer_shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"

  filter {
    name   = "display_name"
    values = ["^Oracle-Linux-8\\.[0-9]+-[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}-[0-9]+$"]
    regex  = true
  }
}

data "oci_objectstorage_namespace" "ns" {
  compartment_id = var.compartment_ocid
}

locals {
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  project_name        = "skp"
  oci_namespace       = data.oci_objectstorage_namespace.ns.namespace

  common_tags = {
    Project   = "seven-kingdoms-portal"
    ManagedBy = "orm-stack"
  }

  # OKE API subnet CIDR (derived from VCN)
  oke_api_subnet_cidr = cidrsubnet(var.vcn_cidr, 8, 3)

  # Components to deploy via deploy.py (c1 skipped — infra created by this stack)
  deploy_components = join(",", compact([
    var.deploy_goad ? "c2" : "",
    var.deploy_observability ? "c3" : "",
    "c4",
    var.deploy_waf ? "c5" : "",
  ]))

  # Generate JWT secret if not provided
  jwt_secret = var.portal_jwt_secret != "" ? var.portal_jwt_secret : "skp-${random_string.jwt_secret.result}"
}

resource "random_string" "jwt_secret" {
  length  = 32
  special = false
}

# ── OCIR Authentication (for Docker image push) ──

data "oci_identity_user" "current" {
  user_id = var.current_user_ocid
}

resource "oci_identity_auth_token" "ocir" {
  count       = var.app_deploy_mode != "vm" ? 1 : 0
  user_id     = var.current_user_ocid
  description = "skp-stack-ocir-push"
}

# ── SSH Key for internal use (deployer → GOAD jumpbox, app VMs) ──

resource "tls_private_key" "deploy_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# ═══════════════════════════════════════════════════════════════
# 1. NETWORKING — App VCN + Subnets
# ═══════════════════════════════════════════════════════════════

module "network" {
  source = "../deploy/terraform/modules/network"

  compartment_id      = var.compartment_ocid
  project_name        = local.project_name
  vcn_cidr            = var.vcn_cidr
  public_subnet_cidr  = var.public_subnet_cidr
  private_subnet_cidr = var.private_subnet_cidr
  oke_api_subnet_cidr = local.oke_api_subnet_cidr
  create_oke_subnets  = var.app_deploy_mode == "oke"
  enable_goad_peering = var.deploy_goad
  goad_vcn_cidr       = var.goad_vcn_cidr
  tags                = local.common_tags
}

# ═══════════════════════════════════════════════════════════════
# 2. OKE CLUSTER (if oke mode — starts early, takes 10-15 min)
# ═══════════════════════════════════════════════════════════════

module "oke" {
  count  = var.app_deploy_mode == "oke" ? 1 : 0
  source = "../deploy/terraform/modules/oke"

  compartment_id         = var.compartment_ocid
  project_name           = local.project_name
  vcn_id                 = module.network.vcn_id
  availability_domain    = local.availability_domain
  api_endpoint_subnet_id = module.network.oke_api_subnet_id
  node_subnet_id         = module.network.private_subnet_id
  service_lb_subnet_id   = module.network.public_subnet_id
  node_nsg_ids           = [module.network.app_nsg_id]
  node_pool_size         = var.oke_node_pool_size
  node_shape             = var.oke_node_shape
  node_ocpus             = var.oke_node_ocpus
  node_memory_gb         = var.oke_node_memory_gb
  ssh_public_key         = var.ssh_public_key
  tags                   = local.common_tags
}

# ═══════════════════════════════════════════════════════════════
# 3. GOAD VCN + WINDOWS VMs (if enabled)
# ═══════════════════════════════════════════════════════════════

module "goad" {
  count  = var.deploy_goad ? 1 : 0
  source = "../goad/terraform"

  compartment_ocid    = var.compartment_ocid
  region              = var.region
  availability_domain = local.availability_domain
  ssh_authorized_keys = "${var.ssh_public_key}\n${tls_private_key.deploy_key.public_key_openssh}"
  app_lpg_id          = module.network.app_lpg_id
  windows_shape       = var.goad_vm_shape
  windows_ocpus       = var.goad_vm_ocpus
  windows_memory_gbs  = var.goad_vm_memory_gb

  depends_on = [module.network]
}

# ═══════════════════════════════════════════════════════════════
# 4. IAM — Dynamic Group + Policy for Instance Principal
# ═══════════════════════════════════════════════════════════════

resource "oci_identity_dynamic_group" "deployer" {
  compartment_id = var.tenancy_ocid
  name           = "skp-stack-deployer"
  description    = "Seven Kingdoms Portal stack deployer instance"
  matching_rule  = "instance.id = '${oci_core_instance.deployer.id}'"

  freeform_tags = local.common_tags
}

resource "oci_identity_policy" "deployer" {
  compartment_id = var.tenancy_ocid
  name           = "skp-stack-deployer-policy"
  description    = "Allow SKP deployer to manage resources for platform deployment"
  statements = [
    "Allow dynamic-group skp-stack-deployer to manage all-resources in compartment id ${var.compartment_ocid}",
    "Allow dynamic-group skp-stack-deployer to manage repos in tenancy",
  ]

  freeform_tags = local.common_tags
}

# ═══════════════════════════════════════════════════════════════
# 5. DEPLOYER VM — Orchestrates remaining deployment
# ═══════════════════════════════════════════════════════════════

resource "oci_core_instance" "deployer" {
  compartment_id      = var.compartment_ocid
  availability_domain = local.availability_domain
  display_name        = "${local.project_name}-stack-deployer"
  shape               = var.deployer_shape

  shape_config {
    ocpus         = var.deployer_ocpus
    memory_in_gbs = var.deployer_memory_gb
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.oracle_linux.images[0].id
    boot_volume_size_in_gbs = 100
  }

  create_vnic_details {
    subnet_id        = module.network.public_subnet_id
    assign_public_ip = true
    nsg_ids          = [module.network.app_nsg_id]
  }

  metadata = {
    ssh_authorized_keys = "${var.ssh_public_key}\n${tls_private_key.deploy_key.public_key_openssh}"
    user_data = base64encode(templatefile("${path.module}/cloud-init.yaml", {
      region              = var.region
      compartment_ocid    = var.compartment_ocid
      tenancy_ocid        = var.tenancy_ocid
      oci_namespace       = local.oci_namespace
      app_deploy_mode     = var.app_deploy_mode
      deploy_components   = local.deploy_components
      deploy_goad         = var.deploy_goad
      deploy_waf          = var.deploy_waf
      app_port            = var.app_port
      jwt_secret          = local.jwt_secret

      # Network outputs
      vcn_ocid            = module.network.vcn_id
      public_subnet_ocid  = module.network.public_subnet_id
      private_subnet_ocid = module.network.private_subnet_id
      app_nsg_ocid        = module.network.app_nsg_id
      lb_nsg_ocid         = module.network.lb_nsg_id
      private_rt_ocid     = module.network.private_route_table_id
      app_lpg_ocid        = var.deploy_goad ? module.network.app_lpg_id : ""

      # OKE outputs (if applicable)
      oke_cluster_ocid = var.app_deploy_mode == "oke" ? module.oke[0].cluster_id : ""

      # GOAD outputs (if applicable)
      goad_jumpbox_ip = var.deploy_goad ? module.goad[0].jumpbox_public_ip : ""
      goad_vcn_ocid   = var.deploy_goad ? module.goad[0].goad_vcn_id : ""
      goad_lpg_ocid   = var.deploy_goad ? module.goad[0].goad_lpg_id : ""

      # OCIR Docker credentials (pre-computed as base64 to avoid shell escaping issues)
      ocir_docker_config = var.app_deploy_mode != "vm" ? jsonencode({
        auths = {
          "${var.region}.ocir.io" = {
            auth = base64encode("${local.oci_namespace}/${data.oci_identity_user.current.name}:${oci_identity_auth_token.ocir[0].token}")
          }
        }
      }) : ""
      app_deploy_mode_is_container = var.app_deploy_mode != "vm" ? "true" : "false"

      # SSH deploy key (for deployer → jumpbox/app VMs)
      deploy_private_key = tls_private_key.deploy_key.private_key_openssh
    }))
  }

  freeform_tags = local.common_tags

  # Note: Do NOT depend on oci_identity_policy.deployer — that would create a
  # circular dependency (policy → dynamic_group → deployer.id → policy).
  # The cloud-init includes a 60s sleep to wait for IAM policy propagation.
  depends_on = [module.network]
}
