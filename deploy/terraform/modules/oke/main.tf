# OKE Module - Oracle Kubernetes Engine Cluster

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

# Get available Kubernetes versions
data "oci_containerengine_cluster_option" "oke_options" {
  cluster_option_id = "all"
}

locals {
  # Get the latest Kubernetes version
  kubernetes_version = var.kubernetes_version != "" ? var.kubernetes_version : element(
    sort(data.oci_containerengine_cluster_option.oke_options.kubernetes_versions),
    length(data.oci_containerengine_cluster_option.oke_options.kubernetes_versions) - 1
  )
}

# OKE Cluster
resource "oci_containerengine_cluster" "main" {
  compartment_id     = var.compartment_id
  kubernetes_version = local.kubernetes_version
  name               = "${var.project_name}-oke-cluster"
  vcn_id             = var.vcn_id

  cluster_pod_network_options {
    cni_type = var.cni_type
  }

  endpoint_config {
    is_public_ip_enabled = var.public_api_endpoint
    subnet_id            = var.api_endpoint_subnet_id
    nsg_ids              = var.api_endpoint_nsg_ids
  }

  options {
    add_ons {
      is_kubernetes_dashboard_enabled = false
      is_tiller_enabled               = false
    }

    kubernetes_network_config {
      pods_cidr     = var.pods_cidr
      services_cidr = var.services_cidr
    }

    service_lb_subnet_ids = [var.service_lb_subnet_id]
  }

  freeform_tags = var.tags
}

# Node Pool
resource "oci_containerengine_node_pool" "main" {
  cluster_id         = oci_containerengine_cluster.main.id
  compartment_id     = var.compartment_id
  kubernetes_version = local.kubernetes_version
  name               = "${var.project_name}-node-pool"

  node_config_details {
    placement_configs {
      availability_domain = var.availability_domain
      subnet_id           = var.node_subnet_id
    }

    size    = var.node_pool_size
    nsg_ids = var.node_nsg_ids

    node_pool_pod_network_option_details {
      cni_type = var.cni_type
    }
  }

  node_shape = var.node_shape

  dynamic "node_shape_config" {
    for_each = var.node_shape == "VM.Standard.E4.Flex" || var.node_shape == "VM.Standard.A1.Flex" ? [1] : []
    content {
      ocpus         = var.node_ocpus
      memory_in_gbs = var.node_memory_gb
    }
  }

  node_source_details {
    source_type = "IMAGE"
    image_id    = var.node_image_id != "" ? var.node_image_id : data.oci_containerengine_node_pool_option.node_pool_option.sources[0].image_id
  }

  initial_node_labels {
    key   = "app"
    value = "observability"
  }

  ssh_public_key = var.ssh_public_key

  freeform_tags = var.tags
}

# Get node pool options for images
data "oci_containerengine_node_pool_option" "node_pool_option" {
  node_pool_option_id = "all"
  compartment_id      = var.compartment_id
}

# Virtual Node Pool (Optional - for serverless)
resource "oci_containerengine_virtual_node_pool" "virtual" {
  count = var.create_virtual_node_pool ? 1 : 0

  cluster_id     = oci_containerengine_cluster.main.id
  compartment_id = var.compartment_id
  display_name   = "${var.project_name}-virtual-node-pool"

  placement_configurations {
    availability_domain = var.availability_domain
    subnet_id           = var.node_subnet_id
    fault_domain        = ["FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"]
  }

  pod_configuration {
    shape     = "Pod.Standard.E4.Flex"
    subnet_id = var.node_subnet_id
    nsg_ids   = var.node_nsg_ids
  }

  size = var.virtual_node_pool_size

  freeform_tags = var.tags
}
