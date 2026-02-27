"""
Seven Kingdoms Portal — deployment configuration.

Loads .env.local and exposes a Config dataclass with all project settings.
Components read their required values from Config rather than os.environ directly.
"""

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
logger = logging.getLogger(__name__)

_cached_config: Optional["Config"] = None


def load_env() -> Optional[Path]:
    """Load environment from .env.local (preferred) or .env."""
    for name in (".env.local", ".env"):
        path = ROOT / name
        if path.exists():
            load_dotenv(path, override=True)
            return path
    return None


def _get(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _bool(key: str, default: bool = False) -> bool:
    val = _get(key, "").strip().lower()
    if not val:
        return default
    return val in ("true", "1", "yes")


def _expand(path_str: str) -> str:
    return os.path.expanduser(path_str) if path_str else ""


@dataclass
class Config:
    """All project settings in one place."""

    # OCI authentication
    oci_profile: str = ""
    oci_region: str = ""
    oci_auth_mode: str = "auto"
    oci_config_file: str = ""
    compartment_id: str = ""
    tenancy_id: str = ""
    oci_namespace: str = ""

    # Component toggles
    deploy_goad: bool = True
    deploy_waf: bool = True
    deploy_dns: bool = False
    deploy_notifications: bool = False
    app_deploy_mode: str = "oke"  # vm | docker | oke

    # App settings
    app_port: str = "9010"
    app_workers: str = "4"
    environment: str = "production"
    portal_jwt_secret: str = ""

    # Infrastructure outputs (populated after C1 deploy)
    vcn_ocid: str = ""
    public_subnet_ocid: str = ""
    private_subnet_ocid: str = ""
    oke_api_subnet_ocid: str = ""
    app_nsg_ocid: str = ""
    lb_nsg_ocid: str = ""
    private_route_table_ocid: str = ""

    # GOAD outputs (populated after C2 deploy)
    goad_jumpbox_ip: str = ""
    goad_dc_kingslanding_ip: str = "192.168.56.10"
    goad_dc_winterfell_ip: str = "192.168.56.11"
    goad_dc_meereen_ip: str = "192.168.56.12"
    goad_mssql_castelblack_host: str = "192.168.56.22"
    goad_mssql_braavos_host: str = "192.168.56.23"
    goad_mssql_user: str = "sa"
    goad_mssql_password: str = ""
    goad_vcn_ocid: str = ""
    goad_lpg_ocid: str = ""
    app_lpg_ocid: str = ""

    # Observability (populated after C3 deploy)
    oci_apm_domain_id: str = ""
    oci_apm_endpoint: str = ""
    oci_apm_private_datakey: str = ""
    oci_apm_public_datakey: str = ""
    oci_log_group_ocid: str = ""
    oci_log_ocid: str = ""
    oci_monitoring_namespace: str = "CustomAttackMetrics"

    # App deployment outputs (populated after C4 deploy)
    app_url: str = ""
    app_lb_ocid: str = ""
    app_instance_ip: str = ""
    bastion_ip: str = ""

    # Docker/OCIR
    ocir_url: str = ""
    docker_image_tag: str = "latest"

    # SSH
    ssh_public_key_path: str = ""
    ssh_private_key_path: str = ""

    # WAF (populated after C5 deploy)
    waf_ocid: str = ""
    waf_policy_ocid: str = ""

    # DNS
    dns_zone_name: str = ""
    dns_hostname: str = ""

    @classmethod
    def from_env(cls, force_refresh: bool = False) -> "Config":
        """Create Config from environment variables."""
        global _cached_config
        if _cached_config is not None and not force_refresh:
            return _cached_config

        load_env()

        cfg = cls(
            # OCI auth
            oci_profile=_get("OCI_PROFILE", "DEFAULT"),
            oci_region=_get("OCI_REGION", "eu-frankfurt-1"),
            oci_auth_mode=_get("OCI_AUTH_MODE", "auto"),
            oci_config_file=_expand(_get("OCI_CONFIG_FILE", "~/.oci/config")),
            compartment_id=_get("OCI_COMPARTMENT_ID"),
            tenancy_id=_get("OCI_TENANCY_ID"),
            oci_namespace=_get("OCI_NAMESPACE"),

            # Component toggles
            deploy_goad=_bool("DEPLOY_GOAD", True),
            deploy_waf=_bool("DEPLOY_WAF", True),
            deploy_dns=_bool("DEPLOY_DNS", False),
            deploy_notifications=_bool("DEPLOY_NOTIFICATIONS", False),
            app_deploy_mode=_get("APP_DEPLOY_MODE", "oke"),

            # App
            app_port=_get("APP_PORT", "9010"),
            app_workers=_get("APP_WORKERS", "4"),
            environment=_get("ENVIRONMENT", "production"),
            portal_jwt_secret=_get("PORTAL_JWT_SECRET"),

            # Infrastructure outputs
            vcn_ocid=_get("VCN_OCID"),
            public_subnet_ocid=_get("PUBLIC_SUBNET_OCID"),
            private_subnet_ocid=_get("PRIVATE_SUBNET_OCID"),
            oke_api_subnet_ocid=_get("OKE_API_SUBNET_OCID"),
            app_nsg_ocid=_get("APP_NSG_OCID"),
            lb_nsg_ocid=_get("LB_NSG_OCID"),
            private_route_table_ocid=_get("PRIVATE_ROUTE_TABLE_OCID"),

            # GOAD
            goad_jumpbox_ip=_get("GOAD_JUMPBOX_IP"),
            goad_dc_kingslanding_ip=_get("GOAD_DC_KINGSLANDING_IP", "192.168.56.10"),
            goad_dc_winterfell_ip=_get("GOAD_DC_WINTERFELL_IP", "192.168.56.11"),
            goad_dc_meereen_ip=_get("GOAD_DC_MEEREEN_IP", "192.168.56.12"),
            goad_mssql_castelblack_host=_get("GOAD_MSSQL_CASTELBLACK_HOST", "192.168.56.22"),
            goad_mssql_braavos_host=_get("GOAD_MSSQL_BRAAVOS_HOST", "192.168.56.23"),
            goad_mssql_user=_get("GOAD_MSSQL_USER", "sa"),
            goad_mssql_password=_get("GOAD_MSSQL_PASSWORD"),
            goad_vcn_ocid=_get("GOAD_VCN_OCID"),
            goad_lpg_ocid=_get("GOAD_LPG_OCID"),
            app_lpg_ocid=_get("APP_LPG_OCID"),

            # Observability
            oci_apm_domain_id=_get("OCI_APM_DOMAIN_ID"),
            oci_apm_endpoint=_get("OCI_APM_ENDPOINT"),
            oci_apm_private_datakey=_get("OCI_APM_PRIVATE_DATAKEY"),
            oci_apm_public_datakey=_get("OCI_APM_PUBLIC_DATAKEY"),
            oci_log_group_ocid=_get("OCI_LOG_GROUP_OCID"),
            oci_log_ocid=_get("OCI_LOG_OCID"),
            oci_monitoring_namespace=_get("OCI_MONITORING_NAMESPACE", "CustomAttackMetrics"),

            # App outputs
            app_url=_get("APP_URL"),
            app_lb_ocid=_get("APP_LB_OCID"),
            app_instance_ip=_get("APP_INSTANCE_IP"),
            bastion_ip=_get("BASTION_IP"),

            # Docker/OCIR
            ocir_url=_get("OCIR_URL"),
            docker_image_tag=_get("DOCKER_IMAGE_TAG", "latest"),

            # SSH
            ssh_public_key_path=_expand(_get("SSH_PUBLIC_KEY_PATH", "~/.ssh/id_rsa.pub")),
            ssh_private_key_path=_expand(_get("SSH_PRIVATE_KEY_PATH", "~/.ssh/id_rsa")),

            # WAF
            waf_ocid=_get("WAF_OCID"),
            waf_policy_ocid=_get("WAF_POLICY_OCID"),

            # DNS
            dns_zone_name=_get("DNS_ZONE_NAME"),
            dns_hostname=_get("DNS_HOSTNAME"),
        )

        _cached_config = cfg
        return cfg

    def to_env_dict(self) -> dict[str, str]:
        """Export config as env var dict for shell scripts."""
        return {
            "OCI_PROFILE": self.oci_profile,
            "OCI_REGION": self.oci_region,
            "OCI_AUTH_MODE": self.oci_auth_mode,
            "OCI_CONFIG_FILE": self.oci_config_file,
            "OCI_COMPARTMENT_ID": self.compartment_id,
            "OCI_TENANCY_ID": self.tenancy_id,
            "OCI_NAMESPACE": self.oci_namespace,
            "APP_DEPLOY_MODE": self.app_deploy_mode,
            "APP_PORT": self.app_port,
            "APP_WORKERS": self.app_workers,
            "ENVIRONMENT": self.environment,
            "PORTAL_JWT_SECRET": self.portal_jwt_secret,
            "VCN_OCID": self.vcn_ocid,
            "PUBLIC_SUBNET_OCID": self.public_subnet_ocid,
            "PRIVATE_SUBNET_OCID": self.private_subnet_ocid,
            "OKE_API_SUBNET_OCID": self.oke_api_subnet_ocid,
            "APP_NSG_OCID": self.app_nsg_ocid,
            "LB_NSG_OCID": self.lb_nsg_ocid,
            "PRIVATE_ROUTE_TABLE_OCID": self.private_route_table_ocid,
            "GOAD_JUMPBOX_IP": self.goad_jumpbox_ip,
            "GOAD_DC_KINGSLANDING_IP": self.goad_dc_kingslanding_ip,
            "GOAD_DC_WINTERFELL_IP": self.goad_dc_winterfell_ip,
            "GOAD_DC_MEEREEN_IP": self.goad_dc_meereen_ip,
            "GOAD_MSSQL_CASTELBLACK_HOST": self.goad_mssql_castelblack_host,
            "GOAD_MSSQL_BRAAVOS_HOST": self.goad_mssql_braavos_host,
            "GOAD_MSSQL_USER": self.goad_mssql_user,
            "GOAD_MSSQL_PASSWORD": self.goad_mssql_password,
            "GOAD_VCN_OCID": self.goad_vcn_ocid,
            "GOAD_LPG_OCID": self.goad_lpg_ocid,
            "APP_LPG_OCID": self.app_lpg_ocid,
            "OCI_APM_DOMAIN_ID": self.oci_apm_domain_id,
            "OCI_APM_ENDPOINT": self.oci_apm_endpoint,
            "OCI_APM_PRIVATE_DATAKEY": self.oci_apm_private_datakey,
            "OCI_APM_PUBLIC_DATAKEY": self.oci_apm_public_datakey,
            "OCI_LOG_GROUP_OCID": self.oci_log_group_ocid,
            "OCI_LOG_OCID": self.oci_log_ocid,
            "APP_URL": self.app_url,
            "APP_LB_OCID": self.app_lb_ocid,
            "APP_INSTANCE_IP": self.app_instance_ip,
            "BASTION_IP": self.bastion_ip,
            "OCIR_URL": self.ocir_url,
            "DOCKER_IMAGE_TAG": self.docker_image_tag,
            "SSH_PUBLIC_KEY_PATH": self.ssh_public_key_path,
            "SSH_PRIVATE_KEY_PATH": self.ssh_private_key_path,
            "WAF_OCID": self.waf_ocid,
            "WAF_POLICY_OCID": self.waf_policy_ocid,
            "DNS_ZONE_NAME": self.dns_zone_name,
            "DNS_HOSTNAME": self.dns_hostname,
        }
