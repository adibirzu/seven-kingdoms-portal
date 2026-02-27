from components.c1_infrastructure import InfrastructureDeployer
from components.c2_goad import GOADDeployer
from components.c3_observability import ObservabilityDeployer
from components.c4_app import AppDeployer
from components.c5_waf import WAFDeployer
from components.c6_dns import DNSDeployer
from components.c7_notifications import NotificationsDeployer

COMPONENTS = {
    "c1": InfrastructureDeployer,
    "c2": GOADDeployer,
    "c3": ObservabilityDeployer,
    "c4": AppDeployer,
    "c5": WAFDeployer,
    "c6": DNSDeployer,
    "c7": NotificationsDeployer,
}

__all__ = ["COMPONENTS"]
