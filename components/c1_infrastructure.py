"""
C1: Infrastructure — VCN, subnets, gateways, security lists, NSGs.

Reuses the existing deploy/terraform/modules/network module. Generates
terraform.tfvars from .env.local and runs terraform apply.
"""

from components.base import ComponentDeployer


class InfrastructureDeployer(ComponentDeployer):
    name = "c1"
    display_name = "Infrastructure (VCN & Network)"
    dependencies = []

    def prerequisites(self) -> tuple[bool, list[str]]:
        messages = []
        if not self.config.compartment_id:
            messages.append("OCI_COMPARTMENT_ID not set")
        if not self.config.oci_region:
            messages.append("OCI_REGION not set")
        return len(messages) == 0, messages

    def get_steps(self) -> list[tuple[str, str]]:
        return [
            ("deploy_infra.sh", "Terraform apply: VCN, subnets, gateways, NSGs"),
        ]

    def verify(self) -> bool:
        print(f"  [{self.name}] Checking VCN OCID...")
        if self.config.vcn_ocid:
            print(f"  OK: VCN_OCID = {self.config.vcn_ocid}")
            return True
        print("  FAIL: VCN_OCID not set (run deploy first)")
        return False

    def destroy(self) -> bool:
        result = self.run_script("destroy_infra.sh", env_extra=self._build_env())
        self.results.append(result)
        return result.success
