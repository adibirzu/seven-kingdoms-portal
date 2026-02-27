"""
C2: GOADv3 Active Directory Lab.

Deploys 5 Windows VMs (3 DCs + 2 servers) + Ubuntu jumpbox in a separate
VCN (192.168.0.0/16), peered to the app VCN via LPG. Runs Ansible
provisioning through the jumpbox to set up the AD forest.
"""

from components.base import ComponentDeployer


class GOADDeployer(ComponentDeployer):
    name = "c2"
    display_name = "GOADv3 Active Directory"
    dependencies = ["c1"]
    optional = True

    def prerequisites(self) -> tuple[bool, list[str]]:
        messages = []
        if not self.config.deploy_goad:
            messages.append("DEPLOY_GOAD=false — skipping GOAD deployment")
            return False, messages
        if not self.config.compartment_id:
            messages.append("OCI_COMPARTMENT_ID not set")
        if not self.config.vcn_ocid:
            messages.append("VCN_OCID not set (deploy C1 first)")

        deps_ok, dep_msgs = self.check_dependencies()
        messages.extend(dep_msgs)
        return len(messages) == 0, messages

    def get_steps(self) -> list[tuple[str, str]]:
        return [
            ("deploy_goad.sh", "Terraform apply: GOAD VCN, Windows VMs, jumpbox, LPG peering"),
            ("provision_goad_ad.sh", "Ansible: AD forest provisioning via jumpbox"),
        ]

    def verify(self) -> bool:
        print(f"  [{self.name}] Checking GOAD jumpbox IP...")
        if self.config.goad_jumpbox_ip:
            print(f"  OK: GOAD_JUMPBOX_IP = {self.config.goad_jumpbox_ip}")
            return True
        if not self.config.deploy_goad:
            print("  OK: GOAD deployment disabled (DEPLOY_GOAD=false)")
            return True
        print("  FAIL: GOAD_JUMPBOX_IP not set")
        return False

    def destroy(self) -> bool:
        result = self.run_script("destroy_goad.sh", env_extra=self._build_env())
        self.results.append(result)
        return result.success
