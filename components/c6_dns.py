"""
C6: DNS — OCI DNS zone and records (optional).

Creates a DNS zone and A record pointing to the app Load Balancer IP.
Reuses the existing deploy/terraform/modules/dns module.
"""

from components.base import ComponentDeployer


class DNSDeployer(ComponentDeployer):
    name = "c6"
    display_name = "DNS (OCI DNS Zone & Records)"
    dependencies = ["c4"]
    optional = True

    def prerequisites(self) -> tuple[bool, list[str]]:
        messages = []
        if not self.config.deploy_dns:
            messages.append("DEPLOY_DNS=false — skipping DNS deployment")
            return False, messages
        if not self.config.compartment_id:
            messages.append("OCI_COMPARTMENT_ID not set")
        if not self.config.dns_zone_name:
            messages.append("DNS_ZONE_NAME not set")

        deps_ok, dep_msgs = self.check_dependencies()
        messages.extend(dep_msgs)
        return len(messages) == 0, messages

    def get_steps(self) -> list[tuple[str, str]]:
        return [
            ("deploy_dns.sh", "Terraform apply: DNS zone + A records"),
        ]

    def verify(self) -> bool:
        if not self.config.deploy_dns:
            print("  OK: DNS deployment disabled (DEPLOY_DNS=false)")
            return True
        if self.config.dns_hostname:
            print(f"  OK: DNS_HOSTNAME = {self.config.dns_hostname}")
            return True
        print("  FAIL: DNS_HOSTNAME not set")
        return False

    def destroy(self) -> bool:
        result = self.run_script("destroy_dns.sh", env_extra=self._build_env())
        self.results.append(result)
        return result.success
