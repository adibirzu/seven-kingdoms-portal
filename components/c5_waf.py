"""
C5: WAF — Web Application Firewall policy on the app Load Balancer.

Applies OWASP protection rules, rate limiting, and optional geo-blocking.
Reuses the existing deploy/terraform/modules/waf module.
"""

from components.base import ComponentDeployer


class WAFDeployer(ComponentDeployer):
    name = "c5"
    display_name = "WAF (Web Application Firewall)"
    dependencies = ["c4"]
    optional = True

    def prerequisites(self) -> tuple[bool, list[str]]:
        messages = []
        if not self.config.deploy_waf:
            messages.append("DEPLOY_WAF=false — skipping WAF deployment")
            return False, messages
        if not self.config.compartment_id:
            messages.append("OCI_COMPARTMENT_ID not set")
        if not self.config.app_lb_ocid and self.config.app_deploy_mode != "docker":
            messages.append("APP_LB_OCID not set (deploy C4 first)")

        deps_ok, dep_msgs = self.check_dependencies()
        messages.extend(dep_msgs)
        return len(messages) == 0, messages

    def get_steps(self) -> list[tuple[str, str]]:
        return [
            ("deploy_waf.sh", "Terraform apply: WAF policy with OWASP rules"),
        ]

    def verify(self) -> bool:
        if not self.config.deploy_waf:
            print("  OK: WAF deployment disabled (DEPLOY_WAF=false)")
            return True
        if self.config.waf_policy_ocid:
            print(f"  OK: WAF_POLICY_OCID = {self.config.waf_policy_ocid}")
            return True
        print("  FAIL: WAF_POLICY_OCID not set")
        return False

    def destroy(self) -> bool:
        result = self.run_script("destroy_waf.sh", env_extra=self._build_env())
        self.results.append(result)
        return result.success
