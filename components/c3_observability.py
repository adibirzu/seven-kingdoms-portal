"""
C3: Observability — APM domain, Log Analytics, Monitoring alarms.

Creates OCI APM domain (for distributed tracing), Log Analytics namespace
and log group (for app logs), and Monitoring alarm definitions.
"""

from components.base import ComponentDeployer


class ObservabilityDeployer(ComponentDeployer):
    name = "c3"
    display_name = "Observability (APM, Logging, Monitoring)"
    dependencies = ["c1"]

    def prerequisites(self) -> tuple[bool, list[str]]:
        messages = []
        if not self.config.compartment_id:
            messages.append("OCI_COMPARTMENT_ID not set")

        deps_ok, dep_msgs = self.check_dependencies()
        messages.extend(dep_msgs)
        return len(messages) == 0, messages

    def get_steps(self) -> list[tuple[str, str]]:
        return [
            ("deploy_observability.sh", "Create APM domain, Log Analytics, Monitoring alarms"),
        ]

    def verify(self) -> bool:
        print(f"  [{self.name}] Checking APM endpoint...")
        if self.config.oci_apm_endpoint:
            print(f"  OK: OCI_APM_ENDPOINT = {self.config.oci_apm_endpoint}")
            return True
        print("  FAIL: OCI_APM_ENDPOINT not set (run deploy first)")
        return False

    def destroy(self) -> bool:
        result = self.run_script("destroy_observability.sh", env_extra=self._build_env())
        self.results.append(result)
        return result.success
