"""
C7: Notifications — ONS topics and subscriptions (optional).

Creates OCI Notifications Service (ONS) topics for monitoring alarm alerts.
Supports email and Slack subscription endpoints.
"""

from components.base import ComponentDeployer


class NotificationsDeployer(ComponentDeployer):
    name = "c7"
    display_name = "Notifications (ONS Topics)"
    dependencies = ["c3"]
    optional = True

    def prerequisites(self) -> tuple[bool, list[str]]:
        messages = []
        if not self.config.deploy_notifications:
            messages.append("DEPLOY_NOTIFICATIONS=false — skipping")
            return False, messages
        if not self.config.compartment_id:
            messages.append("OCI_COMPARTMENT_ID not set")

        deps_ok, dep_msgs = self.check_dependencies()
        messages.extend(dep_msgs)
        return len(messages) == 0, messages

    def get_steps(self) -> list[tuple[str, str]]:
        return [
            ("deploy_notifications.sh", "Create ONS topic + subscriptions"),
        ]

    def verify(self) -> bool:
        if not self.config.deploy_notifications:
            print("  OK: Notifications disabled (DEPLOY_NOTIFICATIONS=false)")
            return True
        print("  OK: Notifications component (manual verification)")
        return True

    def destroy(self) -> bool:
        result = self.run_script("destroy_notifications.sh", env_extra=self._build_env())
        self.results.append(result)
        return result.success
