"""
C4: Application Deployment — the Seven Kingdoms Portal vulnerable app.

Supports three deployment modes (APP_DEPLOY_MODE):
  - vm:     OCI Compute VM + systemd service
  - docker: Local Docker build + run
  - oke:    OKE cluster + OCIR push + kubectl apply
"""

from components.base import ComponentDeployer


class AppDeployer(ComponentDeployer):
    name = "c4"
    display_name = "Application (Vulnerable Portal)"
    dependencies = ["c1"]

    def prerequisites(self) -> tuple[bool, list[str]]:
        messages = []
        mode = self.config.app_deploy_mode

        if mode not in ("vm", "docker", "oke"):
            messages.append(f"Invalid APP_DEPLOY_MODE: {mode} (must be vm, docker, or oke)")

        if mode in ("vm", "oke"):
            if not self.config.compartment_id:
                messages.append("OCI_COMPARTMENT_ID not set")
            if not self.config.vcn_ocid:
                messages.append("VCN_OCID not set (deploy C1 first)")

        if mode == "oke" and not self.config.ocir_url:
            messages.append("OCIR_URL not set (needed for OKE image push)")

        deps_ok, dep_msgs = self.check_dependencies()
        messages.extend(dep_msgs)
        return len(messages) == 0, messages

    def get_steps(self) -> list[tuple[str, str]]:
        mode = self.config.app_deploy_mode
        if mode == "vm":
            return [
                ("deploy_app_vm.sh", "Terraform: compute instance + cloud-init"),
                ("deploy_app_code.sh", "Deploy app code via bastion SSH"),
            ]
        elif mode == "docker":
            return [
                ("deploy_app_docker.sh", "Docker build + run locally"),
            ]
        elif mode == "oke":
            return [
                ("deploy_app_oke.sh", "OKE: build image, push OCIR, kubectl apply"),
            ]
        return []

    def verify(self) -> bool:
        import subprocess
        print(f"  [{self.name}] Checking app health...")

        candidates = []
        if self.config.app_url:
            candidates.append(self.config.app_url.rstrip("/"))
        if self.config.app_instance_ip:
            ip = self.config.app_instance_ip.strip()
            if ip.startswith(("http://", "https://")):
                candidates.append(ip.rstrip("/"))
            else:
                candidates.append(f"http://{ip}:9010")

        for base in candidates:
            try:
                result = subprocess.run(
                    ["curl", "-sf", "--max-time", "10", f"{base}/health"],
                    capture_output=True, text=True, timeout=15,
                )
                if result.returncode == 0:
                    print(f"  OK: {base}/health — healthy")
                    return True
            except Exception:
                continue

        if not candidates:
            print("  FAIL: No APP_URL or APP_INSTANCE_IP configured")
        else:
            print(f"  FAIL: No healthy endpoint found ({', '.join(c + '/health' for c in candidates)})")
        return False

    def destroy(self) -> bool:
        mode = self.config.app_deploy_mode
        script = {
            "vm": "destroy_app_vm.sh",
            "docker": "destroy_app_docker.sh",
            "oke": "destroy_app_oke.sh",
        }.get(mode, "destroy_app_vm.sh")
        result = self.run_script(script, env_extra=self._build_env())
        self.results.append(result)
        return result.success
