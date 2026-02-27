"""
Base class for all Seven Kingdoms Portal component deployers.

Each component extends ComponentDeployer and implements:
  - prerequisites(): check env vars / conditions needed
  - verify(): health-check the deployed resources
  - destroy(): tear down the deployed resources
  - get_steps(): return list of (script, description) for step-based deploy
"""

import json
import logging
import os
import signal
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from shared.config import Config, ROOT

logger = logging.getLogger(__name__)

SCRIPTS_DIR = ROOT / "scripts"
STATE_DIR = ROOT / ".state"

STALE_TRANSITION_SECONDS = 1800  # 30 min


@dataclass
class StepResult:
    name: str
    success: bool
    duration_s: float = 0.0
    message: str = ""


@dataclass
class ComponentState:
    """Persisted state for a component."""
    name: str
    status: str = "not_deployed"  # not_deployed, deploying, deployed, failed, destroying
    deployed_at: str = ""
    outputs: dict = field(default_factory=dict)
    steps_completed: list = field(default_factory=list)
    error: str = ""
    updated_at: str = ""

    def save(self):
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        self.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        path = STATE_DIR / f"{self.name}.json"
        path.write_text(json.dumps(self.__dict__, indent=2))

    @classmethod
    def load(cls, name: str) -> "ComponentState":
        path = STATE_DIR / f"{name}.json"
        if path.exists():
            data = json.loads(path.read_text())
            known = {f.name for f in cls.__dataclass_fields__.values()}
            data = {k: v for k, v in data.items() if k in known}
            return cls(**data)
        return cls(name=name)

    def is_stale_transition(self) -> bool:
        if self.status not in ("deploying", "destroying"):
            return False
        if not self.updated_at:
            return True
        try:
            import calendar
            parts = time.strptime(self.updated_at, "%Y-%m-%dT%H:%M:%SZ")
            updated_epoch = calendar.timegm(parts)
            return (time.time() - updated_epoch) > STALE_TRANSITION_SECONDS
        except (ValueError, OverflowError):
            return True


class ComponentDeployer(ABC):
    """Abstract base class for component deployers."""

    name: str = ""
    display_name: str = ""
    dependencies: list[str] = []
    optional: bool = False

    def __init__(self, config: Config, dry_run: bool = False):
        self.config = config
        self.dry_run = dry_run
        self.state = ComponentState.load(self.name)
        self.results: list[StepResult] = []

    @abstractmethod
    def prerequisites(self) -> tuple[bool, list[str]]:
        """Check if all prerequisites are met."""
        ...

    def deploy(self) -> bool:
        """Run the deployment. Returns True on success."""
        steps = self.get_steps()
        if steps:
            return self._deploy_steps()
        return True

    @abstractmethod
    def verify(self) -> bool:
        """Run health checks. Returns True if all pass."""
        ...

    @abstractmethod
    def destroy(self) -> bool:
        """Tear down deployed resources. Returns True on success."""
        ...

    def get_steps(self) -> list[tuple[str, str]]:
        """Return list of (script, description) steps for this component."""
        return []

    def check_dependencies(self) -> tuple[bool, list[str]]:
        messages = []
        for dep in self.dependencies:
            dep_state = ComponentState.load(dep)
            if dep_state.status == "deployed":
                continue
            if dep_state.is_stale_transition():
                print(f"  WARNING: Dependency {dep} has stale '{dep_state.status}' state. "
                      f"Treating as available.")
                continue
            messages.append(f"Dependency {dep} not deployed (status: {dep_state.status})")
        return len(messages) == 0, messages

    def run_script(self, script_name: str, env_extra: dict = None, timeout: int = 600) -> StepResult:
        """Run a shell script from the scripts/ directory."""
        script_path = SCRIPTS_DIR / script_name
        if not script_path.exists():
            return StepResult(script_name, False, message=f"Script not found: {script_path}")

        if self.dry_run:
            logger.info("[DRY-RUN] Would run: %s", script_path)
            return StepResult(script_name, True, message="[DRY-RUN] Skipped")

        env = {**os.environ, **(env_extra or {})}
        logger.info("Running: %s", script_path)

        start = time.time()
        try:
            process = subprocess.Popen(
                ["bash", str(script_path)],
                env=env,
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                preexec_fn=os.setsid,
            )

            full_output = []
            if process.stdout:
                for line in iter(process.stdout.readline, ""):
                    print(line, end="", flush=True)
                    full_output.append(line)

            try:
                exit_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    process.wait(timeout=5)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                raise subprocess.TimeoutExpired(process.args, timeout)

            duration = time.time() - start
            output_text = "".join(full_output)

            if exit_code == 0:
                return StepResult(script_name, True, duration, "Success")
            else:
                last_err = output_text[-500:] if len(output_text) > 500 else output_text
                return StepResult(script_name, False, duration, f"Exit code {exit_code}: {last_err}")
        except subprocess.TimeoutExpired:
            duration = time.time() - start
            return StepResult(script_name, False, duration, f"Timeout after {timeout}s")
        except Exception as e:
            duration = time.time() - start
            return StepResult(script_name, False, duration, f"Error: {str(e)}")

    def _build_env(self) -> dict:
        """Build env dict for scripts. Override in subclasses."""
        return self.config.to_env_dict()

    def _deploy_steps(self) -> bool:
        """Execute steps with resume capability."""
        steps = self.get_steps()
        force_rerun = getattr(self, "_force_rerun", False)

        if force_rerun:
            self.state.steps_completed = []
            self.state.error = ""

        env = self._build_env()

        for idx, (script, desc) in enumerate(steps, 1):
            if not force_rerun and not self.dry_run and script in self.state.steps_completed:
                print(f"  [{self.name}] Step {idx}/{len(steps)}: {desc}... [SKIP — already completed]")
                continue

            print(f"  [{self.name}] Step {idx}/{len(steps)}: {desc}...")
            result = self.run_script(script, env_extra=env, timeout=1800)
            self.results.append(result)
            if not result.success and not self.dry_run:
                self.state.error = result.message
                self.state.save()
                return False
            if not self.dry_run and script not in self.state.steps_completed:
                self.state.steps_completed.append(script)
                self.state.save()
        return True

    def execute(self, action: str = "deploy") -> bool:
        """Execute a component action with state management."""
        print(f"\n{'=' * 70}")
        print(f"  {self.display_name} ({self.name}) — {action.upper()}")
        print(f"{'=' * 70}")

        if action == "deploy":
            if not self.dry_run:
                deps_ok, dep_msgs = self.check_dependencies()
                if not deps_ok:
                    for msg in dep_msgs:
                        print(f"  BLOCKED: {msg}")
                    return False

                prereqs_ok, prereq_msgs = self.prerequisites()
                if not prereqs_ok:
                    for msg in prereq_msgs:
                        print(f"  PREREQ FAIL: {msg}")
                    return False

            force_rerun = (
                os.environ.get("FORCE_RERUN", "").lower() in ("true", "1", "yes")
                or os.environ.get(f"{self.name.upper()}_FORCE_RERUN", "").lower()
                in ("true", "1", "yes")
            )
            self._force_rerun = force_rerun
            if not self.dry_run:
                self.state.status = "deploying"
                if force_rerun:
                    self.state.steps_completed = []
                self.state.error = ""
                self.state.save()
            try:
                success = self.deploy()
            except KeyboardInterrupt:
                if not self.dry_run:
                    self.state.status = "failed"
                    self.state.error = "Interrupted by user"
                    self.state.save()
                print("  INTERRUPTED: Deployment stopped by user")
                return False
            except Exception as exc:
                logger.exception("Unhandled exception during %s deploy", self.name)
                if not self.dry_run:
                    self.state.status = "failed"
                    self.state.error = f"{type(exc).__name__}: {exc}"
                    self.state.save()
                print(f"  ERROR: {type(exc).__name__}: {exc}")
                return False
            if not self.dry_run:
                self.state.steps_completed = list(dict.fromkeys(self.state.steps_completed))
                self.state.status = "deployed" if success else "failed"
                if success:
                    from datetime import datetime, timezone
                    self.state.deployed_at = datetime.now(timezone.utc).isoformat()
                    self._backup_env()
                self.state.save()
            return success

        elif action == "verify":
            return self.verify()

        elif action == "destroy":
            self.state.status = "destroying"
            self.state.save()
            try:
                success = self.destroy()
            except Exception as exc:
                logger.exception("Unhandled exception during %s destroy", self.name)
                self.state.status = "failed"
                self.state.error = f"{type(exc).__name__}: {exc}"
                self.state.save()
                return False
            if success:
                self.state.status = "not_deployed"
                self.state.error = ""
                self.state.deployed_at = ""
                self.state.steps_completed = []
            else:
                self.state.status = "failed"
                if self.results:
                    failed = [r for r in self.results if not r.success]
                    if failed:
                        self.state.error = failed[-1].message
            self.state.save()
            return success

        else:
            print(f"Unknown action: {action}")
            return False

    def _backup_env(self):
        """Backup .env.local after successful deployment."""
        import shutil
        env_file = ROOT / ".env.local"
        backup_file = ROOT / ".env.local.bak"
        if env_file.exists():
            shutil.copy2(env_file, backup_file)

    def print_results(self):
        if not self.results:
            return
        print(f"\n  {'Step':<40} {'Status':<8} {'Time':<8} Message")
        print(f"  {'-' * 80}")
        for r in self.results:
            icon = "OK" if r.success else "FAIL"
            t = f"{r.duration_s:.1f}s" if r.duration_s else ""
            print(f"  {r.name:<40} [{icon}]  {t:<8} {r.message}")
