#!/usr/bin/env python3
"""
Seven Kingdoms Portal — Deployment Orchestrator.

Deploys, verifies, and tears down the complete security testing platform.
Components are deployed respecting the dependency graph:

  C1 (Infrastructure) ─┬→ C2 (GOADv3 AD Lab) [optional]
                        ├→ C3 (Observability) → C7 (Notifications) [optional]
                        └→ C4 (Application) → C5 (WAF) [optional]
                                             → C6 (DNS) [optional]

Usage:
  python deploy.py --component c1                 # Deploy one component
  python deploy.py --component c1,c3              # Deploy multiple
  python deploy.py --component all                # Full deployment (dep order)
  python deploy.py --verify all                   # Health-check all components
  python deploy.py --status                       # Show status of all
  python deploy.py --destroy                      # Tear down everything
  python deploy.py --component c4 --destroy       # Tear down only C4
  python deploy.py --component all --dry-run      # Preview without executing
  python deploy.py --component c4 --app-mode oke  # Deploy app in OKE mode
  python deploy.py --list-steps c4                # List steps for a component
"""

import argparse
import logging
import os
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path for shared.* imports
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.config import Config, load_env
from components import COMPONENTS
from components.base import ComponentState, STATE_DIR

logger = logging.getLogger("deploy")

# Dependency graph: component → list of required predecessors
DEPENDENCY_GRAPH = {
    "c1": [],
    "c2": ["c1"],
    "c3": ["c1"],
    "c4": ["c1"],
    "c5": ["c4"],
    "c6": ["c4"],
    "c7": ["c3"],
}


def topological_sort(components: list[str]) -> list[str]:
    """Sort components respecting dependency order."""
    # Build subgraph of requested components + their transitive dependencies
    needed = set()

    def add_deps(c):
        if c in needed:
            return
        needed.add(c)
        for dep in DEPENDENCY_GRAPH.get(c, []):
            add_deps(dep)

    for c in components:
        add_deps(c)

    # Kahn's algorithm
    in_degree = {c: 0 for c in needed}
    for c in needed:
        for dep in DEPENDENCY_GRAPH.get(c, []):
            if dep in needed:
                in_degree[c] = in_degree.get(c, 0)  # dep contributes to c's in-degree
    # Recount properly
    in_degree = {c: 0 for c in needed}
    adj = {c: [] for c in needed}
    for c in needed:
        for dep in DEPENDENCY_GRAPH.get(c, []):
            if dep in needed:
                adj[dep].append(c)
                in_degree[c] += 1

    queue = sorted([c for c in needed if in_degree[c] == 0])
    result = []
    while queue:
        node = queue.pop(0)
        result.append(node)
        for neighbor in sorted(adj.get(node, [])):
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)
                queue.sort()

    return result


def print_status():
    """Print status of all components."""
    print(f"\n{'Component':<8} {'Name':<40} {'Status':<14} {'Deployed At':<26} Steps")
    print("-" * 110)
    for cid in sorted(COMPONENTS.keys(), key=lambda x: (x.replace("c", "").zfill(3))):
        cls = COMPONENTS[cid]
        state = ComponentState.load(cid)
        status_color = {
            "deployed": "\033[92m",    # green
            "failed": "\033[91m",      # red
            "deploying": "\033[93m",   # yellow
            "destroying": "\033[93m",
            "not_deployed": "\033[90m",  # gray
        }.get(state.status, "")
        reset = "\033[0m"

        steps_info = ""
        if state.steps_completed:
            steps_info = f"{len(state.steps_completed)} completed"

        print(f"  {cid:<6} {cls.display_name:<40} "
              f"{status_color}{state.status:<14}{reset} "
              f"{state.deployed_at[:25]:<26} {steps_info}")
        if state.error:
            print(f"         ERROR: {state.error[:80]}")
    print()


def print_dependency_graph():
    """Print the dependency graph visually."""
    print("\nDependency Graph:")
    print("  C1 (Infrastructure)")
    print("  ├── C2 (GOADv3 AD Lab) [optional]")
    print("  ├── C3 (Observability)")
    print("  │   └── C7 (Notifications) [optional]")
    print("  └── C4 (Application)")
    print("      ├── C5 (WAF) [optional]")
    print("      └── C6 (DNS) [optional]")
    print()


def list_steps(component_id: str, config: Config):
    """List deployment steps for a component."""
    if component_id not in COMPONENTS:
        print(f"Unknown component: {component_id}")
        return
    deployer = COMPONENTS[component_id](config, dry_run=True)
    steps = deployer.get_steps()
    if not steps:
        print(f"  {component_id}: No steps defined (deploy() is monolithic)")
        return
    print(f"\n  {deployer.display_name} ({component_id}) — {len(steps)} steps:")
    for idx, (script, desc) in enumerate(steps, 1):
        state = ComponentState.load(component_id)
        done = "done" if script in state.steps_completed else "    "
        print(f"    {idx}. [{done}] {desc} ({script})")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Seven Kingdoms Portal — Deployment Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python deploy.py --component all                # Deploy everything
  python deploy.py --component c4 --app-mode oke  # Deploy app on OKE
  python deploy.py --component c2                  # Deploy GOAD only
  python deploy.py --verify all                    # Verify all components
  python deploy.py --status                        # Show deployment status
  python deploy.py --destroy                       # Tear down everything
  python deploy.py --component all --dry-run       # Preview deployment
        """,
    )
    parser.add_argument(
        "--component", "-c",
        help="Component(s) to deploy: c1,c2,... or 'all'",
    )
    parser.add_argument(
        "--verify", "-v",
        nargs="?", const="all",
        help="Verify component(s): c1,c2,... or 'all'",
    )
    parser.add_argument(
        "--status", "-s",
        action="store_true",
        help="Show deployment status of all components",
    )
    parser.add_argument(
        "--destroy", "-d",
        action="store_true",
        help="Destroy deployed resources (use with --component for selective teardown)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview actions without executing",
    )
    parser.add_argument(
        "--app-mode",
        choices=["vm", "docker", "oke"],
        help="Override APP_DEPLOY_MODE for C4 deployment",
    )
    parser.add_argument(
        "--oci-profile",
        help="OCI config profile name (default: from .env.local or DEFAULT)",
    )
    parser.add_argument(
        "--list-steps",
        metavar="COMPONENT",
        help="List deployment steps for a component",
    )
    parser.add_argument(
        "--graph",
        action="store_true",
        help="Print the component dependency graph",
    )
    parser.add_argument(
        "--step",
        type=int,
        help="Run only a specific step number (use with --component for single component)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Override env vars from CLI flags before loading config
    if args.app_mode:
        os.environ["APP_DEPLOY_MODE"] = args.app_mode
    if args.oci_profile:
        os.environ["OCI_PROFILE"] = args.oci_profile

    # Load config
    config = Config.from_env(force_refresh=True)

    # Handle --graph
    if args.graph:
        print_dependency_graph()
        return

    # Handle --status
    if args.status:
        print_status()
        return

    # Handle --list-steps
    if args.list_steps:
        list_steps(args.list_steps, config)
        return

    # Handle --verify
    if args.verify:
        components = sorted(COMPONENTS.keys()) if args.verify == "all" else args.verify.split(",")
        all_ok = True
        for cid in components:
            cid = cid.strip()
            if cid not in COMPONENTS:
                print(f"Unknown component: {cid}")
                all_ok = False
                continue
            deployer = COMPONENTS[cid](config)
            ok = deployer.execute("verify")
            if not ok:
                all_ok = False
        sys.exit(0 if all_ok else 1)

    # Handle --destroy without --component (destroy all in reverse order)
    if args.destroy and not args.component:
        components = list(reversed(topological_sort(list(COMPONENTS.keys()))))
        print(f"\nDestroying all components in reverse dependency order: {', '.join(components)}")
        if not args.dry_run:
            confirm = input("  Are you sure? (yes/no): ").strip().lower()
            if confirm != "yes":
                print("  Aborted.")
                return
        all_ok = True
        for cid in components:
            state = ComponentState.load(cid)
            if state.status == "not_deployed":
                print(f"  {cid}: already not_deployed, skipping")
                continue
            deployer = COMPONENTS[cid](config, dry_run=args.dry_run)
            ok = deployer.execute("destroy")
            if not ok:
                all_ok = False
        sys.exit(0 if all_ok else 1)

    # Handle --component (deploy or targeted destroy)
    if args.component:
        if args.component == "all":
            # Deploy all components that are active (respect toggles)
            components = list(COMPONENTS.keys())
        else:
            components = [c.strip() for c in args.component.split(",")]

        # Validate
        for cid in components:
            if cid not in COMPONENTS:
                print(f"Unknown component: {cid}")
                sys.exit(1)

        action = "destroy" if args.destroy else "deploy"
        if action == "destroy":
            ordered = list(reversed(topological_sort(components)))
        else:
            ordered = topological_sort(components)

        # For "all" deploy, only include components in the ordered set
        # that are either explicitly requested or are dependencies
        print(f"\n{'[DRY-RUN] ' if args.dry_run else ''}"
              f"{action.upper()} order: {' → '.join(ordered)}")

        all_ok = True
        start_time = time.time()
        for cid in ordered:
            deployer = COMPONENTS[cid](config, dry_run=args.dry_run)

            # Handle --step (single step execution)
            if args.step and len(components) == 1:
                steps = deployer.get_steps()
                if not steps:
                    print(f"  {cid}: No steps defined")
                    sys.exit(1)
                if args.step < 1 or args.step > len(steps):
                    print(f"  {cid}: Step {args.step} out of range (1-{len(steps)})")
                    sys.exit(1)
                print(f"\n  Running step {args.step} only: {steps[args.step - 1][1]}")
                deployer.state.status = "deploying"
                deployer.state.save()
                result = deployer.run_script(
                    steps[args.step - 1][0],
                    env_extra=deployer._build_env(),
                    timeout=1800,
                )
                if result.success:
                    if steps[args.step - 1][0] not in deployer.state.steps_completed:
                        deployer.state.steps_completed.append(steps[args.step - 1][0])
                    deployer.state.save()
                    print(f"  Step {args.step}: OK ({result.duration_s:.1f}s)")
                else:
                    deployer.state.error = result.message
                    deployer.state.save()
                    print(f"  Step {args.step}: FAILED — {result.message}")
                    sys.exit(1)
                sys.exit(0)

            ok = deployer.execute(action)
            deployer.print_results()

            if not ok:
                # Optional components don't block the pipeline
                cls = COMPONENTS[cid]
                if cls.optional:
                    print(f"  WARNING: Optional component {cid} failed, continuing...")
                else:
                    all_ok = False
                    if action == "deploy":
                        print(f"\n  STOPPED: {cid} failed. Fix and re-run to resume.")
                        break

            # Refresh config after each component (scripts may update .env.local)
            config = Config.from_env(force_refresh=True)

        elapsed = time.time() - start_time
        print(f"\n{'=' * 70}")
        status = "COMPLETED" if all_ok else "FAILED"
        print(f"  {action.upper()} {status} in {elapsed:.0f}s")
        print(f"{'=' * 70}\n")
        sys.exit(0 if all_ok else 1)

    # No action specified — show help
    parser.print_help()


if __name__ == "__main__":
    main()
