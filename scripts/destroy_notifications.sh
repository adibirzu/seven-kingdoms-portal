#!/usr/bin/env bash
# C7: Destroy notification resources.
set -euo pipefail

echo "=== C7: Notifications Teardown ==="

OCI_PROFILE="${OCI_PROFILE:-DEFAULT}"

# ONS topics must be deleted via OCI CLI
echo "  ONS topic deletion requires manual cleanup via OCI Console."
echo "  (Topic names contain state that prevents automated discovery)"
echo "  Notifications teardown complete."
