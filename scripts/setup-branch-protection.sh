#!/usr/bin/env bash
# setup-branch-protection.sh — declaratively manage required status checks
# for the main branch via the GitHub API.
#
# Usage:
#   scripts/setup-branch-protection.sh              # apply
#   scripts/setup-branch-protection.sh --dry-run    # preview only
#
# Requires: gh CLI authenticated with admin access to the repo.

set -euo pipefail

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
BRANCH="main"

REQUIRED_CHECKS=(
    "cargo fmt (auto-fix)"
    "clippy + test"
    "cargo audit (RustSec)"
    "cargo-deny check"
    "cargo-machete (unused deps)"
    "changelog entry present"
    "trufflehog (secret scan)"
    "shellcheck"
    "e2e"
)

echo "Repository: $REPO"
echo "Branch:     $BRANCH"
echo ""
echo "Required status checks:"
for check in "${REQUIRED_CHECKS[@]}"; do
    echo "  - $check"
done
echo ""

if [ "$DRY_RUN" = true ]; then
    echo "[dry-run] Would update branch protection with the above checks."
    exit 0
fi

CHECKS_JSON="["
for i in "${!REQUIRED_CHECKS[@]}"; do
    [ "$i" -gt 0 ] && CHECKS_JSON+=","
    CHECKS_JSON+="{\"context\":\"${REQUIRED_CHECKS[$i]}\",\"app_id\":-1}"
done
CHECKS_JSON+="]"

gh api "repos/${REPO}/branches/${BRANCH}/protection" \
    --method PUT \
    --input - <<EOF
{
  "required_status_checks": {
    "strict": true,
    "checks": ${CHECKS_JSON}
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0
  },
  "restrictions": null
}
EOF

echo ""
echo "Branch protection updated successfully."
