#!/bin/bash
# Publish to GitHub (split repos, excluding dev/ folder)
# Run from repo root on main branch
#
# Uses a 'github-main' branch that mirrors main but excludes dev/

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "=== Publishing to GitHub ==="

# Ensure we're on main
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
    echo "Error: Must be on main branch (currently on $BRANCH)"
    exit 1
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "Error: Uncommitted changes. Commit or stash first."
    exit 1
fi

# 1. Push client subfolder to filterdns-client repo
echo ""
echo ">>> Pushing client/ to github-client..."
git subtree push --prefix=client github-client main

# 2. Update github-main branch (excludes dev/)
echo ""
echo ">>> Updating github-main branch..."

# Create or switch to github-main
if git show-ref --quiet refs/heads/github-main; then
    git checkout github-main
    git merge main -m "Merge main into github-main"
else
    git checkout -b github-main main
fi

# Remove dev/ from github-main if it exists
if [ -d "dev" ]; then
    git rm -rf dev/ 2>/dev/null || true
    if ! git diff-index --quiet HEAD --; then
        git commit -m "Exclude dev/ from public release"
    fi
fi

# Push to GitHub
echo ""
echo ">>> Pushing github-main to github:main..."
git push github github-main:main

# Return to main
git checkout main

echo ""
echo "=== Done ==="
echo "Published to:"
echo "  - https://github.com/zkmkarlsruhe/filterdns"
echo "  - https://github.com/zkmkarlsruhe/filterdns-client"
echo ""
echo "Branches:"
echo "  - main        → git.zkm.de (includes dev/)"
echo "  - github-main → GitHub (excludes dev/)"
