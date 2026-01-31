# Release Process

Internal documentation for releasing FilterDNS to GitHub.

## Repository Structure

```
git.zkm.de/filterdns (monorepo)
├── main         ──► Internal releases (includes dev/)
├── dev          ──► Development work
└── github-main  ──► Mirrors main, excludes dev/
                     └──► github.com/zkmkarlsruhe/filterdns

client/ subfolder ──► github.com/zkmkarlsruhe/filterdns-client
```

## Branches

| Branch | Remote | Purpose |
|--------|--------|---------|
| `dev` | origin | Active development |
| `main` | origin | Internal releases (full repo) |
| `github-main` | origin, github | Public releases (excludes dev/) |

## Release Checklist

### 1. Prepare Release
```bash
# Ensure on dev branch with clean working tree
git checkout dev
git status

# Run tests
pytest
cd client && go test ./...

# Build frontend
cd web && npm run build
cp -r build/* ../filterdns/static/
```

### 2. Merge to Main
```bash
git checkout main
git merge dev -m "Release vX.Y.Z"
git push origin main
```

### 3. Publish to GitHub
```bash
./dev/publish-github.sh
```

This script:
1. Pushes `client/` to `github.com/zkmkarlsruhe/filterdns-client` (via subtree)
2. Merges `main` into `github-main` branch
3. Removes `dev/` folder from `github-main`
4. Pushes `github-main` to `github.com/zkmkarlsruhe/filterdns`

### 4. Tag Release (optional)
```bash
# Tag on main (internal)
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# Tag on github-main (public)
git checkout github-main
git tag -a v1.0.0 -m "Release v1.0.0"
git push github v1.0.0
git checkout main
```

## Remotes

```
origin        git@git.zkm.de:MuTech/infra/utilities/filterdns.git
github        git@github.com:zkmkarlsruhe/filterdns.git
github-client git@github.com:zkmkarlsruhe/filterdns-client.git
```

## Files Excluded from GitHub

The `dev/` folder is excluded from GitHub. It contains:
- `RELEASE.md` - This file
- `SETUP.md` - Development setup notes
- Internal documentation and notes

## Quick Reference

```bash
# Daily development
git checkout dev
# ... work ...
git commit && git push origin dev

# Release to GitHub
git checkout main
git merge dev
./dev/publish-github.sh
```
