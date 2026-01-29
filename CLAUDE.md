# FilterDNS - Project Notes

## Overview
Self-hosted DNS filtering service for ZKM museum. Provides ad/tracker blocking via DNS with per-profile configurations.

## Terminology (Museum-Focused)
- **Profile**: DNS filtering configuration (e.g., "ps5-exhibit-hall-3")
- **Device**: Individual machine using a profile (identified by IP)
- **Preset**: Predefined blocking rule set (e.g., "block-windows-updates")
- **Blocklist**: External domain list source (e.g., "hagezi-multi-normal")

## Project Structure

```
/workspace/
├── filterdns/              # Python backend
│   ├── api/                # REST API routes
│   │   ├── routes.py       # All API endpoints
│   │   └── auth.py         # Password/admin auth decorators
│   ├── blocklist/          # Blocklist management
│   │   ├── engine.py       # In-memory blocklist lookup (O(1))
│   │   ├── parser.py       # Hosts/adblock format parser
│   │   └── fetcher.py      # HTTP fetcher for blocklists
│   ├── db/                 # Database layer
│   │   ├── models.py       # Pydantic models
│   │   ├── queries.py      # Database operations
│   │   └── database.py     # asyncpg connection
│   ├── dns/                # DNS filtering logic
│   │   ├── filter.py       # Core filtering (check blocklists, rules, presets)
│   │   └── resolver.py     # Upstream DNS resolver
│   ├── gateway/            # DNS protocol servers
│   │   ├── doh.py          # DNS-over-HTTPS (RFC 8484)
│   │   ├── dot.py          # DNS-over-TLS (RFC 7858)
│   │   └── dns53.py        # Legacy DNS (port 53)
│   ├── profiles/           # Preset management
│   │   └── loader.py       # Load presets from YAML/DB
│   ├── cache.py            # Profile config caching
│   ├── config.py           # Settings from env vars
│   ├── app.py              # Quart app factory
│   └── __main__.py         # Entry point
├── web/                    # Svelte frontend
│   ├── src/
│   │   ├── routes/         # SvelteKit pages
│   │   │   ├── +page.svelte           # Home (profile access/create)
│   │   │   ├── +layout.svelte         # App layout
│   │   │   ├── profile/[name]/+page.svelte  # Profile settings page
│   │   │   └── admin/+page.svelte     # Admin dashboard
│   │   └── lib/
│   │       ├── api.ts      # API client functions
│   │       └── stores.ts   # Svelte stores (toasts, auth)
│   ├── build/              # Built static files (copied to filterdns/static)
│   └── package.json
├── alembic/                # Database migrations
│   └── versions/
├── tests/                  # pytest tests
├── profiles.yaml           # Built-in presets definition
└── pyproject.toml          # Python dependencies

## Agent Warnings

### Process Management
**NEVER use `pkill python` or `killall python`** - this kills ALL Python processes including the running server, test runners, and other tools. Always use PID-specific killing:
```bash
# Find the specific process first
ps aux | grep "python -m filterdns"

# Kill by specific PID
kill <PID>

# Or use lsof to find process on a port
lsof -i :8080 | grep LISTEN
kill <PID>
```

## Development Commands

### Start Backend (skip blocklist loading for faster startup)
```bash
cd /workspace && SKIP_BLOCKLISTS=1 python -m filterdns
```

### Start with full blocklists
```bash
cd /workspace && python -m filterdns
```

### Frontend Development
```bash
cd /workspace/web
npm run dev          # Dev server with hot reload (port 5173)
npm run build        # Build for production
```

### Deploy Frontend to Backend
```bash
cd /workspace/web && npm run build
rm -rf /workspace/filterdns/static/*
cp -r /workspace/web/build/* /workspace/filterdns/static/
```

### Run Tests
```bash
cd /workspace && pytest
cd /workspace && pytest -v tests/test_api.py  # Specific test file
```

### Database Migrations
```bash
cd /workspace
alembic upgrade head     # Apply migrations
alembic downgrade -1     # Rollback one
alembic revision -m "description"  # Create new migration
```

## API Endpoints

### Public
- `GET /api/blocklists` - List available blocklists
- `GET /api/presets` - List available presets
- `POST /api/profiles` - Create new profile
- `GET /api/profiles/<name>` - Get profile (requires password if set)

### Profile (requires auth if password set)
- `PUT /api/profiles/<name>` - Update profile settings
- `POST /api/profiles/<name>/pause` - Pause filtering
- `POST /api/profiles/<name>/resume` - Resume filtering
- `GET /api/profiles/<name>/logs` - Query logs
- `GET /api/profiles/<name>/rules` - Custom rules
- `POST /api/profiles/<name>/rules` - Add rule
- `GET /api/profiles/<name>/presets` - Enabled presets
- `PUT /api/profiles/<name>/presets` - Set presets

### Admin (requires admin password)
- `POST /api/admin/login` - Admin login
- `GET /api/admin/profiles` - List all profiles
- `GET /api/admin/stats` - Global statistics

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection string
- `ADMIN_PASSWORD` - Admin panel password
- `DOMAIN` - Base domain (e.g., filterdns.zkm.de)
- `SKIP_BLOCKLISTS` - Set to skip blocklist loading on startup

## Key Files to Edit
- **API routes**: `/workspace/filterdns/api/routes.py`
- **Auth logic**: `/workspace/filterdns/api/auth.py`
- **DNS filtering**: `/workspace/filterdns/dns/filter.py`
- **Frontend API**: `/workspace/web/src/lib/api.ts`
- **Profile page**: `/workspace/web/src/routes/profile/[name]/+page.svelte`
- **Home page**: `/workspace/web/src/routes/+page.svelte`
- **Admin page**: `/workspace/web/src/routes/admin/+page.svelte`

## Current Status (2026-01-29)
- All "client" terminology refactored to "profile" in frontend
- Frontend uses /api/profiles endpoints (no backwards compat)
- Frontend route changed from /client/[name] to /profile/[name]
- Password protection on profiles with set/change/remove UI
- Blocklists grouped by category with bulk toggle
- 185 tests passing
