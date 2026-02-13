<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zkmkarlsruhe/zkm-open-source/main/assets/zkm-logo-light.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/zkmkarlsruhe/zkm-open-source/main/assets/zkm-logo.svg">
    <img alt="ZKM" src="https://raw.githubusercontent.com/zkmkarlsruhe/zkm-open-source/main/assets/zkm-logo.svg" width="120">
  </picture>
</p>

# FilterDNS

[![ZKM](https://img.shields.io/badge/ZKM-Karlsruhe-blue)](https://zkm.de)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Self-hosted DNS filtering service with per-profile configuration. Block ads, trackers, and malware at the DNS level with customizable profiles for different devices or use cases.

## Features

- **Per-profile DNS filtering** via wildcard subdomain (e.g., `my-devices.filterdns.example.com`)
- **Multiple protocols**: DoH (443), DoT (853), Legacy DNS (53)
- **Self-service model**: Users create and manage their own profiles
- **Custom rules**: Per-profile allow/deny lists
- **Presets**: Predefined blocking rule sets (gaming, social media, etc.)
- **Popular blocklists**: Hagezi, StevenBlack, OISD pre-configured
- **Query logging**: View and analyze DNS queries with statistics
- **Web UI**: Modern admin interface built with SvelteKit
- **Pause filtering**: Temporarily disable filtering (5/15/30/60 min)
- **Link devices**: Associate legacy devices by IP for DNS filtering
- **Maintenance mode**: Block all DNS except allowed domains

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   filterdns.example.com                         │
│                                                                 │
│   DNS Query ({profile}.filterdns.example.com)                   │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │     DNS Gateway (Python)                                │   │
│   │     - DoH on 443 (Quart/Hypercorn)                      │   │
│   │     - DoT on 853 (asyncio TLS)                          │   │
│   │     - Legacy DNS on 53 (UDP/TCP)                        │   │
│   └────────────────────┬────────────────────────────────────┘   │
│                        │                                        │
│                        ▼                                        │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │     DNS Filter Engine (dnspython)                       │   │
│   │     - Per-profile blocklist filtering                   │   │
│   │     - Custom allow/deny rules                           │   │
│   │     - Preset rule sets                                  │   │
│   │     - Query logging                                     │   │
│   └────────────────────┬────────────────────────────────────┘   │
│                        │                                        │
│                        ▼                                        │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │     PostgreSQL + Web UI (SvelteKit)                     │   │
│   └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Using Docker Compose

```bash
# Clone the repository
git clone https://github.com/zkmkarlsruhe/filterdns.git
cd filterdns

# Copy example environment
cp .env.example .env

# Edit .env with your settings
nano .env

# Start services
docker compose up -d

# Run database migrations
docker compose exec filterdns alembic upgrade head

# Access the web UI
open http://localhost:8080
```

### Local Development

```bash
# Install Python dependencies
poetry install

# Start PostgreSQL (or use docker)
docker run -d --name filterdns-db \
  -e POSTGRES_USER=filterdns \
  -e POSTGRES_PASSWORD=filterdns \
  -e POSTGRES_DB=filterdns \
  -p 5432:5432 \
  postgres:16-alpine

# Run migrations
poetry run alembic upgrade head

# Start the server (skip blocklist loading for faster startup)
SKIP_BLOCKLISTS=1 poetry run python -m filterdns

# In another terminal, build the frontend
cd web && npm install && npm run dev
```

## Profile Identification

| Protocol | Port | How Profile is Identified |
|----------|------|---------------------------|
| **DoH** | 443 | Subdomain: `my-profile.filterdns.example.com/dns-query` |
| **DoT** | 853 | SNI: `my-profile.filterdns.example.com` |
| **Legacy DNS** | 53 | Source IP lookup in `devices` table |

## Usage

### 1. Create a Profile

Visit the web UI at `http://localhost:8080` and click "Create New Profile".

Or via API:
```bash
curl -X POST http://localhost:8080/api/profiles \
  -H 'Content-Type: application/json' \
  -d '{"name": "my-devices", "password": "optional"}'
```

### 2. Configure Your Device

**For DoH (recommended):**
- URL: `https://my-devices.filterdns.example.com/dns-query`
- Works in: Firefox, Chrome, iOS, Android

**For DoT:**
- Hostname: `my-devices.filterdns.example.com`
- Port: 853
- Works in: Android Private DNS, iOS (with profile)

**For Legacy DNS:**
1. Link your device's IP address to your profile in the web UI
2. Point your device to the FilterDNS server IP on port 53

### 3. Manage Blocklists

In the web UI, enable/disable blocklists for your profile:
- Hagezi Multi Normal (ads, tracking)
- Hagezi Threat Intelligence (malware, phishing)
- StevenBlack Unified
- OISD Small/Big

### 4. Custom Rules

Add allow rules to whitelist specific domains:
```bash
curl -X POST http://localhost:8080/api/profiles/my-devices/rules \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com", "rule_type": "allow"}'
```

Add deny rules to block specific domains:
```bash
curl -X POST http://localhost:8080/api/profiles/my-devices/rules \
  -H 'Content-Type: application/json' \
  -d '{"domain": "unwanted.com", "rule_type": "deny"}'
```

## API Endpoints

### Public
- `GET /api/blocklists` - List available blocklists
- `GET /api/presets` - List available presets
- `POST /api/profiles` - Create new profile

### Profile (per-profile, optional auth)
- `GET /api/profiles/{name}` - Get profile config
- `PUT /api/profiles/{name}` - Update profile
- `DELETE /api/profiles/{name}` - Delete profile
- `POST /api/profiles/{name}/pause` - Pause filtering
- `POST /api/profiles/{name}/resume` - Resume filtering
- `GET /api/profiles/{name}/logs` - Query logs
- `GET /api/profiles/{name}/stats` - Statistics
- `GET/POST/DELETE /api/profiles/{name}/rules` - Custom rules
- `GET/PUT /api/profiles/{name}/presets` - Enabled presets
- `GET/POST/DELETE /api/profiles/{name}/devices` - Linked devices

### Admin
- `POST /api/admin/login` - Admin login
- `GET /api/admin/profiles` - List all profiles
- `GET /api/admin/stats` - Global statistics
- `POST /api/admin/blocklists` - Add blocklist
- `POST /api/admin/presets` - Create custom preset

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://...` | PostgreSQL connection string |
| `FILTERDNS_DOMAIN` | `filterdns.example.com` | Base domain for DNS |
| `FILTERDNS_ADMIN_PASSWORD` | (generated) | Admin panel password |
| `FILTERDNS_UPSTREAM_DNS` | `1.1.1.1,8.8.8.8` | Upstream DNS servers |
| `FILTERDNS_TLS_CERT` | - | TLS certificate path |
| `FILTERDNS_TLS_KEY` | - | TLS private key path |
| `FILTERDNS_PTR_SERVER` | - | PTR lookup server for reverse DNS |
| `FILTERDNS_LOG_QUERIES` | `true` | Enable query logging |
| `FILTERDNS_DEBUG` | `false` | Debug mode |
| `SKIP_BLOCKLISTS` | - | Skip blocklist loading on startup |

## TLS Certificates

For DoH and DoT, you need a wildcard certificate for `*.yourdomain.com`.

Place certificates in `./certs/`:
- `cert.pem` - Certificate chain
- `key.pem` - Private key

## Testing

```bash
# Run unit tests
poetry run pytest

# Test DNS resolution (legacy)
dig @localhost -p 53 google.com

# Test blocking
dig @localhost -p 53 doubleclick.net  # Should return NXDOMAIN

# Test DoH with curl
curl -H 'content-type: application/dns-message' \
  'http://localhost:8080/dns-query?dns=AAABAAABAAAAAAAAA3d3dwZnb29nbGUDY29tAAABAAE'

# Test JSON API
curl 'http://localhost:8080/resolve?name=google.com'
```

## Project Structure

```
filterdns/
├── filterdns/           # Python backend
│   ├── api/             # REST API routes
│   ├── blocklist/       # Blocklist engine
│   ├── db/              # Database layer (asyncpg)
│   ├── dns/             # DNS filtering logic
│   ├── gateway/         # DNS servers (DoH/DoT/DNS53)
│   ├── profiles/        # Preset management
│   ├── app.py           # Quart app factory
│   └── config.py        # Configuration
├── web/                 # SvelteKit frontend
├── alembic/             # Database migrations
├── tests/               # Test suite
├── docker-compose.yml   # Production setup
└── Dockerfile           # Container image
```

## License

MIT License - see [LICENSE](LICENSE) for details.

---

Part of [ZKM Open Source](https://github.com/zkmkarlsruhe)

Copyright (c) 2026 [ZKM | Center for Art and Media Karlsruhe](https://zkm.de)
