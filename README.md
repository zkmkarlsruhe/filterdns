# FilterDNS

Self-hosted DNS filtering service for ZKM museum infrastructure.

## Features

- **Per-client DNS filtering** via wildcard subdomain (e.g., `my-devices.filterdns.zkm.de`)
- **Multiple protocols**: DoH (443), DoT (853), Legacy DNS (53)
- **Self-service model**: Users create and manage their own clients
- **Custom rules**: Per-client allow/deny lists
- **Popular blocklists**: Hagezi, StevenBlack, OISD pre-configured
- **Query logging**: View and analyze DNS queries
- **Web UI**: Simple admin interface built with Svelte
- **Pause filtering**: Temporarily disable filtering (5/15/30 min)
- **Link devices**: Associate legacy devices by IP for DNS filtering

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      filterdns.zkm.de                           │
│                                                                 │
│   DNS Query ({client}.filterdns.zkm.de)                         │
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
│   │     - Per-client blocklist filtering                    │   │
│   │     - Custom allow/deny rules                           │   │
│   │     - Query logging                                     │   │
│   └────────────────────┬────────────────────────────────────┘   │
│                        │                                        │
│                        ▼                                        │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │     PostgreSQL + Web UI (Svelte)                        │   │
│   └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Using Docker Compose

```bash
# Copy example environment
cp .env.example .env

# Edit .env with your settings
nano .env

# Start services
docker compose up -d

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

# Start the server
poetry run python -m filterdns

# In another terminal, build the frontend
cd web && npm install && npm run dev
```

## Client Identification

| Protocol | Port | How Client is Identified |
|----------|------|--------------------------|
| **DoH** | 443 | Subdomain: `my-devices.filterdns.zkm.de/dns-query` |
| **DoT** | 853 | SNI: `my-devices.filterdns.zkm.de` |
| **Legacy DNS** | 53 | Source IP lookup in `linked_devices` table |

## Usage

### 1. Create a Client

Visit the web UI at `http://localhost:8080` and click "Create New Client".

Or via API:
```bash
curl -X POST http://localhost:8080/api/clients \
  -H 'Content-Type: application/json' \
  -d '{"name": "my-devices", "password": "optional"}'
```

### 2. Configure Your Device

**For DoH (recommended):**
- URL: `https://my-devices.filterdns.zkm.de/dns-query`
- Works in: Firefox, Chrome, iOS, Android

**For DoT:**
- Hostname: `my-devices.filterdns.zkm.de`
- Port: 853
- Works in: Android Private DNS, iOS (with profile)

**For Legacy DNS:**
1. Link your device's IP address to your client in the web UI
2. Point your device to the FilterDNS server IP on port 53

### 3. Manage Blocklists

In the web UI, enable/disable blocklists for your client:
- Hagezi Multi Normal (ads, tracking)
- Hagezi Threat Intelligence (malware, phishing)
- StevenBlack Unified
- OISD Small/Big

### 4. Custom Rules

Add allow rules to whitelist specific domains:
```bash
curl -X POST http://localhost:8080/api/clients/my-devices/rules \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com", "rule_type": "allow"}'
```

Add deny rules to block specific domains:
```bash
curl -X POST http://localhost:8080/api/clients/my-devices/rules \
  -H 'Content-Type: application/json' \
  -d '{"domain": "unwanted.com", "rule_type": "deny"}'
```

## API Endpoints

### Public
- `GET /api/blocklists` - List available blocklists
- `POST /api/clients` - Create new client

### Client (per-client, optional auth)
- `GET /api/clients/{name}` - Get client config
- `PUT /api/clients/{name}` - Update client
- `DELETE /api/clients/{name}` - Delete client
- `POST /api/clients/{name}/pause` - Pause filtering
- `POST /api/clients/{name}/resume` - Resume filtering
- `GET /api/clients/{name}/logs` - Query logs
- `GET /api/clients/{name}/stats` - Statistics
- `GET/POST/DELETE /api/clients/{name}/rules` - Custom rules
- `GET/POST/DELETE /api/clients/{name}/devices` - Linked devices

### Admin
- `POST /api/admin/login` - Admin login
- `GET /api/admin/clients` - List all clients
- `GET /api/admin/stats` - Global statistics
- `POST /api/admin/blocklists` - Add blocklist

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://filterdns:filterdns@localhost:5432/filterdns` | PostgreSQL connection |
| `FILTERDNS_DOMAIN` | `filterdns.zkm.de` | Base domain for DNS |
| `FILTERDNS_ADMIN_PASSWORD` | `changeme` | Admin panel password |
| `FILTERDNS_UPSTREAM_DNS` | `1.1.1.1,8.8.8.8` | Upstream DNS servers |
| `FILTERDNS_TLS_CERT` | - | TLS certificate path |
| `FILTERDNS_TLS_KEY` | - | TLS private key path |
| `FILTERDNS_PTR_SERVER` | - | PTR lookup server |
| `FILTERDNS_LOG_QUERIES` | `true` | Enable query logging |
| `FILTERDNS_DEBUG` | `false` | Debug mode |

## TLS Certificates

For DoH and DoT, you need a wildcard certificate for `*.filterdns.zkm.de`.

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
├── filterdns/           # Python package
│   ├── api/             # REST API routes
│   ├── blocklist/       # Blocklist engine
│   ├── db/              # Database layer
│   ├── dns/             # DNS filtering
│   ├── gateway/         # DNS servers (DoH/DoT/DNS53)
│   ├── app.py           # Quart app factory
│   └── config.py        # Configuration
├── web/                 # Svelte frontend
├── alembic/             # Database migrations
├── tests/               # Test suite
├── docker-compose.yml   # Production setup
└── Dockerfile           # Container image
```

## License

Internal use only - ZKM Karlsruhe
