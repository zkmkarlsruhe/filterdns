# Development Setup

Internal setup notes for FilterDNS development.

## Local Development

### Backend (Python)
```bash
# Install dependencies
poetry install

# Start PostgreSQL
docker run -d --name filterdns-db \
  -e POSTGRES_USER=filterdns \
  -e POSTGRES_PASSWORD=filterdns \
  -e POSTGRES_DB=filterdns \
  -p 5432:5432 \
  postgres:16-alpine

# Run migrations
poetry run alembic upgrade head

# Start server (skip blocklists for speed)
SKIP_BLOCKLISTS=1 poetry run python -m filterdns
```

### Frontend (SvelteKit)
```bash
cd web
npm install
npm run dev        # Dev server on :5173
npm run build      # Build to web/build/
```

### Deploy Frontend to Backend
```bash
cd web && npm run build
rm -rf ../filterdns/static/*
cp -r build/* ../filterdns/static/
```

### Client (Go)
```bash
cd client
go build -o filterdns-client .
./filterdns-client --help
```

## Testing

```bash
# Python tests
pytest
pytest -v tests/test_api.py

# Go tests
cd client && go test ./...
```

## Database

```bash
# Create migration
alembic revision -m "description"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

## Docker

```bash
# Build
docker compose build

# Run
docker compose up -d

# Logs
docker compose logs -f filterdns
```

## Ports

| Service | Port |
|---------|------|
| Web UI / API | 8080 |
| DNS (UDP/TCP) | 53 |
| DoT | 853 |
| Frontend dev | 5173 |
| PostgreSQL | 5432 |
