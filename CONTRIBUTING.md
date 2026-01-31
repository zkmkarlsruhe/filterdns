# Contributing to FilterDNS

Thank you for your interest in contributing to FilterDNS! This document provides guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 16+
- Poetry (Python package manager)

### Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/filterdns.git
   cd filterdns
   ```

2. Install Python dependencies:
   ```bash
   poetry install
   ```

3. Start PostgreSQL:
   ```bash
   docker run -d --name filterdns-db \
     -e POSTGRES_USER=filterdns \
     -e POSTGRES_PASSWORD=filterdns \
     -e POSTGRES_DB=filterdns \
     -p 5432:5432 \
     postgres:16-alpine
   ```

4. Run migrations:
   ```bash
   poetry run alembic upgrade head
   ```

5. Start the backend (skip blocklists for faster startup):
   ```bash
   SKIP_BLOCKLISTS=1 poetry run python -m filterdns
   ```

6. In another terminal, start the frontend:
   ```bash
   cd web
   npm install
   npm run dev
   ```

## Making Changes

### Code Style

- **Python**: We use `black` for formatting and `ruff` for linting
  ```bash
  poetry run black filterdns tests
  poetry run ruff check filterdns tests
  ```

- **TypeScript/Svelte**: We use Prettier and ESLint
  ```bash
  cd web && npm run lint && npm run format
  ```

### Running Tests

```bash
# Python tests
poetry run pytest

# With coverage
poetry run pytest --cov=filterdns

# Specific test file
poetry run pytest tests/test_blocklist.py -v
```

### Database Migrations

If you change database models:

```bash
# Create a new migration
poetry run alembic revision -m "description of change"

# Apply migrations
poetry run alembic upgrade head

# Rollback one migration
poetry run alembic downgrade -1
```

## Pull Request Process

1. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and commit with clear messages:
   ```bash
   git commit -m "Add feature: description of what it does"
   ```

3. **Run tests** to ensure nothing is broken:
   ```bash
   poetry run pytest
   ```

4. **Push your branch** and create a pull request:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Describe your changes** in the PR description:
   - What does this PR do?
   - Why is this change needed?
   - How was it tested?

## Project Structure

```
filterdns/
├── filterdns/           # Python backend
│   ├── api/             # REST API (Quart blueprints)
│   ├── blocklist/       # Blocklist parsing and engine
│   ├── db/              # Database models and queries
│   ├── dns/             # DNS filtering logic
│   ├── gateway/         # DNS protocol servers
│   └── profiles/        # Preset management
├── web/                 # SvelteKit frontend
│   ├── src/routes/      # Page components
│   └── src/lib/         # Shared components and utilities
├── alembic/             # Database migrations
└── tests/               # Python test suite
```

## Reporting Issues

When reporting bugs, please include:

- Your environment (OS, Python version, browser)
- Steps to reproduce the issue
- Expected vs actual behavior
- Relevant logs or error messages

## Questions?

Feel free to open an issue for questions or discussions about the project.
