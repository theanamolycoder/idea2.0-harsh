# idea — Setup Instructions

This file contains concise, precise local setup steps for development on macOS/Linux.

## Prerequisites

- Python 3.12 (installed and on PATH)
- Docker & Docker Compose
- Node.js 26 (or use `nvm`)
- `pnpm` (enable via Corepack: `corepack enable && corepack prepare pnpm@latest --activate`)

## Quick local setup (exact commands)

Run these from the repository root.

1. Copy environment file and set DB URL

```bash
cp .env.example .env
# If you run Postgres locally via Docker, set:
# DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/idea
```

2. Start PostgreSQL (Docker Compose)

```bash
docker compose up -d
docker compose ps
```

3. Python: create virtualenv and install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

4. Start the API

```bash
python -m uvicorn app.api.main:app --reload --host 0.0.0.0 --port 8000
```

5. Web: install and start Next.js

```bash
cd app/web
pnpm install
pnpm dev
```

6. Verify services

- Next.js: http://localhost:3000
- FastAPI: http://localhost:8000
- API docs: http://localhost:8000/docs

Notes

- Use `docker compose down -v` to remove DB volume (destructive).
- For an identical Linux dev environment prefer the VS Code Dev Container if available.
