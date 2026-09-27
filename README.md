# SecureAuth API

A production-style authentication API built with **FastAPI** and **PostgreSQL**: JWT access tokens, refresh-token rotation, role-based access control, and rate limiting - with a pytest suite and Docker setup.

## Features

- **Register / login** with bcrypt password hashing
- **JWT access tokens** (short-lived, 15 min default)
- **Refresh tokens with rotation** - opaque, stored hashed (SHA-256), each usable exactly once; logout revokes them
- **Role-based access control** - `user` and `admin` roles, enforced by a dependency (`require_role`)
- **Rate limiting** - IP-based via slowapi; strict limits on `/auth/register` and `/auth/login`
- **Health check** at `/health`
- **Tests**: 12 pytest cases covering auth, rotation, revocation, RBAC and rate limiting

## Tech stack

FastAPI · SQLAlchemy 2 · PostgreSQL (SQLite for local dev/tests) · PyJWT · passlib (bcrypt) · slowapi · Docker & docker-compose · pytest

## Quick start (local, SQLite)

```bash
git clone https://github.com/Cybersec-001/secureauth-api.git
cd secureauth-api
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                  # set SECRET_KEY
uvicorn app.main:app --reload
```

API docs (Swagger UI): http://127.0.0.1:8000/docs

## Run with Docker (PostgreSQL included)

```bash
export SECRET_KEY=$(openssl rand -hex 32)   # or put it in a .env file
docker compose up --build
```

The API listens on http://127.0.0.1:8000 and uses the bundled PostgreSQL 16 service.

## API overview

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/auth/register` | - | Create an account (5/min) |
| POST | `/auth/login` | - | Get an access + refresh token pair (5/min) |
| POST | `/auth/refresh` | - | Rotate a refresh token, get a new pair |
| POST | `/auth/logout` | - | Revoke a refresh token |
| GET | `/auth/me` | Bearer | Current user profile |
| GET | `/users` | Bearer (admin) | List all users |
| PATCH | `/users/{id}/role` | Bearer (admin) | Change a user's role |

Example:

```bash
curl -X POST http://127.0.0.1:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email": "demo@example.com", "password": "strongpass123"}'
```

## How refresh-token rotation works

1. Login issues an access token (JWT, 15 min) and a refresh token (opaque, 7 days).
2. Only the SHA-256 hash of the refresh token is stored - a database leak does not expose usable tokens.
3. Calling `/auth/refresh` revokes the presented token and issues a new pair. A reused old token is rejected, which also flags token theft.
4. `/auth/logout` revokes the refresh token; the access token simply expires within minutes.

## Tests

```bash
pip install -r requirements.txt
pytest
```

12 tests: registration validation, login, token flow, rotation, revocation, RBAC (user blocked from admin routes, admin allowed), and the login rate limit (6th request in a minute -> 429).

## Project structure

```
app/
  main.py       App factory, rate-limit handler, /health
  config.py     Environment-driven settings (pydantic-settings)
  database.py   Engine, session, Base, get_db dependency
  models.py     User and RefreshToken tables
  schemas.py    Pydantic request/response models
  security.py   Password hashing, JWT issue/verify, token hashing
  ratelimit.py  Shared slowapi limiter
  deps.py       get_current_user + require_role dependencies
  auth.py       /auth routes (register, login, refresh, logout, me)
  users.py      /users admin routes
tests/
  conftest.py   Test app + SQLite fixtures
  test_api.py   12 API tests
Dockerfile, docker-compose.yml, .env.example
```

## Security notes

- Passwords are bcrypt-hashed; refresh tokens are stored as SHA-256 hashes only.
- Access tokens expire in minutes; refresh tokens are single-use (rotation).
- `SECRET_KEY` must be a long random value in production (see `.env.example`). The bundled default is for local development only.
- Rate limiting uses in-memory storage; use Redis as the slowapi backend for multi-instance deployments.
