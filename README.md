# CodeSentinel

A locally runnable, evidence-based API security scanner for authorized testing. It parses OpenAPI 3.x documents, discovers operations, runs conservative read-only checks, persists scan state and results, and produces JSON or escaped HTML reports. It is a portfolio/reference project, not a production-ready security product.

## Features and limitations

- OpenAPI 3.0/3.1 JSON and YAML parsing, validation, security inheritance and operation overrides.
- JWT access tokens with Argon2 password hashing, owner-scoped resources, PostgreSQL persistence, Redis/RQ background work.
- Bounded GET/HEAD/OPTIONS checks for response headers, CORS, diagnostic leakage, and a potential authentication mismatch.
- JSON/HTML report output; response bodies and credentials are not persisted.
- Docker Compose services for API, PostgreSQL, Redis, worker, and synthetic local test API.

Not implemented: arbitrary POST/PUT/PATCH/DELETE active tests, credentialed authorization/BOLA test fixtures, automated rate-limit probes, robust parameter generation, and complete cancellation of an in-flight request. The scanner never proves absence of vulnerabilities. A declared operation with required path parameters is not supplied generated values; such behavior is inconclusive/skipped. Findings require human validation.

## Architecture

```text
Client -> FastAPI routes -> SQLAlchemy/PostgreSQL
                    |              ^
                    +-> Redis queue -> RQ worker -> target API
                                           |          |
                                           +-- findings/reports persisted in PostgreSQL
```

The scanner modules are HTTP-independent except for `engine.py`, which owns target validation, bounded requests, and check dispatch. The API only validates submissions and enqueues work. PostgreSQL is the durable source of truth; Redis is coordination only.

## Stack

Python 3.12, FastAPI/Pydantic for validated HTTP APIs, SQLAlchemy/Alembic/psycopg for relational persistence and migrations, Redis/RQ for jobs, httpx for HTTP, PyYAML plus `openapi-spec-validator` for specifications, PyJWT and pwdlib/Argon2 for authentication, and pytest/Ruff/GitHub Actions for quality. Essential functionality requires no paid API or external AI.

## Prerequisites and setup

Install Docker Desktop with Compose v2 on Windows, then in PowerShell:

```powershell
cd codesentinel
Copy-Item .env.example .env
# Edit .env: set a long random JWT_SECRET. For local Compose, ALLOW_PRIVATE_TARGETS=true
# is needed to reach the explicitly allowlisted isolated test-api container.
docker compose up --build -d
```

The API is published only on `127.0.0.1:8000`. The synthetic `test-api`, Redis, and PostgreSQL have no host-published ports. `compose.yaml` contains a clearly labeled local-only fallback database password; set `POSTGRES_PASSWORD` in your shell and ensure `.env`'s `DATABASE_URL` is not used for DB credentials (Compose overrides it for API/worker). Example:

```powershell
$env:POSTGRES_PASSWORD = "replace-with-a-local-random-password"
# Ensure .env JWT_SECRET is also random and private.
docker compose up --build -d
```

The API service runs `alembic upgrade head` before Uvicorn. To run migrations explicitly:

```powershell
docker compose exec api alembic upgrade head
```

Follow logs and stop cleanly:

```powershell
docker compose logs -f api worker
docker compose down
# Add -v only if you intentionally want to delete persistent database/Redis data.
```

Health endpoints: `GET http://localhost:8000/health/live`; readiness checks PostgreSQL and Redis at `/health/ready`.

### Local Python development

Python 3.12 is required. Use a virtual environment and configure PostgreSQL/Redis yourself or use Compose for those services. Copy `.env.example` to `.env` and edit `DATABASE_URL`, `REDIS_URL`, `JWT_SECRET`, and authorized allowlist. Then:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
alembic upgrade head
uvicorn app.main:app --reload
```

Start the queue worker in a second shell: `python -m app.run_worker`.

## API workflow

Registration requires a password of at least 12 characters. Login returns a bearer token; copy the token locally and do not commit it.

Swagger UI at `/docs` documents protected routes as HTTP Bearer authentication. First call the JSON `POST /auth/login` endpoint (or use the PowerShell example below) and copy the returned `access_token`. Click **Authorize** in Swagger UI and enter that token; Swagger sends it as `Authorization: Bearer <token>`. The login endpoint remains a JSON request and is intentionally not represented as an OAuth2 password grant.

```powershell
$base = "http://localhost:8000"
$registration = @{ email = "analyst@example.com"; password = "Use-a-long-local-passphrase-9!" } | ConvertTo-Json
Invoke-RestMethod -Method Post "$base/auth/register" -ContentType "application/json" -Body $registration
$login = @{ email = "analyst@example.com"; password = "Use-a-long-local-passphrase-9!" } | ConvertTo-Json
$token = (Invoke-RestMethod -Method Post "$base/auth/login" -ContentType "application/json" -Body $login).access_token
$headers = @{ Authorization = "Bearer $token" }
Invoke-RestMethod "$base/auth/me" -Headers $headers
```

Use the included OpenAPI fixture for a lab scan. The `target` host must match `ALLOWED_TARGET_HOSTS`; in Compose use `http://test-api:9000` (container service DNS, not localhost).

```powershell
$spec = Get-Content .\tests\fixtures\demo_openapi.yaml -Raw
$scanBody = @{ target = "http://test-api:9000"; specification = $spec } | ConvertTo-Json -Depth 20
$scan = Invoke-RestMethod -Method Post "$base/scans" -Headers $headers -ContentType "application/json" -Body $scanBody
$scanId = $scan.id
Invoke-RestMethod "$base/scans/$scanId" -Headers $headers
Invoke-RestMethod "$base/scans/$scanId/findings" -Headers $headers
Invoke-WebRequest "$base/scans/$scanId/report?format=json" -Headers $headers -OutFile report.json
Invoke-WebRequest "$base/scans/$scanId/report?format=html" -Headers $headers -OutFile report.html
```

A scan is asynchronous. Poll its status until `Completed`, `Failed`, or `Cancelled`. Routes include `POST /auth/register`, `POST /auth/login`, `GET /auth/me`, `POST /auth/logout` (client-side token discard; tokens expire), `POST /scans`, `GET /scans`, `GET /scans/{id}`, `POST /scans/{id}/cancel`, `GET /scans/{id}/findings`, `GET /scans/{id}/report?format=json|html`, `GET /findings/{id}`, and health routes.

## Tests and quality

```powershell
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
pytest --cov=app --cov-report=term-missing
```

The API integration tests use isolated SQLite fixtures. Docker end-to-end behavior should also be checked on a machine with Docker Desktop installed; the current development sandbox may not provide Docker.

## Severity and verification

Severity is Informational, Low, Medium, High, Critical. Verification statuses are Confirmed (direct evidence establishes the stated behavior), Potential (a signal requires validation), Inconclusive (evidence cannot decide), and Not Tested (no check was performed). Current active checks are conservative and generally emit Potential rather than Confirmed. Missing headers are hardening observations, not proof of exploitability. Anonymous access to an operation declared public is not reported as missing authentication.

## Security and authorization

Only scan systems owned by you or explicitly authorized for assessment. Add the exact host to the comma-separated `ALLOWED_TARGET_HOSTS`; arbitrary targets are rejected. Private addresses are blocked by default. The Compose lab opts into private networking solely for the allowlisted synthetic `test-api`. Do not publish that service to the Internet or broaden the allowlist. The scanner does not follow redirects, does not use environment proxies, and never automatically sends state-changing HTTP methods.

See [SECURITY.md](SECURITY.md) for hardening guidance. A scanner cannot guarantee detection of all vulnerabilities. This project is not production-ready; organizational deployment requires security review, hardened secret lifecycle, TLS, auditability, stronger DNS rebinding defenses, operational rate limiting, monitoring, backup/restore validation, and additional integration tests.
