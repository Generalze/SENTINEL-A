# Directive WP-02 — core-api Platform Layer

**Lane:** Core (Sonnet) · **Wave:** 1 · **Depends:** WP-00
**Review chain:** Opus adversarial review → Lead merge gate

## Objective
Turn the WP-00 core-api stub into a real service platform: validated config, structured logging with trace propagation, Prisma, and honest health reporting. No business domains yet.

## Deliverables (all under `services/core-api`)
1. **Config module** — all env vars validated at boot with Zod (`DATABASE_URL`, `NATS_URL`, `REDIS_URL`, `S3_*`, `PORT`, `LOG_LEVEL`, `DEV_AUTH_ENABLED`). Boot fails fast with a clear message listing every invalid/missing var.
2. **Logging** — pino via nestjs-pino; every request gets a `trace_id` (accept inbound `x-trace-id` or generate UUIDv7-style); `trace_id` appears in every log line and is returned as a response header.
3. **Prisma** — `prisma/schema.prisma` initialised for PostgreSQL, one `platform_meta` table (key/value + updated_at), migration committed, `PrismaService` with graceful shutdown.
4. **Health** — `GET /health` (liveness, always cheap) and `GET /health/ready` (checks DB, NATS, Redis; reports per-dependency `up|down|not_configured` and overall status; readiness is honest — a down dependency shows down, it does not lie). §44A.14 doctrine: failure states are honest.
5. **Global plumbing** — exception filter producing `{ error, trace_id }` without stack leaks; validation pipe; graceful shutdown hooks.

## Constraints
- Strict TS, no `any`. No domain logic, no auth logic (that is WP-03).
- Dependencies allowed: @nestjs/*, prisma/@prisma/client, nestjs-pino+pino, zod, nats, ioredis. Nothing else without lead approval.
- NATS/Redis clients live in thin injectable providers (`infra/` folder) so later WPs consume them; connect lazily, tolerate absence in unit tests.

## Acceptance criteria
1. Boot with missing env → process exits non-zero listing the missing vars.
2. With compose stack up: `/health/ready` shows all dependencies `up`; stop Redis → `redis: down`, overall `degraded`, endpoint still returns (HTTP 503).
3. `trace_id` round-trips (inbound header respected, response header set, present in logs).
4. `pnpm -r typecheck && pnpm -r lint && pnpm -r test` clean; unit tests for config validation and health aggregation logic.

## Out of scope
Users, orgs, events, OTel SDK wiring (deferred; pino + trace_id is the Milestone-1 observability baseline).
