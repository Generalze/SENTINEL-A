# Directive WP-00 — Repository Scaffold

**Issued by:** Lead (Fable 5) · **Lane:** Junior (Haiku, certified CERT-H) · **Wave:** 0
**Review chain:** Sonnet adversarial review → Lead merge gate

## Objective
Stand up the pnpm/Turborepo monorepo skeleton exactly as laid out in `EXECUTION_PLAN.md` §4, with local infra and CI. No business logic.

## Scope (files you may create/modify)
- Root: `package.json`, `pnpm-workspace.yaml`, `turbo.json`, `tsconfig.base.json`, `.eslintrc.cjs`, `.prettierrc`, `.nvmrc`/`engines`
- `apps/command-web/` — Vite React-TS app, placeholder page only
- `services/core-api/` — empty NestJS app (`nest new` layout), health endpoint returning `{ status: 'ok' }`
- `packages/contracts/`, `packages/simulator/` — empty package stubs with `src/index.ts`
- `infrastructure/compose/docker-compose.dev.yml` — postgres:16 (with postgis image), nats:2 with JetStream enabled, redis:7, minio; `.env.example` with all connection strings
- `.github/workflows/ci.yml` — install → typecheck → lint → test (allowed to pass trivially for now)
- `tests/integration/` — folder with `.gitkeep`

## Constraints
- TypeScript `strict: true` in `tsconfig.base.json`; every package extends it.
- Node 22 LTS assumed. pnpm 9.
- No `any`, no disabled lint rules.
- Do NOT touch `docs/`, `LICENSE.md`, `README.md`.

## Acceptance criteria
1. `pnpm install` succeeds from clean clone.
2. `pnpm -r typecheck` and `pnpm -r lint` pass.
3. `docker compose -f infrastructure/compose/docker-compose.dev.yml config` validates.
4. `services/core-api` starts and `GET /health` returns 200 `{ status: 'ok' }`.
5. CI workflow YAML is syntactically valid.

## Out of scope
Any domain module, any schema, any database migration, any WebSocket code.
