# SENTINEL — Master Execution Plan

**Lead Developer:** Claude Fable 5 (architecture, critical decisions, all merge gates)
**Execution:** Certified lower-model agents (Opus 5 / Sonnet 5 / Haiku 4.5) under written directives
**Version:** 1.0 — 2026-08-14
**Owner of record:** masterzee001

---

## 1. Command Structure and Decision Rights

This plan mirrors the product's own governance doctrine: no single worker has unlimited authority, evidence before action, and every consequential decision is recorded.

| Level | Who | Authority |
|---|---|---|
| **Lead (Fable 5)** | Architecture, tech-stack decisions, scope, work-package definition, directive authoring, final review of every merge, integration, milestone sign-off, all "critical decisions" | Sole merge authority. Nothing lands without lead review. |
| **Senior lane (Opus 5)** | Security-critical and reasoning-heavy domains: Constitution/policy engine, Fusion correlation, workflow engine. Also adversarial reviewer of other agents' security-relevant code. | May propose design within a directive; may not change contracts or scope. |
| **Core lane (Sonnet 5)** | Domain services, APIs, persistence, realtime, simulator, Command web, integration tests | Implements to directive; escalates ambiguity instead of guessing. |
| **Junior lane (Haiku 4.5)** | Scaffolding, configuration, boilerplate, well-specified single-module tasks, test-case expansion from explicit specs, docs formatting | Never assigned security-critical logic. Output always reviewed by a higher lane before lead review. |

**Escalation rule:** any agent that hits ambiguity, a contract question, or a spec conflict STOPS and reports. Guessing on a security platform is a defect, not initiative.

**Certification rule:** no agent works a lane it has not been certified for. Certification is by live probe (see `AGENT_CERTIFICATION.md`). An agent that fails review twice in a lane is demoted to smaller scopes with tighter directives — the mission does not absorb the risk.

---

## 2. Milestone 1 — Proof A (locked scope)

Per architecture §60/§80, the first serious proof is **not** a vision demo. It is one complete protected workflow, fully honest end to end:

> A simulated multi-source threat enters the event bus → **Fusion** correlates it → the **Constitution** authorises a response → **Command** receives it → a **Field** user acknowledges discreetly → **evidence is preserved** → the **Decision Ledger** explains every step.

**Exit criteria (all must pass):**
1. Simulator can replay a scripted multi-source scenario (camera-sim + access-sim + field report) into the event bus.
2. Fusion produces a hypothesis with threat state, separated confidence/severity values, and at least one recorded contradiction check.
3. Constitution evaluates the response action with a complete decision trace; a two-person-approval path is demonstrated.
4. Command web shows the incident queue and timeline live (WebSocket, no refresh).
5. Field acknowledgement round-trips (REQUESTED → DELIVERED → ACKNOWLEDGED semantics per §76).
6. Evidence object stored immutably (hash + custody event) in object storage.
7. Decision Ledger entry reconstructs the whole chain without re-running anything.
8. Full scenario runs as a single automated integration test in CI — this test becomes the first permanent Crucible regression.

Out of scope for Milestone 1: cameras/ONVIF, AI models, mobile apps, Guest Protection, OpenIntel/DarkWatch, Controlled Reality, multi-site.

---

## 3. Locked Technical Decisions

Stack follows architecture §36, with concrete picks made for one overriding reason: **a single, strongly-typed language across the whole codebase maximises lower-model agent reliability.**

| Layer | Decision | Rationale |
|---|---|---|
| Language | TypeScript, `strict: true`, everywhere | One language = one mental model for all agents; types are executable directives. |
| Monorepo | pnpm workspaces + Turborepo | Matches §37 layout; incremental builds; agents work in isolated packages. |
| Core backend | NestJS 11 | §36 recommendation; module boundaries map 1:1 to §38 service domains. |
| Contracts/validation | Zod schemas in `packages/contracts` — single source of truth, imported by every service and app | Events are immutable statements; the contract package is versioned and owned by the lead. |
| Database | PostgreSQL 16 + PostGIS, Prisma ORM (raw SQL escape hatch for spatial) | §36; Prisma's generated types keep agent code honest. |
| Event transport | NATS JetStream | §36; durable streams, append-only event doctrine. |
| Cache/presence | Redis 7 | §36. |
| Evidence storage | MinIO (dev) → any S3-compatible with object-lock (prod) | §36; immutable originals via object lock + SHA-256 in DB. |
| Realtime | NestJS WebSocket gateway (socket.io) with per-org channels | §41.2; video never rides this channel. |
| Frontend | React 18 + TypeScript + Vite, TanStack Query, Tailwind CSS | §36; MapLibre GL added in Milestone 2. |
| Testing | Vitest (unit/component), Supertest (API), one docker-compose test env, Playwright (Milestone 2) | §51 test pyramid. |
| Observability | OpenTelemetry SDK + Prometheus metrics + pino structured logs, `trace_id` on every event | §49. |
| Local infra | Docker Compose: postgres, nats, redis, minio | Everything runs on the dev machine. |
| CI | GitHub Actions: lint → typecheck → unit → integration → Proof-A scenario | §50.2 gates, scaled to Milestone 1. |

**Deferred by decision (not by accident):** Go/Rust services (only when a measured hotspot justifies them), dedicated graph DB (Postgres first per §36), Flutter mobile (Milestone 3), Kubernetes (compose until a second site exists).

---

## 4. Target Repository Layout (Milestone 1 subset of §37)

```
sentinel/
├─ apps/
│  └─ command-web/          # React incident queue + timeline
├─ services/
│  └─ core-api/             # NestJS modular monolith
│     └─ src/modules/
│        ├─ identity/       # orgs, sites, users, roles, RBAC/ABAC
│        ├─ events/         # ingestion, idempotency, NATS publish
│        ├─ fusion/         # rule-based correlation v1
│        ├─ constitution/   # policy evaluator + versioned policies
│        ├─ incidents/      # lifecycle, severity, timeline
│        ├─ response/       # workflow primitives, acknowledgement semantics
│        ├─ evidence/       # vault, hashes, custody
│        ├─ ledger/         # decision ledger (append-only)
│        └─ realtime/       # WS gateway
├─ packages/
│  ├─ contracts/            # Zod schemas: events, incidents, decisions (LEAD-OWNED)
│  └─ simulator/            # scenario engine + scripted scenarios
├─ infrastructure/
│  └─ compose/              # docker-compose.dev.yml, .env.example
├─ docs/
│  ├─ architecture/         # v1.1 master architecture (existing)
│  └─ execution/            # this plan, certifications, directives
└─ tests/
   └─ integration/          # Proof A end-to-end scenario test
```

---

## 5. Work Breakdown Structure

| WP | Name | Deliverable | Depends on | Lane |
|---|---|---|---|---|
| WP-00 | Repo scaffold | pnpm/turbo monorepo, tsconfig/eslint/prettier, docker-compose, CI skeleton | — | Haiku (lead-reviewed) |
| WP-01 | Contracts package | Event/incident/decision Zod schemas per §40, idempotency keys per §64.1, versioned | WP-00 | Sonnet, lead co-author |
| WP-02 | core-api skeleton | NestJS app, config, health, pino, OTel wiring, Prisma init | WP-00 | Sonnet |
| WP-03 | Identity & org domain | Orgs/sites/zones/users/roles, ABAC guard per §62.1 | WP-02 | Sonnet |
| WP-04 | Event ingestion | Append-only store, idempotency, NATS JetStream publish, dedup-link per §64.1 | WP-01, WP-02 | Sonnet |
| WP-05 | Fusion v1 | Rule-based correlation, hypotheses, threat states §11.2, contradiction engine §11.4 | WP-04 | **Opus** |
| WP-06 | Constitution engine | Deny-by-default evaluator, versioned policies, two-person approval, decision traces §5.1/§62.1 | WP-01 | **Opus** |
| WP-07 | Incident + Response | Incident object §12.1, severity, timeline, workflow primitives §63.1, delivery semantics §76 | WP-05, WP-06 | Opus + Sonnet |
| WP-08 | Decision Ledger | Append-only ledger records per §5.2, written by fusion/constitution/response | WP-06 | Sonnet |
| WP-09 | Evidence vault | MinIO originals, SHA-256, custody events, derived-object rule §72 | WP-02 | Sonnet |
| WP-10 | Simulator | Scenario engine + "coordinated intrusion" script emitting multi-source events §52 | WP-01 | Sonnet (spec by lead) |
| WP-11 | Command web | Incident queue, timeline, acknowledge action, live updates | WP-07, WP-12 | Sonnet + Haiku |
| WP-12 | Realtime gateway | Org-scoped WS channels, presence, incident push | WP-07 | Sonnet |
| WP-13 | **Proof A integration** | End-to-end scenario test in CI; milestone sign-off | all | **Lead + Opus** |

## 6. Execution Waves (parallelism plan)

```
Wave 0  WP-00                                  (serial: everything depends on it)
Wave 1  WP-01 ∥ WP-02                          (contracts + skeleton)
Wave 2  WP-03 ∥ WP-04 ∥ WP-06 ∥ WP-09          (independent domains, worktree-isolated)
Wave 3  WP-05 ∥ WP-08 ∥ WP-10 ∥ WP-12          (fusion + ledger + simulator + realtime)
Wave 3.5 WP-14                                 (security hardening — Wave 2 adversarial findings)
Wave 4  WP-07 ∥ WP-11                          (orchestration + UI)
Wave 5  WP-13                                  (lead-driven integration, hardening, regression)
```

Actual note: an adversarial security review runs at each wave boundary. Wave 2's review produced WP-14 (`docs/execution/security/WAVE-2-FINDINGS.md`) — one CRITICAL cross-tenant idempotency defect and a cluster of wiring/hardening findings, all scheduled rather than hot-patched because the top fix is a contract change (forbidden mid-wave). This is the Asymmetry Doctrine in practice: the review found the hole before it went live.

Parallel agents run in **isolated git worktrees**; the lead merges. Contract changes mid-wave are forbidden — a contract problem stops the wave and comes back to the lead.

---

## 7. Execution Protocol ("flawless" is a process, not a hope)

**Every WP is issued as a written directive** containing: objective, exact spec references (section numbers of the architecture doc), file-level scope, interface contracts, acceptance criteria, explicit out-of-scope list, and the tests that must exist. Agents receive the directive verbatim — never a vague "build X".

**Definition of Done (all WPs):**
1. `pnpm typecheck`, `pnpm lint`, `pnpm test` clean.
2. Acceptance criteria demonstrably met (test names map to criteria).
3. No `any`, no `@ts-ignore`, no TODO in security-critical paths.
4. Events append-only; no security state silently rewritten (§61).
5. New failure modes get a test before the fix lands (Crucible doctrine §25).

**Two-stage review, mirroring Fusion/Adversary/Constitution:**
1. **Adversarial review** — a different model than the author reviews with a break-it mandate (Opus reviews Sonnet/Haiku security-adjacent work; Sonnet reviews Haiku mechanical work).
2. **Lead review** — Fable reviews every diff before merge. Non-negotiable.

**Regression rule:** every defect found in review or integration becomes a permanent test. The Proof A scenario is regression zero.

---

## 8. Agent Roster and Certification

Certification is by **live probe against real SENTINEL domain problems**, graded by the lead against a rubric (spec fidelity 40, edge cases/tests 30, code quality 20, terminology/doctrine fidelity 10). Results and lane certificates: `docs/execution/AGENT_CERTIFICATION.md`.

| Agent | Probe | Lane sought |
|---|---|---|
| Haiku 4.5 | CERT-H: normalised event contract (§40) + idempotency (§64.1) | Junior — mechanical |
| Sonnet 5 | CERT-S: threat-state machine with trust weighting, diversity caps, contradiction handling (§11) | Core — domain services |
| Opus 5 | CERT-O: Constitution evaluator — deny-by-default, two-person approval, decision traces (§5.1/§58.2/§62.1) | Senior — security-critical |

Recertification triggers: two failed reviews in a lane, or assignment to a new domain class.

---

## 9. Risk Register (top 5)

| Risk | Mitigation |
|---|---|
| Agent drift from spec on subtle security rules | Directives quote spec verbatim; adversarial review; lead gate; contracts package lead-owned. |
| Parallel-work merge conflicts | Worktree isolation; package-per-WP boundaries; contracts frozen per wave. |
| "Demo-ware" — happy path only | DoD requires failure-mode tests; §76 delivery semantics mandatory from WP-07 on. |
| Scope creep toward cameras/AI before core is honest | Milestone 1 scope is locked in §2; lead rejects out-of-scope work in review. |
| Silent quality decay in junior-lane output | Haiku output always double-reviewed; demotion rule enforced. |

---

*This plan is the standing order for Milestone 1. Changes to sections 2, 3, or 7 are lead-only decisions and must be committed with a rationale.*
