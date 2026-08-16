# Directive WP-16 - Field Domain

**Issued by:** Lead (/root) - **Lane:** Core with senior review - **Wave:** 7
**Depends:** WP-15 Field Contracts, WP-03 Identity, WP-07 Incidents, WP-12 Realtime
**Review chain:** Cipher adversarial review -> Lead merge gate

## Objective

Implement the authoritative server-side Field domain in `services/core-api`.
This work turns WP-15 contracts into durable assignment and operative-state
semantics without building a mobile client yet.

## Spec References

- Architecture section 13: Field states and core field functions.
- Architecture section 67: Field/protected-user separation and offline store.
- Architecture section 76: delivery semantics and acknowledgement truth.
- Milestone 2 roadmap: WP-16 Field domain and WP-17 realtime delivery.
- WP-15 contracts: `packages/contracts/src/field.ts` and `whisper.ts`.

## Deliverables

- `services/core-api/src/modules/field`
  - Field assignment repository/service/controller.
  - Operative state update endpoint and current-state read model.
  - Assignment accept/decline/start/complete/cancel transitions.
  - Server-side validation with WP-15 schemas.
  - Org/site/incident/assignment-scoped authorization for every read/write.
  - Idempotency keys for assignment actions and state updates.
  - Transactionally coupled domain mutation, timeline/audit record, and outbox
    row.
- Prisma schema and additive migration for:
  - Field assignments.
  - Field operative state history and current-state projection.
  - Field idempotency/replay records keyed by organisation, site, device, and
    sequence where device operations are involved.
  - Field outbox rows, or reuse of the incident outbox only when the event is
    incident-scoped.
- API tests and service tests covering lifecycle, authorization, idempotency,
  duplicate replay, and cross-tenant/site isolation.

## Constraints

- Do not treat realtime socket presence as authoritative Field availability.
  Presence may hint that a client is connected; Field state is an audited domain
  event persisted by the Field service.
- Do not trust client-supplied `freshness_ms`. Compute authoritative freshness
  from `source_at` and server receipt time. Persist client-observed freshness
  only as telemetry.
- Do not rely on role-only authorization. Check organisation, site, incident,
  assignment, purpose, and actor/assignee constraints.
- Do not create a second delivery state machine. Use `DeliveryStateSchema` and
  existing delivery transition rules where transport state is represented.
- All state transitions that can race must use CAS or equivalent transactional
  guards.
- All mutation side effects must be crash-consistent: state mutation, audit or
  timeline record, and outbox record are written in one DB transaction.
- No UI, mobile, Whisper Studio, patrol implementation, or offline local storage
  work in WP-16.

## Acceptance Criteria

1. An authorised dispatcher or commander can create a site-scoped assignment for
   a Field operative in the same organisation/site.
2. The assigned operative can accept, decline, start, and complete only their
   own active assignment; unrelated operators and cross-site users are denied.
3. Illegal assignment transitions fail without changing persisted state.
4. Duplicate accept/decline/start/complete requests are idempotent and do not
   duplicate timeline/outbox records.
5. Operative state updates persist an append-only history and update the current
   state projection under the same organisation/site scope.
6. Authoritative freshness is computed server-side and tested against stale
   client telemetry.
7. Cross-organisation and cross-site negative API tests prove no assignment,
   state, or realtime payload leaks.
8. Focused tests plus `pnpm --filter @sentinel/core-api typecheck`, lint, and
   relevant Prisma validation pass.

## Out of Scope

- Native mobile or protected-user clients.
- Incident field messaging, patrol routes/checkpoints, offline operation inbox,
  and Whisper execution; those remain WP-18 through WP-21.
- Production IdP/device attestation rollout.
- Repository settings, GitHub billing, and deployment configuration.
