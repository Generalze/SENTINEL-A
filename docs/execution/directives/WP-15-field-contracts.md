# Directive WP-15 - Field Contracts

**Issued by:** Lead (/root) - **Lane:** Core with adversarial review - **Wave:** 6
**Review chain:** Cipher adversarial review -> Lead merge gate

## Objective

Extend `packages/contracts` with the Milestone 2 Field vocabulary. These
schemas are the source of truth for Field assignments, operative state, patrol
checkpoints, incident messages, offline operations, and the first device-action
Whisper input. Downstream services must import these contracts rather than
redefining local shapes.

## Spec References

- Architecture section 13: Sentinel Field states and core field functions.
- Architecture section 14: Whisper signal lifecycle, signal/protocol
  separation, and anti-spoofing.
- Architecture section 67: separate Field/protected-user applications, offline
  store, and Whisper recognition placement.
- Architecture section 76: delivery semantics already implemented in
  `packages/contracts/src/delivery.ts`.
- Architecture sections 80 and 81: Proof C and the Weeks 5-8 sequence.

## Deliverables

- `src/field.ts`
  - `FieldState`: `AVAILABLE`, `PATROL`, `OBSERVING`, `RESPONDING`,
    `ON_SCENE`, `NEED_SUPPORT`, `COMPROMISED`, `OFF_DUTY`.
  - `FieldAssignment`: assignment id, organisation/site/incident scope,
    assignee, assignment type, priority, status, delivery state, timestamps,
    actor ids, and need-to-know summary.
  - `FieldAssignmentStatus`: `REQUESTED`, `ACCEPTED`, `DECLINED`,
    `IN_PROGRESS`, `COMPLETED`, `CANCELLED`, `EXPIRED`.
  - `FieldOperativeStateUpdate`: actor, device, state, optional location,
    source timestamp, freshness, and trace id.
  - `PatrolRoute`, `PatrolCheckpoint`, and `CheckpointVerification`.
  - `IncidentFieldMessage`: incident-scoped message envelope with delivery
    state, retention class, sender/recipient ids, body/media references, and
    trace id.
  - `FieldOfflineOperation`: device id, monotonic sequence number,
    idempotency key, operation kind, payload, created_at, and trace id.
- `src/whisper.ts`
  - `WhisperSignal`: versioned signal definition separate from response
    protocol.
  - `WhisperSignalStatus`: `DRAFT`, `SIMULATION`,
    `FALSE_POSITIVE_TEST`, `ANTI_SPOOF_TEST`, `FIELD_DRILL`, `APPROVAL`,
    `ACTIVE`, `ROTATED`, `RETIRED`.
  - `DeviceActionWhisperResult`: signed recognition-result shape for the first
    Milestone 2 modality, including confidence, device trust, context, freshness,
    and anti-replay nonce.
- `src/device.ts`
  - Canonical `DeviceTrustSchema` using the architecture device-trust
    vocabulary: `TRUSTED`, `DEGRADED`, `SUSPICIOUS`, `QUARANTINED`,
    `COMPROMISED`, `OFFLINE`.
- `src/index.ts` exports the new schemas and inferred types.
- Vitest coverage for valid examples, invalid tenant/site scope, invalid state
  transitions where represented in contracts, duplicate/old offline sequence
  examples, Whisper lifecycle ordering examples, and over-large message payloads.

## Constraints

- Strict TypeScript and Zod validation; no `any`.
- Use snake_case field names for wire contracts.
- Every externally carried object includes `schema_version`.
- Do not modify existing incident, delivery, evidence, or Constitution schemas
  unless the change is explicitly required by a failing Field contract test.
- Field presence must not be modelled as authoritative availability; presence is
  a realtime/session signal, while Field state is an audited domain event.
- Whisper contracts must not encode universal secret phrases or any voice,
  gesture, camera, or AI-recognition modality.
- Replay helper identities must include organisation and site scope unless a
  stronger global-uniqueness invariant is introduced and tested.
- `freshness_ms` is client-observed telemetry only. Server modules must compute
  authoritative freshness from source timestamps and receipt time.

## Acceptance Criteria

1. `pnpm --filter @sentinel/contracts test`, typecheck, and lint pass.
2. Every new schema has named tests for valid, invalid, and boundary cases.
3. Field assignment and incident message contracts reuse existing delivery
   semantics instead of introducing a second delivery state machine.
4. Offline operation contracts make duplicate replay detectable by organisation,
   site, device id and monotonic sequence number.
5. Device-action Whisper result is versioned, tenant-scoped, anti-replay capable,
   and separate from the response protocol it may invoke.

## Out of Scope

- Persistence, Prisma migrations, NATS consumers, HTTP APIs, or UI.
- Native mobile or protected-user clients.
- Offline local encryption implementation.
- Whisper Studio UI or recognition engine.
- ONVIF, Edge, camera, voice, gesture, or AI model work.
