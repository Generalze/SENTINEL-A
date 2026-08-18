# Milestone 2 - Field Operations Foundation

**Status:** Active execution slice after approved `milestone-1-proof-a`.
**Owner of record:** masterzee001
**Baseline:** `c948ecf` / `milestone-1-proof-a`

Milestone 1 proved the protected workflow: simulator event ingestion, Fusion,
Constitution, incident response, Command realtime updates, Field
acknowledgement, evidence custody, and Ledger reconstruction.

Milestone 2 turns that proof into an operator-usable Field workflow. It follows
architecture sections 13, 14, 67, 80, and 81. The first build wave is Field
contracts and authoritative server semantics; Whisper and offline replay are
included only after those foundations are explicit and tested.

## Objective

Deliver a minimal but honest Sentinel Field operating loop:

```text
Command assigns a field operative
  -> Field receives the assignment need-to-know
  -> operative presence, state, and acknowledgement are tracked
  -> incident-scoped messages round-trip
  -> patrol/checkpoint foundation is auditable
  -> offline client actions have versioned contracts before implementation
  -> a later device-action Whisper signal can invoke the proven silent protocol
```

This is not a mobile polish milestone. It is the domain, contracts, persistence,
realtime, and test foundation that a mobile app can safely depend on.

## Non-Goals

- No ONVIF, RTSP, live video, camera AI, or Edge runtime.
- No public Guest Protection client.
- No broad case-management or pursuit workflows.
- No native Flutter build until the API and contract layer are stable.
- No biometric, voice, gesture, or camera-based Whisper recognition.
- No production IdP rollout; keep dev auth while defining the production
  boundary.

## Work Packages

| WP | Name | Deliverable | Depends on |
|---|---|---|---|
| WP-15 | Field contracts | Versioned assignment, operative state, presence, patrol, checkpoint, incident-message, offline-operation, and device-action Whisper schemas in `packages/contracts`. | Milestone 1 |
| WP-16 | Field domain | Core API module for operative state, assignment create/claim/accept/decline, site-scoped reads/writes, transactional timeline/outbox records, and CAS/idempotency. | WP-15, identity |
| WP-17 | Field realtime | Authoritative Field events over existing org/site-scoped realtime channels; clients refetch from REST for state, never trusting sockets as source of truth. | WP-16, realtime |
| WP-18 | Incident field messaging | Incident-scoped messages with delivery state, need-to-know access, retention metadata, realtime fanout, and audit timeline links. | WP-16, WP-17 |
| WP-19 | Patrol foundation | Patrol routes, ordered checkpoints, verification events, missed-checkpoint state, and auditable incident/Field timeline records. | WP-16 |
| WP-20 | Offline operation contracts | Idempotent client-operation inbox contract with device identity, monotonic sequence, replay rules, conflict responses, and duplicate-effect tests. Implementation may stop at server-side replay harness if client storage is not ready. | WP-15, WP-16 |
| WP-21 | Whisper foundation gate | Whisper Studio data model and device-action modality design, kept behind contracts and approval lifecycle. Build only enough to prove integration with the existing SILENT Constitution path. | WP-15, WP-20 |
| WP-22 | Milestone 2 regression | One live integration test covering assignment, presence/state, incident message, patrol checkpoint, duplicate replay protection, and, if WP-21 is active, device-action Whisper to silent protocol. | WP-15..WP-21 |

## Acceptance Gates

- Field assignment can be created by an authorised commander/dispatcher and
  delivered only to an operative with matching organisation/site scope.
- Field state supports at least `AVAILABLE`, `RESPONDING`, `ON_SCENE`,
  `NEED_SUPPORT`, `COMPROMISED`, and `OFF_DUTY`, with audited transitions.
- Presence is server-derived from authenticated realtime sessions and never
  treated as authoritative availability or acknowledgement.
- Incident field messages are incident-scoped, need-to-know, append-only, and
  publish realtime updates without leaking across organisations.
- Patrol foundation supports a route, ordered checkpoints, verification events,
  missed-checkpoint state, and timeline/audit records.
- Offline replay semantics are specified before a client queue is built.
  Duplicate replay cannot duplicate acknowledgement, message, checkpoint, or
  incident side effects.
- Device-action Whisper signals are versioned and separate from protocols.
  Activation requires approval, context checks, anti-replay, and audit records.
- SILENT Whisper protocol reuses the Constitution two-person approval and
  incident response machinery proven in Milestone 1.
- The Milestone 2 live regression runs in CI and becomes the second permanent
  Crucible regression after Proof A.

## Suggested Wave Order

1. **Wave 6:** WP-15 contracts, then adversarial review before persistence.
2. **Wave 7:** WP-16 Field domain and WP-17 realtime delivery.
3. **Wave 8:** WP-18 incident messaging and WP-19 patrol foundation.
4. **Wave 9:** WP-20 offline operation contracts and replay harness.
5. **Wave 10:** WP-21 Whisper foundation gate.
6. **Wave 11:** WP-22 live regression, sign-off, and tag.

## Execution Progress

Kept current so a resumed session can see where work stopped without reading
the whole log.

| WP | State | Landed in |
|---|---|---|
| WP-15 / WP-15A | Done | `631fa8a`, `ff083cc` |
| WP-16 | Done, with Wave-7 review findings closed by WP-17 | `bd6076e` |
| WP-17 | Done — site-scoped Field delivery, need-to-know payloads, subject-token safety across every NATS builder, operative REST refetch, WP-16 AC7 API tests | this wave |
| WP-17A | **Scheduled, not started** — Field `site_id` referential integrity (C7-07) | — |
| WP-18 .. WP-22 | Not started | — |

**Next:** Wave 8 — WP-18 incident field messaging, then WP-19 patrol
foundation. WP-17A can run before or alongside Wave 8; it is independent of
both.

Wave-7 review findings, the delivery-semantics ruling, and the remaining
accepted limitations are in
[`security/WAVE-7-FINDINGS.md`](security/WAVE-7-FINDINGS.md). Two items there
are binding on later work:

- **WP-18 must not inherit WP-17's site-room need-to-know boundary.** Incident
  messages have named recipients and an incident purpose, so visibility must be
  narrower than site membership, and message content must not ride the socket.
  The required scope chain is written out in the findings register.
- **WP-19 checkpoint verification follows the Field-state precedent.** The
  client supplies checkpoint, source time, method, and device evidence; the
  server determines tenant/site validity, route membership, checkpoint
  ordering, device/actor authority, authoritative receipt time, replay and
  idempotency, missed/late state, and the audit and timeline effects. Client
  time and client freshness stay telemetry.

## Risk Register

| Risk | Control |
|---|---|
| Field becomes a fake mobile demo without durable semantics. | Build contracts, server domain, and replay tests before UI polish. |
| Presence becomes a spoofable client claim. | Derive online presence from server sessions; treat state/location updates as signed or audited field events. |
| Role-only checks leak incidents to the wrong operative. | Enforce organisation, site, assignment, incident, purpose, and device constraints on every new API. |
| Offline replay duplicates high-consequence actions. | Require device sequence CAS, idempotency keys, and permanent duplicate replay tests. |
| Whisper expands into unsafe AI recognition too early. | Limit Milestone 2 to device action and simulator input; no voice, gesture, or camera recognition. |
| SILENT response bypasses policy because it is "just field comms." | Reuse Constitution evaluation, two-person approval, Ledger, timeline, and response outbox paths. |
| Cross-tenant leaks through realtime rooms or message APIs. | Use the Milestone 1 org/site-scoped principal pattern and add negative tests for every new channel. |

## Lead Direction

Start Milestone 2 with WP-15. Contracts must be reviewed before any module
persists Field or Whisper state. If WP-15 exposes a conflict with existing
incident/response delivery semantics, stop and resolve the contract instead of
adapting downstream code silently.
