# Wave 7 Adversarial Security Review — Field Delivery

**Reviewer:** Cipher (adversarial pass on the WP-16 merge)
**Date:** 2026-08-17
**Scope:** The Field domain as merged in WP-16 (`bd6076e`) and its realtime
delivery path — Field outbox publication, the NATS→WebSocket bridge, room
selection, and the Field REST surface.

This register records the Wave-7 findings and the resolutions implemented in
WP-17. It is an engineering security record, not a milestone sign-off.
Milestone 2 acceptance remains a separate lead decision.

## Findings and disposition

| ID | Priority | Finding | Resolution / current state | Verification evidence |
|---|---|---|---|---|
| C7-01 | P0 | **Cross-site Field fanout.** WP-16 published Field events to `sentinel.field.updated.{organisation_id}` and the bridge forwarded them to `org:{organisation_id}`. Every socket in a tenant therefore received every site's Field traffic — assignment ids, operative ids, and site ids for sites the caller has no scope over. Site scope existed in the domain layer and was discarded at the delivery layer, defeating the §62.1 site conjunct for anything that rides the socket. | **Fixed.** Field events publish on `sentinel.field.updated.{organisation_id}.{site_id}`; the bridge routes on the site token to `org:{org}:field:site:{site}` plus `org:{org}:field:all`. Room membership is derived server-side from the principal's own §62 role assignments — an organisation-wide grant joins the org-wide Field room, a site-scoped grant joins only its own site rooms, and the two branches are mutually exclusive so no socket is served twice. A Field message with no site token is dropped, never fanned out organisation-wide. | `realtime.field-isolation.integration.spec.ts` (live stack) proves the site-A1 event reaches the A1 operative and reaches neither the A2 operative nor the other tenant, and that an organisation-wide dispatcher receives every site exactly once; `field-rooms.util.spec.ts` covers room derivation; `realtime-nats-bridge.service.spec.ts` covers routing and the fail-closed drop. |
| C7-02 | P0 | **Need-to-know leak of operative state.** The `FIELD_STATE_UPDATED` outbox payload carried the operative's `state`, and the shared realtime whitelist passed `state` through. `COMPROMISED` and `NEED_SUPPORT` therefore reached every connected socket in the organisation, including principals whose roles grant no Field action at all. | **Fixed.** The wire carries a signal, not the record: Field outbox payloads are reduced to `kind`, `organisation_id`, `site_id`, and the relevant subject id, and a Field-specific projection (`pickFieldRealtimeFields`) enforces that at the bridge regardless of what a future payload contains. Operative state is read over REST behind `field.state.read`. Sockets are additionally only joined for principals holding a Field visibility action. | `payload-whitelist.util.spec.ts` asserts `state` is dropped even when present; the live AC5 test publishes `state`, `location`, and `need_to_know_summary` and asserts none arrive; `realtime.gateway.spec.ts` asserts a no-Field-action principal joins no Field room. |
| C7-03 | P1 | **Subject-token injection via `site_id`.** `organisation_id` and `site_id` are free-text columns and were interpolated straight into a NATS subject. NATS treats `.` as the token separator and `*`/`>` as wildcards, so a caller able to name a site (`x.y`, `x.>`) could change the subject's arity or widen it — steering Field events into another site's room or across a wildcard. | **Fixed.** One shared validator (`common/messaging/subject-token.ts`) defines what may be a subject token. Every Field mutation validates `site_id` at the API boundary and rejects an unsafe value before persistence; the outbox publisher revalidates and refuses to publish a row whose scope ids are unsafe, skipping it (unpublished, logged at error) rather than stalling the queue. | `subject-token.spec.ts` covers separator, wildcard, whitespace, length, and non-string inputs; `field.api.integration.spec.ts` asserts unsafe site ids are refused over HTTP and never persist; `field-outbox.publisher.spec.ts` covers the publisher's refusal and its continue-past-poisoned-row behaviour. |
| C7-04 | P1 | **No authoritative refetch path for the operative.** The delivery doctrine is that a socket signals and the client refetches over REST. `GET /field/assignments` requires `field.assignment.manage`, which `field.operative` does not hold, and `GET /field/state/:userId` requires `field.state.read`, which it also does not hold. An operative receiving a Field signal had no endpoint to refetch from, so the doctrine was unimplementable and the service's "own state needs no extra authority" branch was unreachable. | **Fixed.** Added `GET /field/assignments/mine`, `GET /field/assignments/mine/:id`, `GET /field/assignments/:id`, and `GET /field/state/mine`. Each route carries exactly one `@RequiresAction` — the assignee's read and the dispatcher's read are separate routes rather than one widened guard. A non-assignee reading another operative's assignment gets 404, not 403, so the assignee set is not itself disclosed. | `field.api.integration.spec.ts` proves `mine` returns only the caller's assignments, that another operative's assignment is 404, that the operative holds no manage authority, and that `state/mine` returns the caller's own state. |
| C7-05 | P2 | **WP-16 acceptance criterion 7 was not delivered.** WP-16 shipped service and repository unit tests against doubles. A double cannot prove that the global guard chain is bound to the Field routes, that a cross-site create is refused, that a cross-organisation read hides existence, or that a duplicate action over HTTP writes no second audit or outbox row. | **Fixed.** A live-stack Field API regression drives the whole surface through the real `DevAuthGuard → AccessGuard` chain. | `field.api.integration.spec.ts` — 13 tests covering lifecycle, cross-site create, cross-organisation read, non-assignee action, dispatcher/operative authority separation, illegal transition, duplicate-action idempotency with audit/outbox counts, and server-computed freshness with a replayed state update. |

## Accepted limitations

Recorded so they are not mistaken for oversights:

1. **Room membership is computed at handshake time.** A role assignment changed
   while a socket is connected does not move that socket between Field rooms
   until it reconnects. This matches the existing organisation-room behaviour.
   Revocation that must take effect immediately is a session-invalidation
   concern and is deferred with the production IdP work, not solved here.

2. **A Field signal still discloses that *something* changed at a site.** The
   payload is deliberately minimal, but membership of a site room is itself the
   need-to-know boundary at this layer. Per-assignment recipient filtering
   belongs with WP-18's incident-scoped messaging, where the recipient set is
   part of the contract.

3. **`site_id` existence is not verified on a state write.** An organisation-wide
   `field.state.write` holder could record state against a site id that exists
   only as a string. It is subject-token safe and therefore cannot steer
   delivery, and assignment creation is already constrained by the assignee's
   site-scoped `field.operative` role. This is data hygiene rather than a
   delivery boundary, and is left to the patrol/site work in WP-19.

## Verification boundary

Evidence for the resolutions above is the named unit and live-stack integration
tests, run against the compose stack (Postgres, NATS, Redis, MinIO): 620 tests
pass, including the Proof A regression. This document does not grant Milestone 2
sign-off, and WP-18 through WP-22 remain outstanding.
