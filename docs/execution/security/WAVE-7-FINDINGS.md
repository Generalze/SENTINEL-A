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
| C7-01 | P0 | **Cross-site Field fanout.** WP-16 published Field events to `sentinel.field.updated.{organisation_id}` and the bridge forwarded them to `org:{organisation_id}`. Every socket in a tenant therefore received every site's Field traffic — assignment ids, operative ids, and site ids for sites the caller has no scope over. Site scope existed in the domain layer and was discarded at the delivery layer, defeating the §62.1 site conjunct for anything that rides the socket. | **Fixed.** Field events publish on `sentinel.field.updated.{organisation_id}.{site_id}`; the bridge routes on the site token to `org:{org}:field:site:{site}` plus `org:{org}:field:all`. Room membership is derived server-side from the principal's own §62 role assignments — an organisation-wide grant joins the org-wide Field room, a site-scoped grant joins only its own site rooms, and the two branches are mutually exclusive, so each socket has a single eligible fanout path (see *Delivery semantics* below). A Field message with no site token is dropped, never fanned out organisation-wide. | `realtime.field-isolation.integration.spec.ts` (live stack) proves the site-A1 event reaches the A1 operative and reaches neither the A2 operative nor the other tenant, and that an organisation-wide dispatcher receives every site over a single fanout path; `field-rooms.util.spec.ts` covers room derivation; `realtime-nats-bridge.service.spec.ts` covers routing and the fail-closed drop. |
| C7-02 | P0 | **Need-to-know leak of operative state.** The `FIELD_STATE_UPDATED` outbox payload carried the operative's `state`, and the shared realtime whitelist passed `state` through. `COMPROMISED` and `NEED_SUPPORT` therefore reached every connected socket in the organisation, including principals whose roles grant no Field action at all. | **Fixed.** The wire carries a signal, not the record: Field outbox payloads are reduced to `kind`, `organisation_id`, `site_id`, and the relevant subject id, and a Field-specific projection (`pickFieldRealtimeFields`) enforces that at the bridge regardless of what a future payload contains. Operative state is read over REST behind `field.state.read`. Sockets are additionally only joined for principals holding a Field visibility action. | `payload-whitelist.util.spec.ts` asserts `state` is dropped even when present; the live AC5 test publishes `state`, `location`, and `need_to_know_summary` and asserts none arrive; `realtime.gateway.spec.ts` asserts a no-Field-action principal joins no Field room. |
| C7-03 | P1 | **Subject-token injection via `site_id`.** `organisation_id` and `site_id` are free-text columns and were interpolated straight into a NATS subject. NATS treats `.` as the token separator and `*`/`>` as wildcards, so a caller able to name a site (`x.y`, `x.>`) could change the subject's arity or widen it — steering Field events into another site's room or across a wildcard. | **Fixed.** One shared validator (`common/messaging/subject-token.ts`) defines what may be a subject token. Every Field mutation validates `site_id` at the API boundary and rejects an unsafe value before persistence; the outbox publisher revalidates and refuses to publish a row whose scope ids are unsafe, skipping it (unpublished, logged at error) rather than stalling the queue. | `subject-token.spec.ts` covers separator, wildcard, whitespace, length, and non-string inputs; `field.api.integration.spec.ts` asserts unsafe site ids are refused over HTTP and never persist; `field-outbox.publisher.spec.ts` covers the publisher's refusal and its continue-past-poisoned-row behaviour. |
| C7-04 | P1 | **No authoritative refetch path for the operative.** The delivery doctrine is that a socket signals and the client refetches over REST. `GET /field/assignments` requires `field.assignment.manage`, which `field.operative` does not hold, and `GET /field/state/:userId` requires `field.state.read`, which it also does not hold. An operative receiving a Field signal had no endpoint to refetch from, so the doctrine was unimplementable and the service's "own state needs no extra authority" branch was unreachable. | **Fixed.** Added `GET /field/assignments/mine`, `GET /field/assignments/mine/:id`, `GET /field/assignments/:id`, and `GET /field/state/mine`. Each route carries exactly one `@RequiresAction` — the assignee's read and the dispatcher's read are separate routes rather than one widened guard. A non-assignee reading another operative's assignment gets 404, not 403, so the assignee set is not itself disclosed. | `field.api.integration.spec.ts` proves `mine` returns only the caller's assignments, that another operative's assignment is 404, that the operative holds no manage authority, and that `state/mine` returns the caller's own state. |
| C7-08 | P1 | **Peer Field identifier disclosure on the shared site channel.** `field.assignment.act` is held by every `field.operative`, so every operative posted to a site is admitted to that site's Field room. The Field projection still forwarded `assignment_id` and `user_id` to that room — while REST deliberately answers **404, not 403**, when one operative asks for another operative's assignment, because the assignee set is itself need-to-know. The socket therefore disclosed the existence and stable identifier of an object REST says the same principal may not know exists, making the realtime channel the weaker boundary. | **Fixed.** The Field projection is reduced to `kind`, `organisation_id`, `site_id` — a cache-invalidation hint carrying no object identity. An operative refetches `assignments/mine` / `state/mine`; a dispatcher or commander refetches their site-scoped list. The cost is a wider refetch rather than a fetch-by-id, which is the correct trade on a shared channel: object-specific notification requires an assignee- or user-scoped room, not a wider payload. | `payload-whitelist.util.spec.ts` has a dedicated C7-08 case asserting `assignment_id` and `user_id` are dropped; the live AC1 and AC5 regressions assert the received payload is exactly scope + kind, including that a state change does not reveal *whose*. |
| C7-06 | P2 | **The subject-token rule was applied to one builder, not all of them.** Lead review of the C7-03 fix asked whether *every* dynamic NATS token was covered. It was not: the service has five subject builders, and WP-17 hardened only the Field one. The material gap is `sentinel.events.{organisation_id}.{site_id}`, where `site_id` is free client text on the ingest API. Because ingest persists first and publishes as a follow-up step (§76), an event whose `site_id` contains `.`, `*`, `>` or whitespace is accepted with 201 and then **never reaches Fusion** — a silently undeliverable detection, which on a protective platform is worse than a rejected request. The incidents/hypothesis consumers were checked and already fail closed (they require an exact 4-segment subject), so this was an availability and integrity gap rather than a misrouting one. | **Fixed for new writes; legacy rows bounded, not quarantined.** Ingest validates both tokens at the boundary and returns 400 before persistence, so an unsafe event can no longer be created. All five builders (`events`, `fusion` hypothesis and incident-candidate, `incidents` updated, `field` updated) assert the shared rule. **Precise claim:** a legacy poisoned event row is refused with an error-level log naming the cause instead of a warn that reads as transient NATS unavailability, and it does not stop other rows — but `tryPublish` returns the same `false` as a transient failure, so the row stays unpublished and **remains eligible for selection on later sweeps**. There is no terminal or quarantine state; adding one needs a column on the events table and was judged not worth a migration to classify historical poison. The incidents outbox publisher — which `break`s on error — now skips a poisoned row instead of stalling every tenant's updates behind it. | `subject-builders.spec.ts` pins all seven builder/token combinations against unsafe input and fixed segment counts. Note its scope: `BUILDERS` is hand-maintained, so it is a regression pin for the builders that exist, **not** an automatic bar on someone adding a sixth unvalidated builder elsewhere — that would require centralising subject construction behind a single module. `events.controller.spec.ts` covers the 400-before-persistence path for both fields. |
| C7-05 | P2 | **WP-16 acceptance criterion 7 was not delivered.** WP-16 shipped service and repository unit tests against doubles. A double cannot prove that the global guard chain is bound to the Field routes, that a cross-site create is refused, that a cross-organisation read hides existence, or that a duplicate action over HTTP writes no second audit or outbox row. | **Fixed.** A live-stack Field API regression drives the whole surface through the real `DevAuthGuard → AccessGuard` chain. | `field.api.integration.spec.ts` — 13 tests covering lifecycle, cross-site create, cross-organisation read, non-assignee action, dispatcher/operative authority separation, illegal transition, duplicate-action idempotency with audit/outbox counts, and server-computed freshness with a replayed state update. |

## Delivery semantics — what is and is not claimed

Lead ruling, recorded so the room design is not over-read:

> **Single-scope delivery path; REST remains authoritative.**

The org-wide/site room split guarantees that a Field event has one eligible
fanout path to any given socket — room membership cannot deliver the same event
to the same socket twice. That is a fanout property.

It is **not** a transport-level exactly-once guarantee, and must not be
described as one. WebSocket delivery is not exactly-once under disconnect,
reconnect, or gateway restart, and the Field outbox publisher is deliberately
at-least-once (a publish that succeeds but fails to mark the row is republished
on the next sweep). Both are acceptable precisely because the socket carries a
signal rather than state: a client that missed a signal, or saw one twice,
converges on the same answer by refetching over REST, where the full
authorization chain runs.

Any future consumer that needs ordered or once-only Field semantics must build
them on the REST read model or on a durable JetStream consumer, not on the WS
channel.

**Subject grammar (C7-08 hardening).** The realtime subscriptions were `>`
(match the organisation token and everything after it), chosen in WP-12 while
publisher arity was still unsettled. Arity is settled now, so the three
realtime subscriptions narrow to single-token wildcards
(`sentinel.fusion.hypothesis.*`, `sentinel.incidents.updated.*`,
`sentinel.field.updated.*.*`) and the bridge additionally rejects any subject
whose segment count is not exactly what its route declares. Consumers fail
closed to the same grammar the builders produce, on both sides.

The JetStream filter subjects (`sentinel.events.>`,
`sentinel.fusion.incident-candidate.>`, `sentinel.fusion.hypothesis.>` on the
incidents consumer) are deliberately unchanged: a durable consumer's filter
subject cannot be altered in place, so narrowing them means recreating
durables, and those consumers already fail closed by requiring an exact
four-segment parse before they act (C4-01). Revisit if durables are ever
rebuilt for another reason.

## Accepted limitations

Recorded so they are not mistaken for oversights:

1. **Room membership is computed at handshake time.** A role assignment changed
   while a socket is connected does not move that socket between Field rooms
   until it reconnects. This matches the existing organisation-room behaviour.
   Revocation that must take effect immediately is a session-invalidation
   concern and is deferred with the production IdP work, not solved here.

2. **A Field signal still discloses that *something* changed at a site.** After
   C7-08 the payload carries no object identity at all — only that a change of
   some `kind` occurred within a scope the socket was already authorised for.
   What remains is the room membership itself: an operative learns that
   *something* Field-related happened at their own site. That is acceptable for
   WP-17, where the subject of an event is an assignment or a state belonging
   to that site, and where every identity behind it must be refetched through
   REST.

   **Lead direction — WP-18 must not inherit this.** An incident field message
   has named recipients and an incident purpose, so its visibility has to be
   strictly narrower than "everyone assigned to this site". The required chain
   is:

   ```text
   authenticated principal
        -> organisation scope
        -> site scope
        -> incident scope
        -> assignment / purpose
        -> named recipient membership
        -> REST-authoritative message
        -> minimal realtime notification
   ```

   The realtime event should say no more than *"a message in incident X changed
   state; refetch it"*. Message content must not ride the socket, and the room
   a message notification lands in cannot be the site room — recipient
   membership is finer-grained than site membership, so WP-18 needs its own
   room or per-socket delivery derived from the recipient set.

## Remediated outside PR #1

| ID | Priority | Finding | Disposition |
|---|---|---|---|
| C7-07 | P2 | **`site_id` existence is not verified on a Field write.** An organisation-wide `field.state.write` holder can record state against a site id that exists only as a string. It is subject-token safe, so it cannot steer delivery or cross a tenant boundary — but it writes authoritative, permanent audit history naming a place that was never in the tenant, and emits a realtime event into a room no socket can be in. | **Fixed in WP-17A** — on branch `wp-17a-field-site-integrity`, stacked on WP-17 and **not part of PR #1**, so it carries its own review and merge gate. An earlier draft of this register listed C7-07 as an accepted limitation; that framing was too generous and is withdrawn. Field writes now prove the site exists **and** belongs to the caller's organisation before the transaction, answering an identical 404 for "no such site" and for "a real site in another tenant" so the endpoint cannot be used to probe the platform. A composite `(site_id, organisation_id) -> sites(id, organisation_id)` foreign key with `ON DELETE RESTRICT` backs it on the two live-state tables; the four historical/reliability tables deliberately keep no site foreign key so security history can never be cascade-erased. Locked ruling — including the standing rule that a future Site lifecycle must define tombstone semantics before any hard delete, and the explicit deferral of `Event`/`Incident` site ids — in [`WP-17A-field-site-integrity.md`](../directives/WP-17A-field-site-integrity.md). |

## Verification boundary

Evidence for the resolutions above is the named unit and live-stack integration
tests, run against the compose stack (Postgres, NATS, Redis, MinIO): **641 tests
pass** (baseline before Wave 7 was 573), together with `pnpm -r typecheck`,
`pnpm -r lint`, both CI source gates, and the Proof A regression.

This count is the merge evidence for the review-gate commit and supersedes the
620 recorded in an earlier draft of this register, which predated the C7-06 and
C7-08 work. If a later commit changes it, update this line — the security
artifact and the merge evidence must not disagree.

This document does not grant Milestone 2 sign-off. WP-17A is scheduled and runs
before Wave 8; WP-18 through WP-22 remain outstanding.

The formal merge gate is the `pull_request` CI workflow. The local run above is
the author's evidence, not a substitute for it: the workflow does not run on
feature-branch pushes, so it only executes once the PR is opened.
