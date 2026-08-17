# Directive WP-18 - Incident Field Messaging

**Issued by:** Lead (/root) - **Lane:** Core with senior review - **Wave:** 8
**Depends:** WP-15 Field Contracts, WP-16 Field Domain, WP-17 Field Realtime, WP-17A Field Site Integrity
**Review chain:** Cipher adversarial review -> Lead merge gate
**Status:** Directive only. **No implementation branch until WP-17A is merged.**

## Objective

Incident-scoped messaging between Command and the field, where the right to see
a message is decided by named recipient membership — not by role, not by site,
and not by being connected to a socket.

## Blocking precondition

This work package does not begin until `main` contains WP-17 and WP-17A. It is
built directly on two of their guarantees:

- Field `site_id` refers to a real site in the caller's organisation (WP-17A).
  Messaging must not re-open the ability to write authoritative history against
  a site that does not exist.
- Delivery semantics are settled: **single-scope delivery path; REST remains
  authoritative** (WP-17). Nothing here may quietly reintroduce a socket as a
  source of truth.

## Spec References

- Architecture section 13: field communications.
- Architecture section 41.2: org-scoped realtime channels.
- Architecture section 44A.11: the server decides what a client may see.
- Architecture section 62.1: organisation + site + clearance + purpose.
- Architecture section 76: delivery semantics and acknowledgement truth.
- WP-15 contract: `IncidentFieldMessageSchema` in `packages/contracts/src/field.ts`.
- Wave-7 findings register: C7-08 and the WP-18 lead direction recorded there.

## Authorization model (binding)

WP-17's need-to-know boundary is site-room membership. **WP-18 must not inherit
it.** An incident message has named recipients and an incident purpose, so its
visibility is strictly narrower than "everyone assigned to this site". Every
read and every write is evaluated down the full chain:

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

Concretely:

- Being a `field.operative` at the incident's site does **not** confer read
  access to a message. Only the sender, a named recipient, or a principal
  holding an explicit incident-oversight authority may read one.
- A principal who is not entitled to a message must not be able to learn that it
  exists. Follow the WP-17 precedent: **404, not 403**, for a message outside
  the caller's recipient set, so the endpoint cannot be used to probe.
- Purpose (`x-purpose`) is required wherever the classification of the route
  demands it under §62.1. Do not weaken the existing guard to make messaging
  convenient.

## Realtime model (binding)

The realtime event is a notification, not a message.

- The socket payload says, in effect, *"a message in incident X changed state;
  refetch it"*. **Message content — `body`, `media_refs`, sender identity —
  never rides the socket.**
- Delivery must be derived from the recipient set, not from the site room. Use a
  per-user room (`org:{org}:user:{user_id}`) or equivalent per-socket delivery
  computed server-side from the principal, never from client input.
- Because a per-recipient room contains exactly the entitled set, a message
  identifier **may** appear in that payload — unlike WP-17's shared site room,
  where C7-08 required removing identifiers precisely because the room was
  wider than the entitled set. State this reasoning in the code, so the
  difference between the two channels is not read as an inconsistency.
- Any new NATS subject follows the WP-17 rules: every dynamic token validated by
  `common/messaging/subject-token.ts`, exact subject arity, consumers failing
  closed on unexpected segment counts.

## Deliverables

- **D1 - Persistence.** Incident field message table plus recipient membership,
  delivery state per recipient, retention metadata, and idempotency records.
  Additive migration. Site and incident references follow the WP-17A precedent:
  validated against the caller's organisation before the write, with a
  database-level constraint where the model allows one.
- **D2 - Append-only semantics.** Messages are immutable once sent. Corrections
  are new messages; nothing rewrites a sent message's content (§61). Delivery
  state advances; message content does not change.
- **D3 - Delivery state.** Reuse `DeliveryStateSchema` and the existing §76
  transition rules. **Do not create a second delivery state machine.** Delivery
  is tracked per recipient, since one message can be delivered to one operative
  and not another.
- **D4 - REST surface.** Send, list-for-incident (scoped to what the caller may
  see), read-one, and acknowledge. One `@RequiresAction` per route; where two
  authorities may read the same resource, expose two routes rather than
  widening a guard.
- **D5 - Realtime notification.** Per-recipient delivery as described above,
  with a projection that carries no message content.
- **D6 - Transactional bundle.** Message row, recipient rows, timeline/audit
  record, and outbox row are written in one database transaction, as in WP-16.
- **D7 - Idempotency.** A resent message with the same idempotency key creates
  no second message, no second delivery record, and no second outbox row.
- **D8 - Retention.** `retention_class` and `expires_at` are persisted and
  audited. WP-18 records retention; it does not implement automated deletion.
- **D9 - Tests.** Unit plus live-stack integration, mirroring the WP-17
  standard:
  - a named recipient can read; a same-site non-recipient gets 404; a
    cross-site and a cross-organisation caller get 404;
  - content never appears in a socket payload, asserted against a real socket;
  - a non-recipient's socket receives nothing;
  - duplicate send is idempotent, with audit/outbox row counts asserted;
  - delivery state transitions follow §76 and illegal transitions are refused
    without mutating state.

## Constraints

- No Whisper, patrol, offline inbox, or mobile client work.
- No second delivery state machine, and no new "message read" concept that
  bypasses §76.
- No client-supplied scope. Organisation, site, incident, and recipient set are
  all resolved server-side.
- No message content in logs, metrics, or realtime payloads.
- Additive schema changes only.
- Message size limits come from the WP-15 contract
  (`MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES`, `MAX_INCIDENT_FIELD_MESSAGE_BYTES`,
  `MAX_INCIDENT_FIELD_MESSAGE_MEDIA_REFS`) and are enforced server-side. Do not
  restate them locally; import them.

## Acceptance Criteria

1. A message is readable by its sender and its named recipients, and by nobody
   else — including a `field.operative` assigned to the same incident and site
   who is not a named recipient.
2. A caller not entitled to a message receives 404, not 403, on read.
3. Cross-site and cross-organisation reads and sends are refused, proven by live
   API tests.
4. No message content reaches a socket, proven by a live socket assertion.
5. A non-recipient's socket receives no notification for that message.
6. Duplicate sends are idempotent and append no second audit or outbox row.
7. Delivery state per recipient follows §76; illegal transitions fail without
   changing persisted state.
8. Messages are append-only; no path rewrites a sent message.
9. `pnpm -r typecheck`, `pnpm -r lint`, `pnpm -r test`, the CI source gates, and
   the Proof A regression pass — **verified by the `pull_request` CI workflow**,
   not by a local run alone.

## Out of Scope

- Automated retention enforcement or deletion jobs.
- Media upload/transcode; `media_refs` are references, and the Evidence vault
  remains the store of record.
- Read receipts beyond §76 delivery state.
- Native mobile clients and Command web UI for messaging.
- Patrol (WP-19), offline operations (WP-20), Whisper (WP-21).

## Open questions for the lead before implementation

1. **Incident-oversight read authority.** Should a `site.commander` be able to
   read every message on an incident at their site without being a named
   recipient? There is a real argument each way — command awareness versus
   need-to-know — and it changes the authorization chain, so it is a lead
   decision rather than an implementer's default.
2. **Recipient set mutability.** May recipients be added to an existing message
   thread after the fact, and if so does a late recipient gain visibility of
   messages sent before they joined? Defaulting to "no backfill" is safer, but
   this should be ruled on explicitly.
3. **Whether `Incident.site_id` takes the WP-17A referential constraint.** The
   WP-17A decision record deferred this pending its own ruling; WP-18 writes
   incident-scoped rows and is the natural point to decide.
