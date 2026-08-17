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
  holding the explicit oversight authority defined below may read one.
- A principal who is not entitled to a message must not be able to learn that it
  exists. Follow the WP-17 precedent: **404, not 403**, for a message outside
  the caller's recipient set, so the endpoint cannot be used to probe.
- Purpose (`x-purpose`) is required wherever the classification of the route
  demands it under §62.1. Do not weaken the existing guard to make messaging
  convenient.

### Commander oversight is an explicit action, never a side effect of `incident.view`

**Lead ruling.** Command needs incident-wide awareness, but it must be granted
deliberately rather than inherited from the broad incident-read permission.
Introduce a new §62 action:

```text
incident.field-message.oversight.read
```

Granted initially to **`site.commander` only**.

`incident.view` must **not** grant access to message content. This is not a
theoretical distinction: `incident.view` is currently held by `site.commander`,
`operator`, `dispatcher`, `field.operative`, `investigator`, and `admin` (see
`identity/roles.ts`), so binding message reads to it would hand message content
to six roles at once. The oversight read is therefore a **separate route with a
separate guard**, exactly as D4 requires — never a widened check on the
recipient route.

The oversight chain is:

```text
authenticated
  -> explicit oversight action
    -> organisation match
      -> site scope
        -> incident scope
          -> clearance
            -> valid purpose
              -> message read
```

**An oversight reader is not a recipient.** This separation is load-bearing:

```text
Named recipient          Commander oversight
-----------------        -------------------
delivery row             no delivery row
delivery state           no delivery state
acknowledgement          no acknowledgement attributed to the commander
```

If oversight created recipient rows, command visibility would silently corrupt
the meaning of §76 delivery state — "delivered" would stop meaning "reached the
operative it was addressed to". A commander may receive a minimal notification
on their own server-derived user room, carrying no body, media, or sender data.

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
  wider than the entitled set. This follows from C7-08's underlying rule rather
  than contradicting it:

  ```text
  WP-17 shared site room:   audience > entitled audience  -> identifier forbidden
  WP-18 per-user room:      audience = entitled user      -> identifier permitted,
                                                             content still forbidden
  ```

  State that reasoning in the code, so the difference between the two channels
  is not later read as an inconsistency and "fixed" in the wrong direction. The
  permitted payload shape is:

  ```json
  { "kind": "incident_field_message.updated", "incident_id": "...", "message_id": "..." }
  ```

  and it is permitted **only** while organisation/user routing comes from
  authenticated, server-resolved scope — never from payload-controlled room
  selection.
- Any new NATS subject follows the WP-17 rules: every dynamic token validated by
  `common/messaging/subject-token.ts`, exact subject arity, consumers failing
  closed on unexpected segment counts.

## Deliverables

- **D1 - Persistence, with tuple-bound references.** Incident field message
  table plus recipient membership, delivery state per recipient, retention
  metadata, and idempotency records. Additive migration.

  The message record is bound to a real tenant/site/incident **tuple**, not to
  bare ids — the WP-17A composite-reference precedent, extended one level:

  ```text
                       Site
                        ^
                        | (site_id, organisation_id)
                        |
  Incident  <---- IncidentFieldMessage
      ^                 |
      | (incident_id, organisation_id, site_id)
      |
  ```

  ```text
  FK #1  (site_id, organisation_id)
         -> Site(id, organisation_id)                       ON DELETE RESTRICT

  FK #2  (incident_id, organisation_id, site_id)
         -> Incident(id, organisation_id, site_id)          ON DELETE RESTRICT
  ```

  FK #2 needs a referenceable candidate key on Incident:
  `UNIQUE(id, organisation_id, site_id)`. Its redundancy with the primary key is
  **intentional** — it lets the database prove that *this exact incident belongs
  to this exact tenant and site*, not merely that the incident id exists.

  Net effect: WP-18 changes no existing Incident semantics, yet it becomes
  impossible to create a Field message against an incident whose site is
  fictional, belongs to another organisation, or disagrees with the site scope
  recorded on the message.

- **D1a - Scope is server-derived, never supplied.** The send request body must
  **not** carry `organisation_id` or `site_id`. The server loads the incident
  and derives both from it, then checks them against the principal.

- **D1b - Legacy incidents are refused generically.** An otherwise-authorised
  caller messaging on a pre-existing incident whose `site_id` does not resolve
  to a real operational Site gets **409 Conflict**, `Incident is not eligible
  for Field messaging`. Do not reveal whether the dangling identifier is
  nonexistent or belongs to another tenant. Log the integrity problem
  internally with the trace id so it is diagnosable without being disclosed.

- **D2 - Append-only semantics.** Once committed:

  ```text
  message body     IMMUTABLE
  recipient set    IMMUTABLE
  sender           IMMUTABLE
  incident / site  IMMUTABLE

  delivery state   MAY ADVANCE
  ```

  Corrections are new messages; nothing rewrites a sent message (§61).

- **D2a - No retroactive recipient backfill.** **Lead ruling: recipients are
  frozen at send time.** WP-18 exposes no API for adding somebody to an
  already-sent message.

  ```text
  Message 1 -> A, B
  C joins the incident later
  Message 1 remains -> A, B only
  Message 2 -> A, B, C, if the sender chooses
  ```

  If older information genuinely needs to reach C, it is **re-shared as a new
  message**, producing a new immutable record and a new audit trail rather than
  silently enlarging the audience of historical content.

  This also settles thread semantics: WP-18 introduces **no thread-level
  historical entitlement**. Entitlement is evaluated per message, always.
- **D3 - Delivery state.** Reuse `DeliveryStateSchema` and the existing §76
  transition rules. **Do not create a second delivery state machine.** Delivery
  is tracked per recipient, since one message can be delivered to one operative
  and not another.
- **D4 - REST surface.** Send, list-for-incident (scoped to what the caller may
  see), read-one, and acknowledge. One `@RequiresAction` per route; where two
  authorities may read the same resource, expose two routes rather than
  widening a guard. Concretely, the recipient/sender read and the commander
  oversight read are **separate routes with separate guards**
  (`field.message.*` versus `incident.field-message.oversight.read`), and
  acknowledge exists only on the recipient route.
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
9. **A principal holding `incident.view` but not
   `incident.field-message.oversight.read` cannot read message content**, proven
   by a live API test for each of the other `incident.view` roles.
10. **A commander reading by oversight creates no recipient row, no delivery
    state, and no acknowledgement** — asserted by row counts, so oversight
    cannot silently alter what "delivered" means.
11. **Changing incident participation, assignment, role, or recipient
    eligibility later never grants retrospective access to previously sent
    messages.** A user added to the incident after a message was sent is denied
    that message with the same 404 as any other non-recipient.
12. The database rejects a message row whose `(site_id, organisation_id)` or
    `(incident_id, organisation_id, site_id)` tuple does not match a real Site
    and Incident — proven by a direct write that bypasses the service.
13. A send against a legacy incident with an unresolvable site returns a generic
    409 that does not distinguish "nonexistent" from "another tenant's".
14. `pnpm -r typecheck`, `pnpm -r lint`, `pnpm -r test`, the CI source gates, and
    the Proof A regression pass — **verified by the `pull_request` CI workflow**,
    not by a local run alone.

## Out of Scope

- Automated retention enforcement or deletion jobs.
- Media upload/transcode; `media_refs` are references, and the Evidence vault
  remains the store of record.
- Read receipts beyond §76 delivery state.
- Native mobile clients and Command web UI for messaging.
- Patrol (WP-19), offline operations (WP-20), Whisper (WP-21).

## Lead rulings (closed)

The three questions this directive originally left open are now decided. They
are recorded here as well as inline so the reasoning is not lost in a diff.

1. **Commander oversight: GRANTED, but only via an explicit action.**
   `site.commander` gets incident-wide message oversight through the new
   `incident.field-message.oversight.read` action on a separate route — never
   as a consequence of `incident.view`, which six roles hold. An oversight
   reader is not a recipient: no delivery row, no delivery state, no
   acknowledgement, so command visibility cannot corrupt the meaning of §76
   delivery state.

2. **Recipient membership: IMMUTABLE per sent message.** Recipients are frozen
   at send time; there is no backfill API. Later participation changes never
   grant retrospective access. Sharing older information with a new participant
   means sending a new message, which produces a new immutable record and a new
   audit trail instead of silently enlarging a historical audience.

3. **`Incident.site_id`: UNCHANGED — but messages are tuple-bound.** WP-18 does
   not alter existing Incident referential semantics. The Incident model
   deliberately keeps `organisation_id`/`site_id` as scalar cross-domain
   identifiers to stay independent of Fusion/Identity migration ordering, and
   Proof A depends on today's behaviour. Instead, the new message record carries
   composite foreign keys to both `Site` and `Incident` (D1), so WP-18 cannot
   create a message against a fictional, cross-tenant, or scope-mismatched
   incident without touching what already exists.

   The broader Event/Fusion/Incident site-identity question is **explicitly
   carried as a WP-22 / Milestone-2 sign-off prerequisite decision**, not
   smuggled into WP-18. It must be ruled on before Milestone 2 is signed off.

## Milestone-2 prerequisite raised by this directive

> **Cross-domain site identity.** `Event.site_id` and `Incident.site_id` remain
> free-text cross-domain identifiers while Field and Field messaging now require
> real, tenant-matched Sites. That divergence is deliberate and bounded today,
> but it is a Milestone-2 sign-off prerequisite: WP-22 must not close until the
> lead has ruled on whether the Event/Fusion/Incident domains adopt the same
> referential standard, or the divergence is documented as permanent with its
> reasoning.
