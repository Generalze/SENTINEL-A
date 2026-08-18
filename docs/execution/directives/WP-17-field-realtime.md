# Directive WP-17 - Field Realtime Delivery

**Issued by:** Lead (/root) - **Lane:** Core with senior review - **Wave:** 7
**Depends:** WP-12 Realtime, WP-15 Field Contracts, WP-16 Field Domain
**Review chain:** Cipher adversarial review -> Lead merge gate

## Objective

Deliver authoritative Field events to the right operators and to nobody else,
and give a Field client a REST read model it can refetch from. WP-16 made the
Field domain durable; WP-17 makes its realtime delivery honest.

Sockets are a *signal* channel. A client learns only that something in its own
scope changed, then refetches authoritative state over REST where the full
authorization chain runs. No client ever treats a socket payload as truth.

## Spec References

- Architecture section 41.2: org-scoped realtime channels; video never rides
  this channel.
- Architecture section 44A.11: the server decides what a client may see.
- Architecture section 62.1: organisation + site + clearance + purpose
  authorization, not role-only.
- Architecture section 76: delivery semantics and acknowledgement truth.
- Milestone 2 roadmap: WP-17 Field realtime; risk control "Cross-tenant leaks
  through realtime rooms or message APIs".

## Findings This Directive Must Close

WP-16 landed the Field domain and an outbox publisher, and wired
`sentinel.field.updated.>` into the existing realtime bridge. Reviewing that
merge against sections 41.2/44A.11/62.1 produces four defects:

- **F1 (cross-site leak, HIGH).** `field.updated` is broadcast to `org:{org}`.
  Every socket in the tenant receives every site's Field traffic, including
  operatives posted to a different site. Site scope exists in the domain layer
  and is discarded at the delivery layer.
- **F2 (need-to-know leak, HIGH).** The `FIELD_STATE_UPDATED` outbox payload
  carries the operative's `state`. `COMPROMISED` and `NEED_SUPPORT` therefore
  reach every connected socket in the organisation, including principals whose
  roles grant no Field action at all.
- **F3 (subject-token injection, HIGH).** `organisation_id` and `site_id` are
  free-text columns, and `fieldUpdatedSubject` interpolates `site_id` straight
  into a NATS subject. A site id containing `.`, `*`, or `>` changes the
  subject's arity or turns it into a wildcard, so a caller who can name a site
  can steer or widen delivery.
- **F4 (no refetch path, blocking).** `GET /field/assignments` requires
  `field.assignment.manage`. The `field.operative` role does not hold it, so an
  operative who receives a Field signal has no endpoint from which to refetch
  the assignment. "Refetch from REST" is not currently possible.

WP-16 acceptance criterion 7 (cross-organisation and cross-site negative **API**
tests) was also not delivered — only service/repository unit tests against
doubles exist. WP-17 closes it.

## Deliverables

- **D1 - Site-scoped realtime rooms.**
  - `RealtimePrincipal` carries role assignments as `{ role, site_id }`, not
    bare role strings; the loader stops discarding `site_id`.
  - Field room membership is derived server-side from the principal's role
    assignments and the section 62 role table: a principal joins Field rooms
    only if some assignment grants a Field visibility action
    (`field.assignment.manage`, `field.assignment.act`, `field.state.read`).
  - An organisation-wide granting assignment joins one org-wide Field room; a
    site-scoped grant joins one room per granted site. The two are mutually
    exclusive so no socket receives an event twice.
  - The existing `org:{organisation_id}` room and its incident/hypothesis/
    presence traffic are unchanged.
  - No `join` message handler exists. Rooms remain underivable from client
    input.

- **D2 - Site-scoped Field subject and bridge routing.**
  - Field events publish to `sentinel.field.updated.{organisation_id}.{site_id}`.
  - The bridge parses organisation and site from the concrete subject and emits
    to the site room and the org-wide Field room only.
  - A Field message whose subject carries no site token is dropped and logged.
    Fail closed; never fall back to an organisation-wide broadcast.

- **D3 - Subject-token safety.**
  - One shared validator defines what may appear as a NATS subject token.
  - `site_id` is validated at write time on every Field mutation; an unsafe id
    is rejected with 400 before anything is persisted.
  - The publisher revalidates before publishing and skips (does not publish,
    does not mark published) any row whose scope ids are unsafe, logging at
    error level. This path is unreachable once write-time validation is in
    place and exists as defence in depth.

- **D4 - Need-to-know payload minimisation.**
  - Field outbox payloads carry routing and identity only: `kind`,
    `organisation_id`, `site_id`, and `assignment_id` or `user_id`.
  - Operative `state` is removed from the wire. It is read over REST, behind
    `field.state.read`.
  - The bridge applies a Field-specific whitelist so a future payload change
    cannot widen what reaches a socket.

- **D5 - REST refetch surface.**
  - `GET /api/v1/field/assignments/mine` (`field.assignment.act`) - the
    caller's own assignments, site-scoped.
  - `GET /api/v1/field/assignments/mine/:id` (`field.assignment.act`) - one own
    assignment; 404 when the caller is not the assignee.
  - `GET /api/v1/field/assignments/:id` (`field.assignment.manage`) - one
    assignment for a dispatcher/commander, org- and site-scoped.
  - `GET /api/v1/field/state/mine` (`field.state.write`) - the caller's own
    current state. `field.state.read` is the authority to read *another*
    operative's state and `field.operative` does not hold it, so the existing
    `state/:userId` route denies an operative reading itself back.

- **D6 - Tests.**
  - Unit: room derivation for org-wide, site-scoped, and no-Field-action
    principals; subject build and parse; token validation; Field payload
    whitelist.
  - Live realtime integration: a Field event reaches the same-site operative
    and the org-wide commander, and reaches neither a different-site operative
    in the same organisation, nor another organisation, nor a connected
    principal with no Field action.
  - Live Field API integration (closes WP-16 AC7): assignment lifecycle over
    HTTP; cross-site create denied; cross-organisation read returns 404;
    non-assignee action denied; duplicate action idempotent with no extra audit
    or outbox rows; server-computed freshness; `mine` returns only the caller's
    assignments.

## Constraints

- Do not weaken `@RequiresAction`. A route carries exactly one action; where two
  authorities may read the same resource, expose two routes.
- Do not let a client name a room, a subject, or a scope. Every scope value is
  derived from the authenticated principal or from server-side state.
- Do not treat socket presence as Field availability. Presence remains a
  connection hint; Field state remains an audited domain record.
- Do not put domain state on the wire. Sockets carry a signal; REST carries
  truth.
- Do not create a second delivery state machine.
- Additive changes only to the Prisma schema. WP-17 is expected to need none.
- No patrol, incident messaging, offline inbox, Whisper, or mobile client work.

## Acceptance Criteria

1. A Field event for site A reaches a socket scoped to site A and does not reach
   a socket scoped only to site B in the same organisation.
2. A Field event does not reach any socket in another organisation.
3. A connected principal whose roles grant no Field action receives no Field
   event.
4. An organisation-wide Field authority receives Field events for every site in
   its organisation, over a single eligible fanout path — the org-wide/site
   room split cannot deliver one event to the same socket twice.

   This is a statement about room fanout, not about transport. WebSocket
   delivery is not exactly-once under disconnect, reconnect, or publisher
   retry, and the Field outbox is deliberately at-least-once. The guarantee
   the system actually offers is **single-scope delivery path; REST remains
   authoritative** — a client that missed or double-received a signal reaches
   the same state by refetching.
5. Operative `state` never appears in a socket payload; the payload carries only
   `kind`, `organisation_id`, `site_id`, and the relevant subject id.
6. A `site_id` that is not a safe subject token is rejected at the API boundary
   before persistence, and the publisher refuses to publish one.
7. A Field operative can list and read their own assignments over REST, and
   cannot read another operative's assignment.
8. Cross-organisation and cross-site negative API tests exist for the Field REST
   surface, and duplicate actions remain idempotent over HTTP (WP-16 AC7).
9. `pnpm -r typecheck`, `pnpm -r lint`, and `pnpm -r test` pass against the live
   stack, and the Proof A regression still passes.

## Out of Scope

- Native mobile or protected-user clients.
- Command web UI for Field.
- Patrol routes, incident field messaging, offline operation inbox, Whisper.
- Production IdP, device attestation, socket transport hardening beyond the
  existing dev-auth handshake.
- Repository settings, billing, deployment configuration.
