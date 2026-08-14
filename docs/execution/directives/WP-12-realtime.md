# Directive WP-12 — Realtime Gateway

**Lane:** Core (Sonnet) · **Wave:** 3 · **Depends:** WP-02
**Review chain:** Opus adversarial review (auth boundary) → Lead merge gate

## Spec references
§41.2 (realtime channels; no video on this path), §9.2 (Command live updates), §44A.11 pattern (server decides what a client may see — applied here to operator scoping).

## Deliverables (`services/core-api/src/modules/realtime`)
1. Socket.IO gateway (`@nestjs/websockets` + `@nestjs/platform-socket.io` — approved deps) on the same HTTP server, path `/ws`.
2. **Auth on connect:** same dev-auth principal model as WP-03 (`x-dev-user-id` in handshake auth); unauthenticated connections rejected; principal's organisation determines the ONLY room the socket may join: `org:{organisation_id}`. Cross-org subscription attempts are denied and logged.
3. **Bridge NATS → WS:** subscribe `sentinel.incidents.updated.*`, `sentinel.fusion.hypothesis.*` and forward to the matching org room as `incident.updated` / `hypothesis.updated` messages (payload: ids + summary fields, not full internal records).
4. **Presence:** in-Redis presence set per org (user_id, connected_at, socket count); `presence.changed` broadcast on join/leave; `GET /api/v1/presence` tenant-scoped.
5. Heartbeat/disconnect handling; the gateway never crashes the API on NATS outage (reconnects with backoff, logs degraded state — health/ready already reports NATS).

## Acceptance criteria
1. Two clients in different orgs: org-A incident update reaches only the org-A client (test with two socket clients against live stack).
2. Unauthenticated connect rejected (test).
3. NATS restart while sockets connected: clients stay connected, updates resume (test may be manual-scripted; report observed behaviour).
4. Presence add/remove reflected in Redis and endpoint (test).

## Out of scope
Video transport (never on this channel), field mobile channels, message replay/backfill (client refetches via REST).
