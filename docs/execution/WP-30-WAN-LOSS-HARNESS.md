# WP-30 — WAN-loss harness

The infrastructure Proof D stands on: a topology whose WAN can actually be
severed, a typed control that severs it, a mechanism for the asymmetric case a
blunt cut cannot express, and the restart procedures — including the one that
is deliberately manual.

This document is the operator's account. The engineering arguments live in the
files themselves; the reasons are not repeated here, only pointed at.

## Why this exists

Before WP-30 the repository had **no severable boundary at all**.
`infrastructure/compose/docker-compose.dev.yml` starts postgres, nats, redis and
minio, declares no networks and contains no core-api. Every live suite boots
`AppModule` inside the vitest process on the host and reaches those containers
over loopback. Central, Edge and the test were one process on one host in one
network namespace.

A "WAN outage" written against that topology can only be a flag, a stub, or a
mocked method call — the three things the Proof-D acceptance definition names
and refuses. There was nothing to disconnect.

## The topology

`infrastructure/compose/docker-compose.wan-loss.yml`, project `sentinel-wp30`.

```
 ┌────────────┐  field   ┌──────┐   wan    ┌──────────┐ central  ┌─────────┐
 │ field-lan- │──────────│ edge │──────────│ wan-link │──────────│ central │
 │  witness   │  (LAN)   │      │  (CUT)   │  (proxy) │          │ core-api│
 └────────────┘          └──────┘          └──────────┘          └────┬────┘
                            │                                        │
                       edge_queue                             postgres / nats
                        (volume)                               redis / minio
```

`wan` is the only severable segment. Every other property of the topology exists
so that the cut means what it claims to mean:

| Property | Why |
|---|---|
| Edge's LAN attachment is on `field`, a different network | severing the WAN cannot take site connectivity with it |
| Edge's store is a **named** volume | no network operation can reach it; and a named volume is not silently replaced on recreate, so the durability assertion can fail |
| the cut is `docker network disconnect` | detaches an interface from a **running** container; the process is never signalled |
| Edge is on neither `central` nor any network reaching postgres | there is no route around the severed link |
| `restart: 'no'` on edge and central | the daemon cannot quietly resurrect a service the suite is supposed to notice dying |

If the cut killed the Edge, the scenario would prove nothing — every "Edge kept
operating" assertion downstream would be vacuously true of a corpse. The
mechanism suite asserts it does not: same pid, same `StartedAt`, same restart
count across the cut.

### Images

| Image | Source | Note |
|---|---|---|
| `sentinel-core-api:wp30` | `services/core-api/Dockerfile` | new in WP-30. Central has to become a thing that *sits somewhere* before "central is unreachable" can be a statement about routing. |
| `sentinel-edge-runtime:wp30` | `services/edge-runtime/Dockerfile` | **authored by the WP-29B Edge-deploy lane**, vendored here byte-identically together with the root `.dockerignore`. See "Provenance" below. |

`services/core-api/Dockerfile.dockerignore` is a per-Dockerfile ignore file:
BuildKit uses it *instead of* the root `.dockerignore` for that one build, so
central's context can admit `services/core-api` without the Edge image ever
carrying core-api into a wiring closet.

### Host ports

All bound to `127.0.0.1`, all distinct from the shared dev stack's.

| Port | Reaches |
|---|---|
| `3230` | central **directly** — the harness's out-of-band witness channel |
| `3240` | central **through the WAN** — what a client behind the link sees |
| `3241` | wan-link **control plane** — the harness only; the Edge has no route to it |
| `3210` | the Edge |
| `5453` | the harness's own postgres |

## The cut / restore control

`tests/wan-loss/harness/wan-control.ts`.

```ts
const wan = new WanControl();
await wan.state();      // 'CONNECTED' | 'CUT' — read from the daemon, never cached
const cut = await wan.cut();       // { to: 'CUT',       at: ISO, edge: {...} }
const back = await wan.restore();  // { to: 'CONNECTED', at: ISO, edge: {...} }
wan.transitions();      // the authoritative, ordered record of the interval
```

Underneath:

```
docker network disconnect sentinel-wp30_wan sentinel-wp30-edge
docker network connect    sentinel-wp30_wan sentinel-wp30-edge
```

Three properties worth knowing:

- **Verified, not assumed.** Both operations re-read the container's
  attachments afterwards and throw if reality disagrees. A harness whose "cut"
  was merely a command that exited zero would one day report a green Proof D
  against a fully connected network.
- **Not idempotent, on purpose.** Cutting a cut link throws. An idempotent cut
  lets a scenario cut twice by accident and pass, leaving its single restore to
  land the link wherever the bookkeeping happened to point.
- **The harness is the authority on the interval.** Central cannot testify to a
  period during which nothing reached it — a silence in its log is equally
  consistent with an outage, an idle client, a crashed client and a logging
  failure. Only the party that caused the interval can attest to it.

### The cut is a black hole, not a name lookup

Detaching a container from a Docker network also removes that network's names
from its embedded DNS, so a naive cut fails at *resolution* — `ENOTFOUND`,
instantly. That is a weaker and less honest outage: a severed uplink does not
un-name the datacentre, and every retry/backoff classifier ever written routes
DNS failure differently from network failure.

So `wan` has a fixed subnet, `wan-link` has a fixed address in it
(`172.30.30.10`), and the Edge pins that address in `/etc/hosts` via
`extra_hosts`. `/etc/hosts` is a **file**; it outlives the interface. After the
cut the name still resolves and the route is gone.

**If you change `wan-link`'s `ipv4_address`, change the Edge's `extra_hosts`
entry with it.** They are two halves of one decision.

## Asymmetric failure — the phase a blunt cut cannot express

> the request arrives, central commits, the response is lost

This is the only state in which the client's knowledge and the server's state
genuinely diverge. A symmetric cut cannot produce it, because a symmetric cut
also stops the request.

`infrastructure/wan-link/wan-link.mjs` — a dependency-free HTTP reverse proxy
bind-mounted read-only into a stock Node image, so the file you read is verbatim
the bytes that run. Driven from `tests/wan-loss/harness/wan-link-control.ts`.

| Mode | Behaviour |
|---|---|
| `pass` | ordinary forwarding |
| `drop_response` | forward, await the upstream response **to completion**, then destroy the client socket without writing a byte |
| `drop_response_once` | the same for exactly one request, then reverts to `pass` **on its own** |
| `blackhole` | do not forward, never answer; the client's own timeout ends it |

Details that carry weight:

- The upstream response is **drained to `end` before being dropped**. Destroying
  the socket the instant headers arrived could catch central mid-write, and the
  harness would be asserting a commit it had not witnessed.
- `clientRes.socket.destroy()`, never `end()`. `end()` would send a well-formed
  zero-length 200 and the client would read a *successful* response — the
  opposite of a lost one.
- `drop_response_once` disarms when the request is **accepted**, not after the
  drop, so the retry needs no second control call. That is what makes the test
  deterministic rather than dependent on scheduling.
- `blackhole` is the partner case, and the pair matters: both produce `UNKNOWN`
  at the client, only one leaves an effect at central. A scenario that cannot
  tell them apart is testing retry, not recovery.

### The journal is the witness

After a dropped response, ask the three parties:

- **client** — "my socket died." Cannot distinguish a lost request from a
  committed one. That ambiguity *is* the situation under test.
- **central** — "I committed and I emitted a response." Emitting is the last
  thing it can observe; it has no honest log line saying the response was
  destroyed.
- **wan-link** — "I forwarded at T1, upstream answered 201 at T2, I destroyed
  that answer at T3."

Only the third is testimony. `GET /control/journal` returns it. Without it, a
phase-8 test would pass identically on a topology where the request never landed
— proving nothing, about the hardest case in the scenario.

Every journal field is an **ISO instant**. There are no duration fields and none
may be added.

## Restart orchestration

| Restart | How | Proves |
|---|---|---|
| **Edge** | `restartEdge()` → `docker restart` + poll liveness | site-local durable state survives the process |
| **Central** | `restartCentral()` → same | central holds its commitments across its own death |
| **Field app** | **manual — see below** | — |

`docker restart`, not `compose up --force-recreate`: a recreate builds a *new*
container, which would defeat the assertion the restart exists to make. Both
helpers assert the pid changed, because a restart that silently did nothing
would let every downstream durability check pass trivially.

### Field app restart — documented, manual, and deliberately not automated

WP-26's Field client is an **Android application on a physical handset**. There
is no container for it, and there must not be a stand-in that behaves like one.

The `field-lan-witness` container is a **network probe**: `sleep infinity`, no
application code, occupying the Field device's network *position* so the harness
can ask one question — after the cut, can something on the site LAN still reach
the Edge? It does not enrol, authenticate, sign, queue, sync or report degraded
state, and it must never be grown into something that appears to.

Manual procedure, for a Proof-D run with a real handset:

1. Handset is on the site LAN and can reach the Edge at `http://<edge-lan-ip>:3100`.
   In this compose topology the Edge's LAN address is on the `field` network;
   for a bench run, publish `3210` and put the handset on the host's LAN.
2. Record the wall-clock instant, and the harness's `wan.transitions()` record,
   so the app restart can be placed inside the outage interval.
3. Force-stop the app: **Settings → Apps → Sentinel Field → Force stop**.
   Force-stop, not swipe-away — swiping from the recents list does not
   reliably kill the process, and a process that never died has not restarted.
4. Relaunch from the launcher.
5. Assert against the app's own UI: the queued operations are still present, and
   the degraded-state indication is still shown.

Automating this needs a device farm or an emulator lane. Until then the manual
step is honest and a container pretending to be a handset would not be.

## Running it

```bash
# 1. topology up (blocks on healthchecks)
docker compose -p sentinel-wp30 \
  -f infrastructure/compose/docker-compose.wan-loss.yml up -d --build --wait

# 2. migrations — an operator action, exactly as CI runs it.
#    WP-30 adds none; this deploys the existing chain unchanged.
DATABASE_URL="postgresql://sentinel:sentinel@127.0.0.1:5453/sentinel" \
  pnpm --filter @sentinel/core-api exec prisma migrate deploy --schema prisma/schema

# 3. the suite
WP30_WAN_LOSS_LIVE=1 \
  pnpm --filter @sentinel/core-api exec vitest run --config ../../vitest.wan-loss.config.ts

# 4. teardown. `-v` is safe ONLY with `-p sentinel-wp30` pinned.
docker compose -p sentinel-wp30 \
  -f infrastructure/compose/docker-compose.wan-loss.yml down -v --remove-orphans
```

`WP30_KEEP_TOPOLOGY=1` leaves the stack up after the run so a failure can be
inspected in the state it happened in.

> **Never run `docker compose -f infrastructure/compose/docker-compose.wan-loss.yml down -v`
> without `-p sentinel-wp30`.** Compose derives an unset project name from the
> compose file's *directory* — the same name `docker-compose.dev.yml` derives —
> and the teardown would delete the shared dev stack's volumes.

### Gating

`vitest.wan-loss.config.ts` + `WP30_WAN_LOSS_LIVE=1` + a **separate CI job**,
following the `vitest.proof-a.config.ts` / `PROOF_A_LIVE` precedent. Without the
flag every suite reports SKIPPED — visibly not run, rather than a pass it never
earned.

It must never join `pnpm -r test`: it would contend for the shared database
(already recorded engineering debt), it would mutate host network state as a
side effect of an ordinary test run, and it takes minutes rather than seconds.

## What runs today, and what is pending

Running, for real, against the containerised topology:

- WAN severed → central unreachable from the Edge, as a black hole
- the Edge process, its site LAN and its durable store all survive the cut
- restore returns the route; the harness holds the timestamped interval
- **phase 8** — request lands, central commits, response destroyed, replay
  converges **effectively-once** (one canonical event, `received_count ≥ 1`)
- the `blackhole` partner case — same client-visible `UNKNOWN`, no effect at
  central
- Edge restart with the store intact; central restart with commitments intact

Pending on other lanes, marked `it.todo` in
`tests/wan-loss/proof-d-scenario.test.ts` with the reason in the test name:
Field degraded-state recognition (WP-26 Android), local queueing, explicit
refusals on expired policy/absent authority, authenticated reconnect and ordered
sync, stale authority, duplicate incident action, and the audit trail across the
outage.

**They are pending rather than stubbed.** A stand-in Edge that accepted, queued
and replayed operations would make the file green today and would make Proof D a
statement about the stand-in — the exact failure mode this milestone exists to
retire. `it.todo` cannot pass; a fake Edge would.

The topology is already correct for every one of them. What is missing is the
runtime, and when it lands each `it.todo` becomes a body rather than a rewrite.

## Vocabulary

**Effectively-once**, never "exactly-once". The system does not promise a
delivery arrives once; it promises that however many arrive, **at most one
effect** results. `UNKNOWN` is a truthful outcome, and assertions are written as
an honest disjunction of the states the system may report plus the domain
invariant (`canonical effect count ≤ 1`) that holds in all of them.

## Provenance

`services/edge-runtime/Dockerfile` and the root `.dockerignore` are the WP-29B
Edge-deploy lane's work, vendored here **byte-identically** (verified by
`sha256sum`) so WP-30 is self-contained and so git resolves the overlap without
conflict if both land. If that lane revises either file before merge, take its
version — WP-30 depends on the image existing, not on owning it.
