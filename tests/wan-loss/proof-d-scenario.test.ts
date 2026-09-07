/**
 * WP-30 — THE PROOF-D SCENARIO SKELETON.
 *
 * The locked acceptance definition (MILESTONE-3-ROADMAP.md):
 *
 *     central online, real Field device connected, Edge operational
 *       -> WAN severed  -> central unreachable
 *       -> Edge continues authorised critical local functions
 *       -> Field client recognises degraded state
 *       -> allowed operations queued locally
 *       -> some operations EXPLICITLY REFUSED (policy expired / no authority)
 *       -> WAN restored -> authenticated reconnect -> ordered synchronisation
 *       -> duplicates converge, changed requests conflict
 *       -> stale authority cannot rewrite current state
 *       -> no duplicate incident action -> complete audit trail
 *
 * WHAT RUNS HERE TODAY, AND WHAT IS MARKED PENDING, AND WHY THE SECOND LIST IS
 * NOT A FAILURE.
 * ---------------------------------------------------------------------------
 * The phases below that exercise the SEVERABLE BOUNDARY run for real. The
 * phases that need Edge BEHAVIOUR — a durable queue, a reconnect protocol,
 * degraded-state reporting, a policy lease that can expire — are marked
 * pending against the lane building them.
 *
 * THEY ARE MARKED PENDING RATHER THAN STUBBED, AND THAT IS THE MOST IMPORTANT
 * DECISION IN THIS FILE. A mock Edge inside a Proof-D harness is precisely the
 * defect the whole witness argument exists to prevent: it would produce a green
 * Proof D for a system that had never survived an outage, and it would do so
 * in the one artefact everybody downstream would cite as evidence that it had.
 * `it.todo` cannot pass. A fake Edge would.
 *
 * THE ONE PHASE THAT MATTERS MOST ALREADY RUNS.
 * --------------------------------------------
 * Phase 8 — the request arrives, central commits, the response is lost — is
 * the only state in which the client's knowledge and the server's state
 * genuinely diverge, and it is the reason every duplicate-suppression
 * mechanism in the system exists. It runs here today, end to end, against a
 * containerised central through a real link that destroys a real response,
 * because central's own §64.1 idempotency is genuine domain behaviour that
 * exists now. It needs no Edge to be truthful, and stating it now means the
 * lanes building the Edge have a working target rather than a description.
 *
 * "EFFECTIVELY-ONCE", NEVER "EXACTLY-ONCE".
 * -----------------------------------------
 * The system cannot promise a message is delivered once. It promises that
 * however many times a delivery arrives, at most one EFFECT results. The
 * assertions below are written as that: an honest disjunction of the states
 * the system may truthfully report, plus the domain invariant that holds in
 * every one of them.
 */

import { afterEach, afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import { CONTAINERS, probeFrom } from './harness/docker';
import { ENDPOINTS, assertSchemaDeployed, restartCentral, restartEdge } from './harness/topology';
import { WanControl } from './harness/wan-control';
import { WanLinkControl } from './harness/wan-link-control';
import {
  buildEvent,
  canonicalEvents,
  harnessPrisma,
  seedNamespace,
  submitThroughWan,
  uniqueNamespace,
} from './harness/central';

const live = process.env.WP30_WAN_LOSS_LIVE === '1';
const describeLive = live ? describe : describe.skip;

const WAN_ENDPOINT = { host: 'sentinel-wan', port: 8080, path: '/health' };

describeLive('WP-30 — Proof D scenario against a genuinely severable WAN', () => {
  const wan = new WanControl();
  const wanLink = new WanLinkControl(ENDPOINTS.wanLinkControl, ENDPOINTS.centralThroughWan);
  let prisma: PrismaClient;

  beforeAll(async () => {
    await assertSchemaDeployed();
    prisma = harnessPrisma();
    await wan.ensureConnected();
    await wanLink.reset();
  }, 300_000);

  afterEach(async () => {
    // Both resets are mandatory, and for the same reason: a scenario that
    // fails between cutting and restoring — or between arming a drop and
    // disarming it — would leave the link broken for every test after it, and
    // the resulting cascade would bury the one real failure under a dozen
    // consequences of it. Each test is responsible for the state it leaves.
    await wan.ensureConnected();
    await wanLink.reset();
  }, 300_000);

  afterAll(async () => {
    await prisma.$disconnect();
  });

  // ===========================================================================
  // PHASES THAT RUN TODAY — the severable boundary and central's own
  // effectively-once behaviour across it.
  // ===========================================================================

  it('PHASE 1-2: severing the WAN makes central unreachable from the Edge, and the harness times the interval', async () => {
    const cut = await wan.cut();

    const duringOutage = await probeFrom(CONTAINERS.edge, WAN_ENDPOINT);
    expect(duringOutage.outcome).toBe('UNREACHABLE');

    const restored = await wan.restore();
    const afterOutage = await probeFrom(CONTAINERS.edge, WAN_ENDPOINT);
    expect(afterOutage.outcome).toBe('REACHABLE');

    // Order, never elapsed time. The probe's own verdict instant falls inside
    // the harness's recorded interval, which is a claim about SEQUENCE and is
    // stable under any CI load; "the outage lasted N ms" is a claim about
    // speed and would not be.
    expect(Date.parse(cut.at)).toBeLessThanOrEqual(Date.parse(duringOutage.observedAt));
    expect(Date.parse(duringOutage.observedAt)).toBeLessThanOrEqual(Date.parse(restored.at));
  }, 180_000);

  it('PHASE 3: the Edge keeps serving the site while central is unreachable', async () => {
    await wan.cut();

    // Asked from the SITE LAN, not from the host. A published port would
    // answer even if the `field` network had collapsed entirely, so a host
    // probe would report success for a site that had lost its Edge.
    const lanToEdge = await probeFrom(CONTAINERS.fieldLanWitness, { host: CONTAINERS.edge, port: 3100, path: '/health' });
    expect(lanToEdge.outcome).toBe('REACHABLE');

    // And the Edge's own account of its durable store — the one dependency
    // whose failure must take it out of service.
    const readiness = await fetch(`${ENDPOINTS.edge}/health/ready`);
    const body = (await readiness.json()) as { dependencies: Record<string, string> };
    expect(body.dependencies.queue_storage).toBe('up');

    // THE HONEST LIMIT OF THIS ASSERTION, STATED HERE SO NOBODY LATER READS IT
    // AS MORE THAN IT IS: this proves the Edge PROCESS and its STORE survive
    // the outage. It does not prove the Edge accepted, queued and later
    // replayed a Field operation, because `services/edge-runtime` has no
    // ingress and no queue yet — those are EDGE-B and the store lane. The
    // scenario that proves the stronger claim is `it.todo` below, unstubbed.
    await wan.restore();
  }, 180_000);

  it('PHASE 8: the request lands, central commits, the RESPONSE is destroyed — and the replay converges effectively-once', async () => {
    const namespace = uniqueNamespace('phase8');
    await seedNamespace(prisma, namespace);

    const eventId = `evt_wp30_${namespace.organisationId}`;
    // Frozen and reused across both attempts. `occurred_at` is part of
    // `deriveIdempotencyKey(org, site, source, event_id, occurred_at, window)`,
    // so a retry that re-generated it would derive a DIFFERENT key, central
    // would treat the replay as a genuinely new event, and this test would
    // "prove" duplicate suppression by never once asking for it. This is the
    // single easiest way to write a phase-8 test that passes while testing
    // nothing.
    const occurredAt = new Date().toISOString();
    const event = buildEvent(namespace, eventId, occurredAt);

    // ARM THE ASYMMETRY. `drop_response_once` disarms itself when the request
    // is ACCEPTED, so the retry needs no second control call — which is what
    // makes this deterministic. A test that had to disarm between the two
    // attempts would have a window in which the outcome depended on
    // scheduling.
    await wanLink.setMode('drop_response_once');

    // ---- Attempt 1: the response is destroyed on the way back. -------------
    const first = await submitThroughWan(namespace, event);

    // UNKNOWN IS THE TRUTHFUL OUTCOME, and asserting it is asserting that the
    // harness produced the divergence it set out to produce. The client holds
    // no evidence its operation happened. It cannot distinguish this from a
    // request that never arrived — and that inability is the situation under
    // test, not a defect in the test.
    expect(first.kind).toBe('UNKNOWN');

    // ---- THE WITNESS. -----------------------------------------------------
    // This is why the wan-link journals. Ask the three parties what happened:
    // the client says "my socket died" and cannot tell a lost request from a
    // committed one; central says "I committed and I emitted a response", and
    // emitting is the last thing it can observe — it has no honest log line
    // saying the response was destroyed. Only the link that made the decision
    // can testify to it.
    //
    // Without this assertion, PHASE 8 would pass identically on a topology
    // where the request never landed at all — i.e. while proving nothing, and
    // proving it about the hardest case in the scenario.
    const journal = await wanLink.journal();
    const dropped = journal.filter((entry) => entry.disposition === 'RESPONSE_DROPPED');
    expect(dropped).toHaveLength(1);
    expect(dropped[0].method).toBe('POST');
    expect(dropped[0].path).toBe('/api/v1/events');
    // Central COMMITTED. A 201 that the client never saw is the whole point.
    expect(dropped[0].upstream_status).toBe(201);
    // Instants, in order — the request was forwarded before upstream answered,
    // and upstream answered before the answer was destroyed. Order, not
    // duration.
    expect(Date.parse(dropped[0].request_forwarded_at!)).toBeLessThanOrEqual(
      Date.parse(dropped[0].upstream_responded_at!),
    );
    expect(Date.parse(dropped[0].upstream_responded_at!)).toBeLessThanOrEqual(Date.parse(dropped[0].decided_at));

    // ---- Attempt 2: the identical operation is replayed. -------------------
    // The link has already returned to `pass` on its own.
    expect((await wanLink.state()).mode).toBe('pass');
    const second = await submitThroughWan(namespace, event);

    // AN HONEST DISJUNCTION, NOT A CERTAINTY THE SYSTEM CANNOT GIVE.
    //
    // `duplicate: true` is what central reports when it recognises the replay,
    // and it is what SHOULD happen here. But a system-level assertion that
    // demands it would be asserting a promise the platform does not make:
    // §64.1's idempotency window is finite, and a replay that fell outside it
    // would be a NEW canonical event — which is correct behaviour, not a
    // defect. So the states are enumerated, and the INVARIANT below is what
    // actually carries the weight.
    expect(second.kind).toBe('COMMITTED');
    const body = (second as { body: { duplicate: boolean; original_event_id?: string } }).body;
    if (body.duplicate) {
      expect(body.original_event_id).toBe(eventId);
    }

    // ---- THE DOMAIN INVARIANT. --------------------------------------------
    // EFFECTIVELY-ONCE, never exactly-once. The system does not promise a
    // delivery arrives once; it promises that however many arrive, AT MOST ONE
    // EFFECT results. Two deliveries reached central and exactly one canonical
    // event exists. The duplicate is not erased — `received_count` preserves
    // the fact that a redelivery happened, which §64.1 requires — it simply
    // never became a second effect.
    const canonical = await canonicalEvents(namespace, eventId);
    expect(canonical.length).toBeLessThanOrEqual(1);
    expect(canonical).toHaveLength(1);
    expect(canonical[0].received_count).toBeGreaterThanOrEqual(1);
  }, 300_000);

  it('PHASE 8 (partner case): a request that never LANDS is distinguishable from one whose response was lost', async () => {
    const namespace = uniqueNamespace('blackhole');
    await seedNamespace(prisma, namespace);
    const eventId = `evt_wp30_bh_${namespace.organisationId}`;
    const event = buildEvent(namespace, eventId, new Date().toISOString());

    // A scenario that cannot tell these two apart is not testing recovery, it
    // is testing retry. Both produce an UNKNOWN at the client; only one leaves
    // an effect at central, and a system that treated them identically would
    // either duplicate the first case or lose the second.
    await wanLink.setMode('blackhole');
    const attempt = await submitThroughWan(namespace, event);
    expect(attempt.kind).toBe('UNKNOWN');

    const journal = await wanLink.journal();
    const notForwarded = journal.filter((entry) => entry.disposition === 'NOT_FORWARDED');
    expect(notForwarded).toHaveLength(1);
    expect(notForwarded[0].upstream_status).toBeNull();

    // Central holds NOTHING. Same client-visible outcome as phase 8, opposite
    // server state — which is exactly why the client's view is not evidence
    // and the journal is.
    await wanLink.setMode('pass');
    expect(await canonicalEvents(namespace, eventId)).toHaveLength(0);
  }, 300_000);

  it('RESTART ORCHESTRATION: the Edge restarts with its durable store intact and the site LAN unaffected', async () => {
    const record = await restartEdge();

    // A different pid is the proof the process was genuinely replaced —
    // `restartEdge` throws otherwise, because a restart that silently did
    // nothing would let every downstream durability assertion pass trivially.
    expect(record.after.pid).not.toBe(record.before.pid);
    expect(Date.parse(record.stoppedAt)).toBeLessThanOrEqual(Date.parse(record.readyAt));

    // The durable store came back writable, on the Edge's own evidence. The
    // volume is NAMED in the compose file precisely so this assertion can
    // fail: an anonymous volume would be silently replaced on recreate and
    // this check could never detect a lost queue.
    const readiness = await fetch(`${ENDPOINTS.edge}/health/ready`);
    const body = (await readiness.json()) as { dependencies: Record<string, string> };
    expect(body.dependencies.queue_storage).toBe('up');

    const lanToEdge = await probeFrom(CONTAINERS.fieldLanWitness, { host: CONTAINERS.edge, port: 3100, path: '/health' });
    expect(lanToEdge.outcome).toBe('REACHABLE');
  }, 300_000);

  it('RESTART ORCHESTRATION: central restarts and still holds what it committed before the restart', async () => {
    const namespace = uniqueNamespace('central_restart');
    await seedNamespace(prisma, namespace);
    const eventId = `evt_wp30_cr_${namespace.organisationId}`;
    const event = buildEvent(namespace, eventId, new Date().toISOString());

    const committed = await submitThroughWan(namespace, event);
    expect(committed.kind).toBe('COMMITTED');

    const record = await restartCentral();
    expect(record.after.pid).not.toBe(record.before.pid);

    // Durability across central's own death. Its state lives in postgres, NATS
    // and S3 — none of which are in that container and none of which were
    // restarted — so this asks whether central holds its commitments across a
    // process restart, not whether PostgreSQL does.
    const canonical = await canonicalEvents(namespace, eventId);
    expect(canonical).toHaveLength(1);
  }, 300_000);

  // ===========================================================================
  // PENDING — EDGE BEHAVIOUR THAT DOES NOT EXIST YET.
  //
  // Each of these is a phase of the locked acceptance definition that needs
  // runtime that does not exist yet. WP-29B has since landed the Edge
  // durable queue and trusted time, so the reasons below are narrower than
  // they were when this file was written — but none of them has closed,
  // and a reason that goes stale silently is how a gap becomes invisible. They are `it.todo`: they cannot pass,
  // they are reported as todo in every run, and no reader can mistake them for
  // covered.
  //
  // THE ALTERNATIVE WAS CONSIDERED AND REJECTED. Standing up a stand-in Edge
  // that accepted, queued and replayed operations would make this file green
  // today, and it would make Proof D a statement about the stand-in. That is
  // the exact failure mode the milestone exists to retire — "the ordering,
  // idempotency and recovery machinery is exercised through an internal replay
  // service, not a real client queue behind a severed link" is the sentence
  // that created WP-30 in the first place.
  //
  // The topology is already correct for every one of them. What is missing is
  // the runtime, and when it lands each of these becomes a body, not a rewrite.
  // ===========================================================================

  it.todo(
    'PHASE 4: the Field client recognises the degraded state — PENDING: WP-26 Field client is an Android app on a physical handset; no automated Field runtime exists in this topology, and the field-lan-witness container is a NETWORK PROBE that must never be grown into a pretend Field app',
  );

  it.todo(
    'PHASE 5: allowed operations are queued locally on the Edge — PENDING (Edge ingress + transport): the durable queue now EXISTS (services/edge-runtime/src/modules/queue — WAL-journalled store, state machine, crash recovery), and the named volume, the storage probe and the restart orchestration are in place. What is still missing is a way to drive it: the Edge exposes no ingress but /health, so nothing can hand it an operation to queue, and it has no outbound client, so nothing can drain the queue to central once the link returns',
  );

  it.todo(
    'PHASE 6: some operations are EXPLICITLY REFUSED because policy expired or authority is unavailable — PENDING (Edge policy-lease lane): the Edge holds no policy cache and no lease with an expiry to run out. This phase matters as much as the successes — a degraded client that quietly allows everything has stopped enforcing, not survived an outage',
  );

  it.todo(
    'PHASE 7: authenticated reconnect and ORDERED synchronisation after restore — PENDING (Edge transport lane): there is no reconnect protocol and no sync ordering to assert. The cut/restore control and its timestamped record are ready to drive it',
  );

  it.todo(
    'PHASE 9: stale authority cannot rewrite current state — PENDING (Edge policy-lease lane + WP-29A leases): needs an Edge that can hold an authority decision across the outage and present it late',
  );

  it.todo(
    'PHASE 10: no duplicate incident ACTION after reconnect — PENDING (Edge transport + WP-27/28 device action): phase 8 above proves effectively-once for an EVENT through a real dropped response; the incident-action equivalent needs a genuine authenticated device signing through the device gateway, and this harness will not forge one',
  );

  it.todo(
    'PHASE 11: complete audit trail spanning the outage — PENDING (Edge transport lane): needs Edge-originated records to correlate with central ledger entries across the interval the harness already timestamps',
  );

  it.todo(
    'FIELD APP RESTART: documented and manual — WP-26 ships an Android application, not a container. The procedure is in docs/execution/WP-30-WAN-LOSS-HARNESS.md; automating it needs a device farm or an emulator lane, and a container pretending to be a handset would be worse than the manual step',
  );
});
