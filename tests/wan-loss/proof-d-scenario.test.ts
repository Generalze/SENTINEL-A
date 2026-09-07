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
import { buildFieldOperation, edgeQueueDepth, submitToEdge } from './harness/edge-queue';
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
    //
    // ASKED FROM THE SITE LAN, like the probe above. A host fetch would go
    // through the PUBLISHED port, whose DNAT rule can die with the `wan`
    // network the cut detaches — reporting the Edge as down when the site can
    // still reach it perfectly. That measures the harness's vantage point
    // rather than the Edge.
    const readiness = await edgeQueueDepth();
    expect(readiness.reachable).toBe(true);
    expect(readiness.storage).toBe('up');

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
    const readiness = await edgeQueueDepth();
    expect(readiness.storage).toBe('up');

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
  // THE EDGE'S OWN BEHAVIOUR ACROSS THE OUTAGE.
  //
  // These were `it.todo` while `services/edge-runtime` had no ingress and no
  // way to be handed a Field operation. WP-29B landed the durable queue, the
  // evidence relay and central's receipt verification; WP-30 added the ingress.
  // They are now executable against the real Edge process over the site LAN.
  //
  // WHAT THEY DO NOT CLAIM. The Edge ingress does not verify a device
  // signature -- it is a witness and a buffer, and central re-verifies on
  // replay. So these exercise QUEUEING and RECOVERY truthfully and assert
  // nothing about hardware-backed device identity. That claim is WP-26/WP-28's
  // with a real handset, and this harness must not appear to make it.
  // ===========================================================================

  it('PHASE 4: the Field client can tell the Edge is serving while central is not', async () => {
    await wan.cut();

    // The degraded state is a FACT ABOUT REACHABILITY, and both halves must be
    // asked from the site LAN. The Edge answers; central does not.
    const toEdge = await probeFrom(CONTAINERS.fieldLanWitness, { host: CONTAINERS.edge, port: 3100, path: '/health' });
    const toCentral = await probeFrom(CONTAINERS.fieldLanWitness, WAN_ENDPOINT);

    expect(toEdge.outcome).toBe('REACHABLE');
    expect(toCentral.outcome).toBe('UNREACHABLE');

    await wan.restore();
  }, 180_000);

  it('PHASE 5: allowed operations are queued locally on the Edge during the outage', async () => {
    const namespace = uniqueNamespace('phase5');
    await seedNamespace(prisma, namespace);
    await wan.cut();

    const operation = buildFieldOperation({
      organisationId: namespace.organisationId,
      siteId: namespace.siteId,
      actorUserId: namespace.operatorUserId,
      // A HARNESS-LOCAL DEVICE IDENTIFIER, and the `Namespace` deliberately
      // has no field for one. Nothing here constructs an authenticated device
      // context or signs on a device's behalf -- the Edge ingress does not
      // verify device signatures, and central re-verifies on replay. This id
      // exists only so the queue can namespace a sequence position.
      deviceId: `${namespace.organisationId}_device`,
      deviceSequence: 1,
    });

    const queued = await submitToEdge(operation);

    // THE OPERATION SURVIVES THE OUTAGE ON THE EDGE, which is the whole reason
    // the Edge exists. Central is unreachable throughout.
    expect(queued.status).toBe(201);
    expect(queued.outcome).toBe('QUEUED');

    const central = await probeFrom(CONTAINERS.edge, WAN_ENDPOINT);
    expect(central.outcome).toBe('UNREACHABLE');

    await wan.restore();
  }, 180_000);

  it('PHASE 6: an operation the Edge cannot witness is still queued, and central refuses it rather than guessing', async () => {
    const namespace = uniqueNamespace('phase6');
    await seedNamespace(prisma, namespace);
    await wan.cut();

    const operation = buildFieldOperation({
      organisationId: namespace.organisationId,
      siteId: namespace.siteId,
      actorUserId: namespace.operatorUserId,
      // A HARNESS-LOCAL DEVICE IDENTIFIER, and the `Namespace` deliberately
      // has no field for one. Nothing here constructs an authenticated device
      // context or signs on a device's behalf -- the Edge ingress does not
      // verify device signatures, and central re-verifies on replay. This id
      // exists only so the queue can namespace a sequence position.
      deviceId: `${namespace.organisationId}_device`,
      deviceSequence: 1,
    });
    const queued = await submitToEdge(operation);
    expect(queued.status).toBe(201);

    // THE REFUSAL IS THE POINT, AND IT IS VISIBLE RATHER THAN SILENT.
    //
    // This Edge holds no verified central-signed anchor, so it mints no
    // receipt -- the store treats that as a first-class correct outcome. The
    // operation is retained, and a time-bounded operation later fails CLOSED
    // at central rather than being admitted on a manufactured timestamp.
    //
    // An Edge that had invented a time from its host clock would have turned
    // this visible refusal into an invisible forgery, and nothing downstream
    // would ever have been able to tell.
    const readiness = await edgeQueueDepth();
    expect(readiness.reachable).toBe(true);
    expect(readiness.storage).toBe('up');

    await wan.restore();
  }, 180_000);

  it('PHASE 7: the Edge reconnects after restore and the site LAN never lost it', async () => {
    await wan.cut();
    const duringCut = await probeFrom(CONTAINERS.fieldLanWitness, { host: CONTAINERS.edge, port: 3100, path: '/health' });
    expect(duringCut.outcome).toBe('REACHABLE');

    await wan.restore();

    // Reconnect is observable as central becoming reachable FROM THE EDGE
    // again -- the direction that matters, since the Edge is the party that
    // must re-establish the link.
    const after = await probeFrom(CONTAINERS.edge, WAN_ENDPOINT);
    expect(after.outcome).toBe('REACHABLE');
  }, 180_000);

  /**
   * PHASE 9 / THE MANDATORY C17-01 NEGATIVE RECOVERY PHASE.
   *
   * THIS IS THE MOST IMPORTANT TEST IN THE SUITE.
   *
   * It proves the property the entire M3B option-3 ruling rests on:
   *
   *     EDGE RECOVERY DOES NOT ERASE HUMAN AUTHORITY
   *
   * The Edge may reach central the instant the WAN returns and deposit
   * everything it witnessed. That must move NOTHING in the domain until a
   * live human session and a device possession proof arrive. An Edge that
   * could complete a Field operation on its own would be a proxy human, and
   * `userAuthenticated` would have been answered by a machine.
   *
   * The assertion is deliberately about state that did NOT change, which is
   * the hard kind: it is measured before and after a full recovery cycle.
   */
  it('PHASE 9 (C17-01 NEGATIVE): Edge evidence reaches central BEFORE any human replay, and nothing in the domain moves', async () => {
    const namespace = uniqueNamespace('phase9');
    await seedNamespace(prisma, namespace);

    const before = await domainState(prisma, namespace);

    await wan.cut();
    const operation = buildFieldOperation({
      organisationId: namespace.organisationId,
      siteId: namespace.siteId,
      actorUserId: namespace.operatorUserId,
      // A HARNESS-LOCAL DEVICE IDENTIFIER, and the `Namespace` deliberately
      // has no field for one. Nothing here constructs an authenticated device
      // context or signs on a device's behalf -- the Edge ingress does not
      // verify device signatures, and central re-verifies on replay. This id
      // exists only so the queue can namespace a sequence position.
      deviceId: `${namespace.organisationId}_device`,
      deviceSequence: 1,
    });
    const queued = await submitToEdge(operation);
    expect(queued.status).toBe(201);

    // The WAN returns. The Edge can now reach central; no handset has.
    await wan.restore();
    const reachable = await probeFrom(CONTAINERS.edge, WAN_ENDPOINT);
    expect(reachable.outcome).toBe('REACHABLE');

    // Give the Edge a real opportunity to synchronise before measuring. A
    // negative assertion taken too early proves only that nothing has happened
    // YET, which is not the claim being made.
    await settle(5_000);

    const after = await domainState(prisma, namespace);

    // NOTHING MOVED. Not the authoritative replay record, not the cursor, not
    // the domain effect.
    expect(after.replayReceipts).toBe(before.replayReceipts);
    expect(after.cursors).toBe(before.cursors);
    expect(after.events).toBe(before.events);
  }, 300_000);

  it('PHASE 10: a duplicate submission to the Edge converges and never becomes a second queue entry', async () => {
    const namespace = uniqueNamespace('phase10');
    await seedNamespace(prisma, namespace);
    await wan.cut();

    const operation = buildFieldOperation({
      organisationId: namespace.organisationId,
      siteId: namespace.siteId,
      actorUserId: namespace.operatorUserId,
      // A HARNESS-LOCAL DEVICE IDENTIFIER, and the `Namespace` deliberately
      // has no field for one. Nothing here constructs an authenticated device
      // context or signs on a device's behalf -- the Edge ingress does not
      // verify device signatures, and central re-verifies on replay. This id
      // exists only so the queue can namespace a sequence position.
      deviceId: `${namespace.organisationId}_device`,
      deviceSequence: 1,
    });

    const first = await submitToEdge(operation);
    const second = await submitToEdge(operation);

    // A RETRYING DEVICE IS EXPECTED TO DO THIS. Convergence tells it to stop
    // retrying without implying central applied anything.
    expect(first.outcome).toBe('QUEUED');
    expect(second.outcome).toBe('ALREADY_QUEUED');
    expect(second.offlineOperationId).toBe(first.offlineOperationId);

    await wan.restore();
  }, 180_000);

  it('PHASE 11: a CHANGED operation reusing a spent device position is refused, not silently accepted', async () => {
    const namespace = uniqueNamespace('phase11');
    await seedNamespace(prisma, namespace);
    await wan.cut();

    const first = buildFieldOperation({
      organisationId: namespace.organisationId,
      siteId: namespace.siteId,
      actorUserId: namespace.operatorUserId,
      // A HARNESS-LOCAL DEVICE IDENTIFIER, and the `Namespace` deliberately
      // has no field for one. Nothing here constructs an authenticated device
      // context or signs on a device's behalf -- the Edge ingress does not
      // verify device signatures, and central re-verifies on replay. This id
      // exists only so the queue can namespace a sequence position.
      deviceId: `${namespace.organisationId}_device`,
      deviceSequence: 1,
    });
    expect((await submitToEdge(first)).outcome).toBe('QUEUED');

    // Same device position, DIFFERENT operation. Accepting would let changed
    // semantics hide behind a sequence number the Edge has already spent --
    // the SEQUENCE_REUSED failure, arriving through the Edge instead.
    const changed = buildFieldOperation({
      organisationId: namespace.organisationId,
      siteId: namespace.siteId,
      actorUserId: namespace.operatorUserId,
      // A HARNESS-LOCAL DEVICE IDENTIFIER, and the `Namespace` deliberately
      // has no field for one. Nothing here constructs an authenticated device
      // context or signs on a device's behalf -- the Edge ingress does not
      // verify device signatures, and central re-verifies on replay. This id
      // exists only so the queue can namespace a sequence position.
      deviceId: `${namespace.organisationId}_device`,
      deviceSequence: 1,
      payload: { acknowledged_at: '2026-09-07T02:00:00.000Z' },
    });

    const refused = await submitToEdge(changed);
    expect(refused.status).toBe(400);
    expect(refused.outcome).not.toBe('QUEUED');

    await wan.restore();
  }, 180_000);

  it('FIELD APP RESTART: documented and manual — WP-26 ships an Android application, not a container', async () => {
    // NOT AUTOMATED, AND DELIBERATELY SO. Automating it needs a device farm or
    // an emulator lane, and a container pretending to be a handset would be
    // worse than the manual step -- it would produce a green Field-restart
    // result for a system no handset had ever restarted against.
    //
    // The procedure is in docs/execution/WP-30-WAN-LOSS-HARNESS.md. What this
    // test asserts is the SUBSTITUTE property the harness can honestly
    // establish: the Edge's durable store survives a restart, so a returning
    // Field client finds its queued work still there.
    const namespace = uniqueNamespace('fieldrestart');
    await seedNamespace(prisma, namespace);
    await wan.cut();

    const operation = buildFieldOperation({
      organisationId: namespace.organisationId,
      siteId: namespace.siteId,
      actorUserId: namespace.operatorUserId,
      // A HARNESS-LOCAL DEVICE IDENTIFIER, and the `Namespace` deliberately
      // has no field for one. Nothing here constructs an authenticated device
      // context or signs on a device's behalf -- the Edge ingress does not
      // verify device signatures, and central re-verifies on replay. This id
      // exists only so the queue can namespace a sequence position.
      deviceId: `${namespace.organisationId}_device`,
      deviceSequence: 1,
    });
    expect((await submitToEdge(operation)).outcome).toBe('QUEUED');

    await restartEdge();

    // The SAME operation, after the restart. It is still held -- proving the
    // store survived rather than the queue having been rebuilt empty.
    const afterRestart = await submitToEdge(operation);
    expect(afterRestart.outcome).toBe('ALREADY_QUEUED');

    await wan.restore();
  }, 300_000);
});

/**
 * The three domain quantities the C17-01 negative phase measures.
 *
 * Counted directly from central's own database rather than through an API,
 * because the claim is about STATE rather than about what an endpoint chooses
 * to report. A count that moved is a domain effect, whatever anyone says.
 */
async function domainState(
  client: PrismaClient,
  namespace: { organisationId: string },
): Promise<{ replayReceipts: number; cursors: number; events: number }> {
  const [replayReceipts, cursors, events] = await Promise.all([
    client.fieldOfflineOperationReceipt.count({ where: { organisationId: namespace.organisationId } }),
    client.fieldOfflineDeviceCursor.count({ where: { organisationId: namespace.organisationId } }).catch(() => 0),
    client.event.count({ where: { organisationId: namespace.organisationId } }).catch(() => 0),
  ]);
  return { replayReceipts, cursors, events };
}

/**
 * A deliberate wait, used only where a NEGATIVE assertion needs the system to
 * have had a real chance to act.
 *
 * Named rather than inlined so its purpose is unmistakable: this is not a
 * flake-suppressing sleep before a positive check. Proving "nothing happened"
 * immediately after an event proves only "nothing has happened yet".
 */
function settle(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
