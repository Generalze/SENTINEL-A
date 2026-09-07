/**
 * WP-30 — THE MECHANISM PROOF. QUALIFYING THE INSTRUMENT BEFORE TRUSTING IT.
 *
 * These tests do not test Sentinel. They test the HARNESS, and they exist
 * because Proof D is an argument built on top of one claim:
 *
 *     "central was genuinely unreachable from the Edge between T1 and T2,
 *      while the Edge and its site LAN kept working."
 *
 * Every scenario in the WAN-loss suite inherits its credibility from that
 * claim. If the cut is not real, a green Proof D is worse than no Proof D: it
 * is a false negative on the exact risk the milestone exists to retire, and it
 * is one that nothing downstream would ever catch, because everything
 * downstream ASSUMES this.
 *
 * So the instrument is calibrated first, against four properties. Each one is
 * a way the harness could be silently wrong:
 *
 *   1. Before the cut, the Edge can reach central. Without this, "unreachable
 *      after the cut" is not evidence of anything — a route that never worked
 *      is unreachable for free.
 *   2. After the cut, it cannot. And it fails as a BLACK HOLE, not as a name
 *      lookup, because a WAN outage does not un-name the datacentre and an
 *      Edge tested only against DNS failure has not been tested against WAN
 *      failure.
 *   3. The cut did not take the Edge with it. The process, the site LAN and
 *      the durable store all survive — asserted, not assumed. If the cut
 *      killed the Edge, every "Edge continued operating" assertion downstream
 *      would be vacuously true of a corpse.
 *   4. Restore restores.
 *
 * NOT ONE ASSERTION HERE READS A DURATION.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CONTAINERS, attachedNetworks, containerFacts, probeFrom, WAN_NETWORK } from './harness/docker';
import { ENDPOINTS, assertSchemaDeployed } from './harness/topology';
import { edgeQueueDepth } from './harness/edge-queue';
import { WanControl } from './harness/wan-control';

/**
 * The gate. Mirrors the `PROOF_A_LIVE` precedent exactly.
 *
 * This suite builds two images, starts nine containers, severs networks and
 * restarts services. It must never join the ordinary `pnpm -r test` sweep,
 * where it would contend with every other suite for the shared database and
 * turn a two-minute run into a twenty-minute one. `describe.skip` rather than
 * an early return, so an ungated run reports the tests as SKIPPED — visibly
 * not run — instead of reporting a pass it never earned.
 */
const live = process.env.WP30_WAN_LOSS_LIVE === '1';
const describeLive = live ? describe : describe.skip;

/**
 * How the Edge names central. This is the pinned `/etc/hosts` entry from the
 * compose file, and using the NAME here rather than the address is the point:
 * it is what proves the post-cut failure is a routing failure and not a
 * resolution one.
 */
const WAN_ENDPOINT = { host: 'sentinel-wan', port: 8080, path: '/health' };

describeLive('WP-30 — WAN cut/restore mechanism (qualifies the harness itself)', () => {
  const wan = new WanControl();

  beforeAll(async () => {
    await assertSchemaDeployed();
    // Start from a known state rather than from whatever a previous failure
    // left behind. A suite that began with an unknown link state would be
    // asserting against a topology it had not established.
    await wan.ensureConnected();
  }, 300_000);

  afterAll(async () => {
    await wan.ensureConnected();
  }, 300_000);

  it('before the cut: the Edge reaches central through the WAN, and the site LAN reaches the Edge', async () => {
    const toCentral = await probeFrom(CONTAINERS.edge, WAN_ENDPOINT);
    expect(toCentral.outcome).toBe('REACHABLE');

    const lanToEdge = await probeFrom(CONTAINERS.fieldLanWitness, { host: CONTAINERS.edge, port: 3100, path: '/health' });
    expect(lanToEdge.outcome).toBe('REACHABLE');

    // The baseline is worth stating explicitly: this is the state the outage
    // is a departure FROM, and a scenario that could not establish it would
    // have nothing to compare against.
    expect(await wan.state()).toBe('CONNECTED');
  }, 120_000);

  it('the cut makes central unreachable FROM THE EDGE, and it fails as a black hole rather than a name lookup', async () => {
    const cut = await wan.cut();
    try {
      expect(cut.to).toBe('CUT');
      // The daemon's own view. `docker network disconnect` returning zero is
      // not evidence the interface is gone; this is.
      expect(await attachedNetworks(CONTAINERS.edge)).not.toContain(WAN_NETWORK);

      const toCentral = await probeFrom(CONTAINERS.edge, WAN_ENDPOINT);
      expect(toCentral.outcome).toBe('UNREACHABLE');

      // THE DISTINCTION THAT MAKES THIS A WAN OUTAGE.
      //
      // `ENOTFOUND` would mean the Edge could not RESOLVE the endpoint —
      // which is what a naive `docker network disconnect` produces, because
      // detaching also removes the network's names from the container's
      // embedded DNS. That is a weaker failure, and every retry/backoff
      // classifier ever written routes it differently from a network failure.
      // The compose file pins `sentinel-wan` in the Edge's `/etc/hosts`, a
      // FILE, which outlives the interface. So the name still resolves, the
      // route is gone, and the Edge learns this the way it would learn it from
      // a real severed uplink: nothing comes back.
      expect(toCentral.detail).not.toBe('ENOTFOUND');
      expect(['ETIMEDOUT', 'EHOSTUNREACH', 'ENETUNREACH']).toContain(toCentral.detail);
    } finally {
      await wan.restore();
    }
  }, 120_000);

  it('the cut does NOT take down the Edge: same process, site LAN intact, durable store still writable', async () => {
    const before = await containerFacts(CONTAINERS.edge);
    const cut = await wan.cut();
    try {
      // 1. THE PROCESS WAS NEVER SIGNALLED. An unchanged pid is the load-
      //    bearing assertion; `status: running` alone would be equally true of
      //    an Edge that died and was restarted by the daemon, which is why
      //    both compose services also set `restart: 'no'`.
      expect(cut.edge.status).toBe('running');
      expect(cut.edge.pid).toBe(before.pid);
      expect(cut.edge.restartCount).toBe(before.restartCount);
      expect(cut.edge.startedAt).toBe(before.startedAt);

      // 2. FIELD ↔ EDGE LOCAL CONNECTIVITY SURVIVES, asked from the site LAN
      //    rather than from the host — a published port would answer even if
      //    the `field` network had collapsed, and would prove nothing.
      const lanToEdge = await probeFrom(CONTAINERS.fieldLanWitness, { host: CONTAINERS.edge, port: 3100, path: '/health' });
      expect(lanToEdge.outcome).toBe('REACHABLE');

      // 3. EDGE LOCAL STORAGE SURVIVES, ON THE EDGE'S OWN EVIDENCE.
      //    `EdgeQueueStorageProbe` reports `queue_storage` by testing W_OK on
      //    the durable queue directory, and it is the one dependency whose
      //    failure takes Edge out of service. Reading the Edge's own readiness
      //    is a stronger claim than the harness inspecting a volume: it is the
      //    Edge saying it can still keep an operation safe.
      //    ASKED FROM THE SITE LAN. A host fetch reaches the PUBLISHED port,
      //    whose DNAT rule can die with the `wan` network this very test has
      //    just detached -- so it would report the Edge as down while the site
      //    still reaches it perfectly, and the test would "fail" by measuring
      //    the harness's own vantage point.
      const readiness = await edgeQueueDepth();
      expect(readiness.storage).toBe('up');

      // 4. AND THE EDGE IS STILL SERVING AT ALL. Liveness touches no
      //    dependency, so this is specifically "the process is answering",
      //    which is the claim "Edge continues operating" rests on.
      const liveness = await probeFrom(CONTAINERS.fieldLanWitness, {
        host: CONTAINERS.edge,
        port: 3100,
        path: '/health',
      });
      expect(liveness.outcome).toBe('REACHABLE');
    } finally {
      await wan.restore();
    }
  }, 120_000);

  it('restore returns the route, and the harness holds an ordered, timestamped record of the interval', async () => {
    const cut = await wan.cut();
    const restored = await wan.restore();

    const toCentral = await probeFrom(CONTAINERS.edge, WAN_ENDPOINT);
    expect(toCentral.outcome).toBe('REACHABLE');

    // THE HARNESS IS THE AUTHORITY ON THE INTERVAL, and this is where that is
    // asserted rather than merely claimed. Central cannot testify to an
    // interval it could not observe: a silence in its log is equally
    // consistent with an outage, an idle client, a crashed client and a
    // logging failure. The party that CAUSED the interval is the only one that
    // can attest to it.
    //
    // ORDER, NOT ELAPSED TIME. `cut.at <= restored.at` is a claim about
    // sequence and is stable on a loaded CI runner; "the outage lasted N ms"
    // is a claim about speed and is not. Nothing in this suite asserts the
    // second.
    expect(cut.to).toBe('CUT');
    expect(restored.to).toBe('CONNECTED');
    expect(Date.parse(cut.at)).toBeLessThanOrEqual(Date.parse(restored.at));

    const transitions = wan.transitions();
    expect(transitions.at(-2)?.to).toBe('CUT');
    expect(transitions.at(-1)?.to).toBe('CONNECTED');
  }, 120_000);

  it('refuses to cut a link that is already cut, and to restore one that was never cut', async () => {
    // Not defensive programming for its own sake. An idempotent cut is a trap:
    // a scenario that cut twice by accident would pass, and its single restore
    // would leave the link in whichever state the bookkeeping happened to land
    // on — silently corrupting every test that ran afterwards. A scenario is
    // either taking the link down or it is not, and the harness says which.
    await expect(wan.restore()).rejects.toThrow(/already CONNECTED/);

    await wan.cut();
    try {
      await expect(wan.cut()).rejects.toThrow(/already CUT/);
    } finally {
      await wan.restore();
    }
  }, 120_000);
});
