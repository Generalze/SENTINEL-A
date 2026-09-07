/**
 * WP-30 — `cutWan()` / `restoreWan()`. THE OUTAGE, AS A TYPED OPERATION.
 *
 * WHAT THE CUT ACTUALLY IS
 * ------------------------
 *     docker network disconnect sentinel-wp30_wan sentinel-wp30-edge
 *
 * The Edge's WAN interface is removed from the running container. Not a
 * proxy toggle, not an environment variable, not a boolean any code under test
 * can read, and — this is the part that matters — not something the Edge can
 * distinguish from a real outage, because it is not a simulation of one. There
 * is no route. Packets have nowhere to go.
 *
 * WHY THE HARNESS, AND NOT A LOG, IS THE AUTHORITY ON THE INTERVAL
 * ---------------------------------------------------------------
 * The obvious way to establish "the WAN was down from T1 to T2" is to read
 * central's logs and find the gap. That reasoning is circular. Central cannot
 * observe an interval during which nothing reached it; a silence in its log is
 * equally consistent with an outage, an idle client, a crashed client, a
 * client that had nothing to say, and a logging failure. Absence of evidence
 * is being read as evidence, in the one place the whole proof turns on.
 *
 * The only party that can testify to the interval is the party that CAUSED it.
 * So this class is the record: every transition is appended, in order, with the
 * ISO instant at which the daemon confirmed it, and `transitions()` is what a
 * scenario cites when it needs to say when the outage began and ended.
 *
 * TIMESTAMPS, NEVER DURATIONS
 * ---------------------------
 * Transitions carry instants. This file computes no elapsed time and exposes
 * no "how long was it down", because there is no assertion worth writing that
 * needs one: "the WAN was cut at T1 and restored at T2, and this operation was
 * attempted between them" is a claim about ORDER, which is stable on a loaded
 * CI runner, while "the WAN was down for 4 seconds" is a claim about SPEED,
 * which is not. TI-01/02/03 removed timing dependence from this repository's
 * suites; a WAN-loss harness is the easiest place in the codebase to put it
 * back, and this is the file where that would happen.
 *
 * VERIFIED, NOT ASSUMED
 * ---------------------
 * Neither operation trusts its own exit code. `docker network disconnect` can
 * return zero having done nothing interesting, and a harness whose "cut" was a
 * command that ran is a harness that will one day report a passing Proof D
 * against a fully connected network. Both operations re-read the container's
 * attachments from the daemon afterwards and throw if reality disagrees.
 */

import {
  CONTAINERS,
  WAN_NETWORK,
  attachedNetworks,
  containerFacts,
  docker,
  type ContainerRuntimeFacts,
} from './docker';

export type WanState = 'CONNECTED' | 'CUT';

export interface WanTransition {
  readonly to: WanState;
  /** ISO instant at which the daemon confirmed the change. Never a duration. */
  readonly at: string;
  /**
   * The Edge's runtime facts immediately after the transition.
   *
   * Carried because the single most important thing a cut must NOT do is take
   * the Edge with it. An unchanged pid across a cut is the proof that the
   * process was never signalled — `status: running` alone would also be true
   * of an Edge that died and was restarted.
   */
  readonly edge: ContainerRuntimeFacts;
}

export class WanCutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WanCutError';
  }
}

export class WanControl {
  private readonly log: WanTransition[] = [];

  /**
   * The daemon's answer, not a cached one.
   *
   * Deliberately not memoised. A harness that remembered what it had done and
   * reported that back would answer "CUT" just as confidently after a
   * `docker network connect` typed in another terminal, or after a compose
   * recreate silently re-attached the container. The ground truth for "is
   * there a route" is the container's attachment list, so that is what is read
   * every time.
   */
  async state(): Promise<WanState> {
    const networks = await attachedNetworks(CONTAINERS.edge);
    return networks.includes(WAN_NETWORK) ? 'CONNECTED' : 'CUT';
  }

  /**
   * SEVER THE WAN.
   *
   * Refuses when already cut rather than succeeding quietly. An idempotent cut
   * sounds convenient and is a trap: a scenario that cut twice by accident
   * would pass, and its restore would leave the link in whichever state the
   * bookkeeping happened to land on. A scenario is either taking the link down
   * or it is not, and the harness should say which.
   */
  async cut(): Promise<WanTransition> {
    const before = await this.state();
    if (before === 'CUT') {
      throw new WanCutError(`WAN is already CUT — refusing to cut twice (edge is not attached to ${WAN_NETWORK})`);
    }

    await docker(['network', 'disconnect', WAN_NETWORK, CONTAINERS.edge]);

    const after = await this.state();
    if (after !== 'CUT') {
      throw new WanCutError(
        `disconnect reported success but ${CONTAINERS.edge} is still attached to ${WAN_NETWORK}. ` +
          `The suite must not proceed: every downstream assertion would be made against a connected network.`,
      );
    }

    return this.append('CUT');
  }

  /**
   * RESTORE THE WAN.
   *
   * The Edge is given whatever address the network's IPAM hands out; only the
   * `wan-link`'s address is pinned, and only because the Edge's `/etc/hosts`
   * names it. Nothing in the topology addresses the Edge by IP, so pinning one
   * here would be a constraint with no purpose that could only ever fail.
   */
  async restore(): Promise<WanTransition> {
    const before = await this.state();
    if (before === 'CONNECTED') {
      throw new WanCutError(`WAN is already CONNECTED — refusing to restore a link that was never cut`);
    }

    await docker(['network', 'connect', WAN_NETWORK, CONTAINERS.edge]);

    const after = await this.state();
    if (after !== 'CONNECTED') {
      throw new WanCutError(
        `connect reported success but ${CONTAINERS.edge} is not attached to ${WAN_NETWORK}`,
      );
    }

    return this.append('CONNECTED');
  }

  /**
   * THE AUTHORITATIVE RECORD OF THE OUTAGE.
   *
   * Returned as a copy, because a scenario that could mutate the record could
   * make the harness testify to an interval that never happened — and this
   * record exists precisely because nothing else in the system can testify to
   * it truthfully.
   */
  transitions(): readonly WanTransition[] {
    return [...this.log];
  }

  /**
   * Put the link back if a scenario left it down, and say whether it had to.
   *
   * For `afterEach`. A test that fails between `cut()` and `restore()` would
   * otherwise leave the WAN severed for every test after it, and the resulting
   * cascade of failures would bury the ONE real failure under a dozen
   * consequences of it. Returns whether a repair was needed so a suite can
   * surface that rather than silently tidying up — a harness that quietly
   * fixed a leaked cut would be hiding a scenario with no teardown path.
   */
  async ensureConnected(): Promise<{ repaired: boolean; at: string }> {
    if ((await this.state()) === 'CONNECTED') {
      return { repaired: false, at: new Date().toISOString() };
    }
    const transition = await this.restore();
    return { repaired: true, at: transition.at };
  }

  private async append(to: WanState): Promise<WanTransition> {
    const transition: WanTransition = {
      to,
      at: new Date().toISOString(),
      edge: await containerFacts(CONTAINERS.edge),
    };
    this.log.push(transition);
    return transition;
  }
}
