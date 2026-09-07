/**
 * WP-30 — THE ASYMMETRIC FAILURE CONTROL, AND ITS JOURNAL.
 *
 * `WanControl` severs the link symmetrically: nothing leaves, nothing returns,
 * central never hears the request. That is a real outage and it covers most of
 * Proof D.
 *
 * IT CANNOT COVER THE PHASE THE WHOLE ARGUMENT TURNS ON.
 *
 *     THE REQUEST ARRIVES. CENTRAL COMMITS. THE RESPONSE IS LOST.
 *
 * This is the only state in which the client's knowledge and the server's
 * state genuinely diverge. Everywhere else the two disagree only about
 * timing; here the client holds NO evidence its operation happened and central
 * holds an effect. Every duplicate-suppression mechanism in the system exists
 * for this window, and a proof that never enters it has not exercised any of
 * them — it has exercised retry-after-failure, which is a different and much
 * easier thing.
 *
 * A symmetric cut cannot produce it, because a symmetric cut also stops the
 * request. Producing it requires something ON the path that treats the two
 * directions differently, which is `infrastructure/wan-link/wan-link.mjs`.
 * This class is its typed client.
 *
 * WHY THE JOURNAL IS THE WITNESS, AND NOT CENTRAL'S LOG
 * ----------------------------------------------------
 * After the drop, ask the three parties what happened:
 *
 *   the client   — "my socket died." It cannot distinguish a request that
 *                  never arrived from one that committed. That ambiguity is
 *                  not a defect; it is the situation being tested.
 *   central      — "I committed, and I emitted a response." Emitting is the
 *                  last thing central can observe. It has no way to know the
 *                  response was destroyed, and no honest log line saying so.
 *   the wan-link — "I forwarded the request at T1, upstream answered 201 at
 *                  T2, and I destroyed that answer at T3."
 *
 * Only the third is testimony. So the journal is what a scenario cites when it
 * asserts that the phase-8 window actually occurred, rather than inferring it
 * from a client error that a mere connection refusal would produce just as
 * convincingly. Without it, a phase-8 test could pass on a topology where the
 * request never landed at all — proving nothing while appearing to prove the
 * hardest case.
 */

export type WanLinkMode = 'pass' | 'drop_response' | 'drop_response_once' | 'blackhole';

export interface WanLinkState {
  readonly mode: WanLinkMode;
  /** ISO instant the mode was last set. */
  readonly since: string;
  readonly journal_entries: number;
  readonly upstream: string;
  readonly observed_at: string;
}

/**
 * One disposition, as the link recorded it.
 *
 * Every temporal field is an INSTANT. There is no elapsed-time field and none
 * may be added: a scenario that needs an interval has two instants and can
 * name them, and a scenario that wants to assert on a duration is asking a
 * question whose answer depends on CI load rather than on the system.
 */
export interface WanLinkJournalEntry {
  readonly seq: number;
  readonly at: string;
  readonly mode: WanLinkMode;
  readonly method: string;
  readonly path: string;
  readonly disposition: 'RESPONSE_DELIVERED' | 'RESPONSE_DROPPED' | 'NOT_FORWARDED' | 'UPSTREAM_ERROR';
  readonly upstream_status: number | null;
  readonly upstream_response_bytes?: number;
  readonly request_forwarded_at: string | null;
  readonly upstream_responded_at: string | null;
  readonly decided_at: string;
}

export class WanLinkControl {
  /**
   * @param controlUrl the CONTROL plane, published for the harness alone.
   * @param dataUrl    the DATA plane — where a client behind the WAN sends.
   *
   * Two ports, not one path on one port. A control endpoint on the data plane
   * would be indistinguishable from a real request to central, and would mean
   * anything behind the WAN could change the state of the WAN. In the compose
   * topology the Edge has no route to the control plane at all: a node under
   * test must not be able to operate the instrument measuring it.
   */
  constructor(
    private readonly controlUrl: string,
    readonly dataUrl: string,
  ) {}

  async state(): Promise<WanLinkState> {
    return this.controlRequest<WanLinkState>('GET', '/control/state');
  }

  /**
   * Set the mode and VERIFY it took.
   *
   * The response is re-read rather than assumed because a scenario whose
   * `drop_response_once` silently failed to arm would send its request, get a
   * perfectly good 201 back, and then assert convergence on a duplicate that
   * was never created. It would pass. Loudly failing to arm is the only
   * acceptable outcome.
   */
  async setMode(mode: WanLinkMode): Promise<WanLinkState> {
    const applied = await this.controlRequest<{ mode: WanLinkMode }>('POST', '/control/mode', { mode });
    if (applied.mode !== mode) {
      throw new Error(`wan-link refused mode ${mode}; it reports ${applied.mode}`);
    }
    return this.state();
  }

  async journal(): Promise<WanLinkJournalEntry[]> {
    const body = await this.controlRequest<{ entries: WanLinkJournalEntry[] }>('GET', '/control/journal');
    return body.entries;
  }

  /**
   * Clear the journal so a scenario reads only its own dispositions.
   *
   * Sequence numbers deliberately do NOT reset — see the note in
   * `wan-link.mjs`. Every scenario owns its own `(org, site, user, device)`
   * namespace, and its own slice of this journal is the network-layer
   * equivalent.
   */
  async resetJournal(): Promise<void> {
    await this.controlRequest('POST', '/control/journal/reset');
  }

  /**
   * Restore ordinary forwarding. For `afterEach`.
   *
   * A scenario that fails while the link is in `drop_response` would otherwise
   * silently drop every response for every test after it, and the resulting
   * cascade would bury the one real failure under a dozen consequences.
   */
  async reset(): Promise<void> {
    await this.setMode('pass');
    await this.resetJournal();
  }

  private async controlRequest<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
    const response = await fetch(`${this.controlUrl}${path}`, {
      method,
      headers: body === undefined ? undefined : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(`wan-link control ${method} ${path} -> HTTP ${response.status}: ${await response.text()}`);
    }
    return (await response.json()) as T;
  }
}
