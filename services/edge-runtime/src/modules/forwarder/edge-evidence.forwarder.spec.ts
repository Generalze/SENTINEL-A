import { describe, expect, it, vi } from 'vitest';
import { EdgeEvidenceForwarder, mapStandingToOutcome } from './edge-evidence.forwarder';

/**
 * M3B §4 / §6 — THE MAPPING IS WHERE A FALSE TERMINAL STATE WOULD BE BORN.
 *
 * The Edge queue already separates `CENTRAL_RECEIVED` from `CENTRAL_APPLIED`
 * precisely so a transport acknowledgement cannot become a false commit. This
 * function is the one place that separation could be undone by a single
 * careless `case`, so it is a pure function and every row of its table is
 * asserted.
 *
 * The property, stated once:
 *
 *     EVIDENCE VERIFICATION MAY NEVER PRODUCE A TERMINAL STATE.
 *     Terminal states require an AUTHORITATIVE replay outcome.
 */

describe('mapping central standing onto the Edge queue', () => {
  // THE STATE AN EDGE SITS IN FOR AS LONG AS THE HANDSET STAYS AWAY. Central
  // holds the witness; the Field action is still awaiting authorised replay.
  it('treats recorded evidence as CENTRAL_RECEIVED, never as completion', () => {
    expect(mapStandingToOutcome('EVIDENCE_RECORDED')).toEqual({ kind: 'PROGRESS', progress: 'CENTRAL_RECEIVED' });
  });

  it('treats an authoritative replay that has only been received the same way', () => {
    expect(mapStandingToOutcome('AUTHORITATIVE_REPLAY_RECEIVED')).toEqual({
      kind: 'PROGRESS',
      progress: 'CENTRAL_RECEIVED',
    });
  });

  it('reports an in-flight replay as CENTRAL_APPLYING, which is still not terminal', () => {
    expect(mapStandingToOutcome('AUTHORITATIVE_REPLAY_APPLYING')).toEqual({
      kind: 'PROGRESS',
      progress: 'CENTRAL_APPLYING',
    });
  });

  // The only two answers permitted to settle an entry, and both come from the
  // authoritative replay record rather than from anything the evidence channel
  // did.
  it('settles APPLIED only from an authoritative applied outcome', () => {
    expect(mapStandingToOutcome('AUTHORITATIVE_REPLAY_APPLIED')).toMatchObject({ kind: 'SETTLE_APPLIED' });
  });

  it('settles REFUSED only from an authoritative deterministic rejection', () => {
    expect(mapStandingToOutcome('AUTHORITATIVE_REPLAY_REJECTED')).toMatchObject({ kind: 'SETTLE_REFUSED' });
  });

  // UNKNOWN is a truthful answer, not a retry hint dressed up as a result.
  it('keeps UNKNOWN unsettled', () => {
    expect(mapStandingToOutcome('UNKNOWN')).toMatchObject({ kind: 'UNKNOWN' });
  });

  it('treats an answer it does not recognise as UNKNOWN rather than as progress', () => {
    // A central that grew a new standing must not be able to advance this
    // Edge's queue by accident. Defaulting to UNKNOWN means an unfamiliar
    // answer costs a retry; defaulting to progress would cost correctness.
    expect(mapStandingToOutcome('SOMETHING_NEW' as never)).toMatchObject({ kind: 'UNKNOWN' });
  });

  // THE ONE THAT WOULD MATTER MOST IF IT EVER BROKE. Swept rather than listed,
  // so a standing added later is covered without anybody remembering to add it
  // here.
  it('NO evidence-only standing can ever settle an entry', () => {
    const evidenceOnly = ['EVIDENCE_RECORDED', 'AUTHORITATIVE_REPLAY_RECEIVED', 'AUTHORITATIVE_REPLAY_APPLYING', 'UNKNOWN'] as const;
    for (const standing of evidenceOnly) {
      const outcome = mapStandingToOutcome(standing);
      expect(outcome.kind, standing).not.toBe('SETTLE_APPLIED');
      expect(outcome.kind, standing).not.toBe('SETTLE_REFUSED');
    }
  });
});

/**
 * The HTTP paths, which are the OTHER place a terminal state could be
 * manufactured. The mapping table above is only reached on a 2xx.
 */
describe('what an unhappy HTTP answer may and may not settle', () => {
  function forwarderAnswering(response: { status: number; body?: unknown }): EdgeEvidenceForwarder {
    vi.stubGlobal('fetch', async () => ({
      status: response.status,
      ok: response.status >= 200 && response.status < 300,
      json: async () => response.body ?? {},
    }));
    const config = { values: { SENTINEL_CENTRAL_URL: 'https://central.example', EDGE_ID: 'edge-1', EDGE_KEY_ID: 'key-1' } } as never;
    const signer = { canSign: () => true, sign: () => ({ schema_version: 1 }) } as never;
    return new EdgeEvidenceForwarder(config, signer);
  }

  const bundle = { envelope: {}, payload: {}, receipt: {}, trustedTimeEvidence: null };

  // THE CORRECTION. An evidence conflict is stuck evidence, not a failed
  // operation: the Field action may still apply perfectly when the handset
  // reconnects, and settling here would mark it failed on the strength of an
  // Edge-side bookkeeping conflict.
  it('does NOT settle an evidence conflict, because terminal needs an authoritative outcome', async () => {
    const outcome = await forwarderAnswering({ status: 409 }).forward(bundle);
    expect(outcome.kind).toBe('UNKNOWN');
    expect(outcome.kind).not.toBe('SETTLE_REFUSED');
  });

  it('does not settle a refused evidence submission', async () => {
    const outcome = await forwarderAnswering({ status: 403 }).forward(bundle);
    expect(outcome.kind).toBe('UNKNOWN');
  });

  it('does not settle a server fault', async () => {
    const outcome = await forwarderAnswering({ status: 503 }).forward(bundle);
    expect(outcome.kind).toBe('UNKNOWN');
  });

  it('does not settle an unreadable answer', async () => {
    vi.stubGlobal('fetch', async () => ({ status: 200, ok: true, json: async () => { throw new Error('bad json'); } }));
    const config = { values: { SENTINEL_CENTRAL_URL: 'https://central.example' } } as never;
    const signer = { canSign: () => true, sign: () => ({}) } as never;
    const outcome = await new EdgeEvidenceForwarder(config, signer).forward(bundle);
    expect(outcome.kind).toBe('UNKNOWN');
  });

  // A severed WAN is the case the whole system exists for, not a failure.
  it('does not settle when the WAN is unreachable', async () => {
    vi.stubGlobal('fetch', async () => { throw new Error('ECONNREFUSED'); });
    const config = { values: { SENTINEL_CENTRAL_URL: 'https://central.example' } } as never;
    const signer = { canSign: () => true, sign: () => ({}) } as never;
    const outcome = await new EdgeEvidenceForwarder(config, signer).forward(bundle);
    expect(outcome).toMatchObject({ kind: 'UNKNOWN', reason: 'TRANSPORT_UNREACHABLE' });
  });

  // An Edge that cannot prove who it is must not forward at all.
  it('does not attempt to forward without a signing identity', async () => {
    const config = { values: { SENTINEL_CENTRAL_URL: 'https://central.example' } } as never;
    const signer = { canSign: () => false, sign: () => null } as never;
    const outcome = await new EdgeEvidenceForwarder(config, signer).forward(bundle);
    expect(outcome).toMatchObject({ kind: 'NOT_ATTEMPTED' });
  });
});
