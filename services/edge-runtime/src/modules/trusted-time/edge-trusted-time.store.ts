import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Inject, Injectable, Logger, type Provider } from '@nestjs/common';
import type { SignedEdgeTrustedTimeAnchor } from '@sentinel/contracts';
import { EdgeConfigService } from '../../config/config.service';

/** DI token for the anchor store. */
export const EDGE_TRUSTED_TIME_ANCHOR_STORE = Symbol('EDGE_TRUSTED_TIME_ANCHOR_STORE');

/**
 * ============================================================================
 * WP-29B / FW2-11 — WHERE THE SIGNED ANCHOR RESTS.
 *
 * Round 1 stopped at this file: an anchor persisted as plain JSON hands anyone
 * who can write it the power to choose what time Edge believes it is, and there
 * was no primitive in the repository that could make a persisted anchor
 * independently verifiable. The ruling supplied one, and this is what changed:
 *
 *   WHAT IS STORED IS THE SIGNED STATEMENT AND ITS SIGNATURE, BYTE FOR BYTE,
 *   AND NOTHING DERIVED FROM THEM.
 *
 * No cached `trusted_now`, no remembered expiry, no pre-computed offset, no
 * "verified: true" flag. Every one of those would be a value produced BY
 * verification that would then be trusted WITHOUT verification after a restart
 * — which is exactly the property the signature exists to remove. The store
 * therefore has no opinion at all: it is a byte pipe, and
 * `EdgeTrustedTimeAnchorVerifier` re-runs the entire chain on every load.
 *
 * THE STORE IS NOT A TRUST BOUNDARY, AND THAT IS THE ACHIEVEMENT.
 *
 * An attacker with write access to the anchor file can delete it, truncate it,
 * replace it with an older anchor, or replace it with one issued to a different
 * Edge. Every one of those is caught: a missing or corrupt file refuses at the
 * parse, an older anchor refuses at the lifetime check, another Edge's anchor
 * refuses at the binding check, and any edit whatsoever refuses at the
 * signature. What they cannot do is make Edge believe a time central never
 * asserted, and that is the whole point.
 * ============================================================================
 */
export interface EdgeTrustedTimeAnchorStore {
  /**
   * The candidate to resume with, as UNVERIFIED bytes, or `null`.
   *
   * The return type is deliberately `unknown`. Typing it as the parsed anchor
   * would let a caller skip the verifier and use it — and a store that hands
   * back something already shaped like a trusted value is a store that invites
   * exactly that. What comes off a disk is a candidate, and it stays a
   * candidate until the chain says otherwise.
   */
  load(): Promise<unknown>;
  /** Persist an anchor central signed. May legitimately do nothing. */
  save(anchor: SignedEdgeTrustedTimeAnchor): Promise<void>;
  /** Forget the persisted anchor. Never an error when there was none. */
  clear(): Promise<void>;
}

/**
 * THE VOLATILE STORE, KEPT DELIBERATELY.
 *
 * The ruling is explicit that this must not be deleted because persistence now
 * exists, and the reason is that it is not a placeholder — it is the ABSENCE OF
 * TRUST behaviour, and it is the correct configuration for a deployment that
 * has not pinned a verification keyring, for an Edge whose queue directory is
 * not on durable storage, and for every test that wants a cold start.
 *
 * An Edge wired with this holds trusted time only for as long as its process
 * lives. That is a real cost and a completely safe one: after a restart it
 * emits `edge_trusted_time: null`, central refuses the five time-bounded kinds
 * at NO_TRUSTWORTHY_TIME_WITNESS, and nothing is forged.
 */
@Injectable()
export class VolatileEdgeTrustedTimeAnchorStore implements EdgeTrustedTimeAnchorStore {
  async load(): Promise<unknown> {
    return null;
  }

  async save(_anchor: SignedEdgeTrustedTimeAnchor): Promise<void> {
    // Intentionally nothing.
  }

  async clear(): Promise<void> {
    // Intentionally nothing.
  }
}

/** The file the persistent store keeps, inside the configured queue directory. */
export const EDGE_TRUSTED_TIME_ANCHOR_FILENAME = 'trusted-time-anchor.json';

/**
 * THE PERSISTENT STORE. Same-boot restart recovery, and nothing more.
 *
 * WHY THE WRITE IS ATOMIC
 * -----------------------
 * Write-to-temp-then-rename, because a partially written anchor is the one
 * failure mode that costs something real. `rename` within a directory is atomic
 * on every platform Sentinel targets, so a reader sees either the whole old
 * anchor or the whole new one. Without it, an Edge power-cycled mid-write would
 * come back to a truncated file — refused, correctly, but having thrown away a
 * perfectly good anchor it was holding a moment earlier, and taking the site's
 * ability to witness with it until central is reachable again.
 *
 * WHY A FAILED WRITE IS NOT AN ERROR THE CALLER SEES
 * --------------------------------------------------
 * Persistence is an OPTIMISATION over the volatile behaviour: it saves a
 * re-anchoring round trip after a restart. It is never what makes an anchor
 * trustworthy — the signature is. So a write that fails is logged and swallowed,
 * because the alternative is throwing on the path that runs every time central
 * refreshes the anchor, and an Edge that fell over because its disk was full
 * would have converted a degraded state into an outage.
 *
 * WHY A FAILED READ IS SILENT
 * ---------------------------
 * `load` answers `null` for a missing file, an unreadable one, or bytes that
 * are not JSON. All three mean the same thing to the verifier — there is no
 * candidate — and distinguishing them for a caller would be an oracle over the
 * filesystem of a box on a customer LAN.
 */
@Injectable()
export class FileSystemEdgeTrustedTimeAnchorStore implements EdgeTrustedTimeAnchorStore {
  private readonly logger = new Logger(FileSystemEdgeTrustedTimeAnchorStore.name);
  private readonly path: string;

  constructor(@Inject(EdgeConfigService) config: EdgeConfigService) {
    this.path = join(config.values.EDGE_QUEUE_PATH, EDGE_TRUSTED_TIME_ANCHOR_FILENAME);
  }

  async load(): Promise<unknown> {
    let raw: string;
    try {
      raw = await readFile(this.path, 'utf8');
    } catch {
      return null;
    }
    try {
      return JSON.parse(raw);
    } catch {
      // Corrupt bytes are not a candidate. They are also not a crisis: the
      // verifier would refuse them anyway, and Edge simply starts cold.
      return null;
    }
  }

  async save(anchor: SignedEdgeTrustedTimeAnchor): Promise<void> {
    // The signed pair, verbatim. `JSON.stringify` of the parsed anchor is safe
    // here in a way it is NOT for a queued operation payload: what is written
    // is re-PARSED and re-VERIFIED on load, and the verifier re-canonicalises
    // the statement before checking the signature, so key order in this file
    // carries no meaning and cannot break anything.
    const body = JSON.stringify({ statement: anchor.statement, signature: anchor.signature });
    const temporary = `${this.path}.${randomUUID()}.tmp`;
    try {
      await mkdir(dirname(this.path), { recursive: true });
      await writeFile(temporary, body, { encoding: 'utf8', mode: 0o600 });
      await rename(temporary, this.path);
    } catch {
      // Reason-free on purpose: the path is the deployment's, and a log line is
      // not the place to disclose it.
      this.logger.warn('failed to persist the trusted-time anchor; continuing in memory');
    }
  }

  async clear(): Promise<void> {
    try {
      await writeFile(this.path, '', { encoding: 'utf8', mode: 0o600 });
    } catch {
      this.logger.warn('failed to clear the persisted trusted-time anchor');
    }
  }
}

/**
 * THE BINDING, and the default is the SAFE one.
 *
 * Persistence is selected only when this deployment has pinned a verification
 * keyring, and that conditional is the load-bearing part. A persisted anchor is
 * worth exactly as much as Edge's ability to verify it: without a keyring,
 * every loaded anchor refuses at KEYRING_UNAVAILABLE anyway, so writing one
 * would be storing a private-ish operational record on disk in exchange for
 * nothing at all. Worse, it would leave a file that LOOKS like trust material
 * on a box where nothing can check it — the exact shape of the round-1 STOP.
 */
export const EDGE_TRUSTED_TIME_ANCHOR_STORE_BINDING: Provider = {
  provide: EDGE_TRUSTED_TIME_ANCHOR_STORE,
  inject: [EdgeConfigService],
  useFactory: (config: EdgeConfigService): EdgeTrustedTimeAnchorStore =>
    config.values.EDGE_TRUSTED_TIME_VERIFICATION_KEYS === undefined
      ? new VolatileEdgeTrustedTimeAnchorStore()
      : new FileSystemEdgeTrustedTimeAnchorStore(config),
};
