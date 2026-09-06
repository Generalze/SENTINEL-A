import { Injectable } from '@nestjs/common';
import type { EdgeTrustedTimeAnchorRecord } from './edge-trusted-time.anchor';

/** DI token for the anchor store. */
export const EDGE_TRUSTED_TIME_ANCHOR_STORE = Symbol('EDGE_TRUSTED_TIME_ANCHOR_STORE');

/**
 * WP-29B / FW2-11 — ANCHOR PERSISTENCE IS **BLOCKED** PENDING A RULING.
 *
 * THE STOP, IN ONE SENTENCE
 * -------------------------
 * A persisted trusted-time anchor must be integrity-protected so that it is
 * INDEPENDENTLY VERIFIABLE after a restart, and this repository contains no
 * primitive that can make it so.
 *
 * WHAT THE SEARCH FOUND
 * ---------------------
 * Every cryptographic operation in production source is VERIFICATION of a
 * client's signature, or hashing. Specifically:
 *
 *   - `P256KeyImporter.verifySignature` (shield) — verifies DEVICE signatures
 *     against a registered public key. There is no signing counterpart.
 *   - `WhisperSignatureVerifier` — Ed25519 verification whose key resolver is a
 *     permanently fail-closed stub returning `null`.
 *   - `AndroidKeyAttestationVerifier` — X.509 chain verification against pinned
 *     public roots.
 *   - `deviceCanonicalDigest` / `computeContentHash` — SHA-256. UNKEYED.
 *
 * There is NO `createSign`, no HMAC, no JWT/JWS/PASETO/COSE, no KMS or HSM
 * integration, and no server-held private key or symmetric secret anywhere in
 * the environment schema, the compose files or the filesystem. The only working
 * signing recipe in the tree is `signCanonicalStatement` in
 * `shield.test-support.ts`, which is test-only and takes an in-memory key.
 *
 * WHY AN UNKEYED DIGEST DOES NOT CLOSE THIS
 * -----------------------------------------
 * The tempting move is to write the anchor as JSON beside a SHA-256 of itself.
 * That detects bit rot and nothing else. The adversary an integrity-protected
 * anchor defends against is someone who can write the file — and anyone who can
 * write the anchor can write the digest. It would be a checksum wearing the
 * costume of an integrity check, and its presence would make the gap HARDER to
 * see than its absence does.
 *
 * WHY "TRUST THE JSON FILE" IS NOT AN ACCEPTABLE DOWNGRADE
 * -------------------------------------------------------
 * The anchor is the seed of every `edge_trusted_time` Edge ever emits. An
 * attacker who can write an unauthenticated anchor file chooses what time Edge
 * believes it is — with a back-dated `server_time` and a matching
 * `monotonic_at_issue`, every subsequent receipt is genuinely signed by a
 * genuinely TRUSTED Edge and places operations inside whatever lease window the
 * attacker picked. Central cannot detect it: the receipt is well-formed, the
 * Edge key verifies, `edge_trust` is TRUSTED, and the whole ordered refusal
 * chain passes. The forgery would be indistinguishable from correct operation,
 * which is the definition of the failure this whole subsystem exists to prevent.
 *
 * WHAT THIS FILE DOES INSTEAD
 * ---------------------------
 * It defines the seam and provides the only implementation that is safe without
 * a ruling: one that loads nothing and persists nothing. This follows the
 * existing `FailClosedWhisperDeviceKeyResolver` precedent — the shape exists,
 * wired and typed, and it answers "no" until someone with the authority to do
 * so decides how it answers "yes".
 *
 * THE CONSEQUENCE, STATED HONESTLY
 * --------------------------------
 * An Edge that restarts holds no anchor until central re-establishes trusted
 * time. During that window it emits `edge_trusted_time: null` and central
 * refuses the five time-bounded kinds at NO_TRUSTWORTHY_TIME_WITNESS. That is a
 * real operational cost and it is the correct cost: note that FW2-10 already
 * invalidates a persisted anchor across a boot-identity change, so persistence
 * would only ever have helped a restart WITHIN one boot — a much narrower
 * benefit than the risk of an unauthenticated time seed.
 *
 * THE SMALLEST SAFE ADDITION (for the CTO's ruling, not implemented here)
 * ----------------------------------------------------------------------
 * Do not sign the anchor locally at all. Let CENTRAL sign it. Central already
 * owns `server_time`, and the receipt path already proves the repository can
 * verify a P-256 signature over a domain-tagged canonical statement. So:
 *
 *   1. A `sentinel.edge.trusted-time-anchor.v1` domain separator and a
 *      canonical statement builder beside the existing ones in
 *      `device-offline.ts`, using the same `canonicalDeviceJson` recipe.
 *   2. Central signs that statement with a SERVER key at issue. This is the
 *      genuinely new capability: the repository has no server signing key, so
 *      this requires a key-custody decision (where it lives, how it rotates)
 *      and a registry the way `DeviceKey` is one for devices — both of which
 *      are new trust boundaries and, for the registry, a migration.
 *   3. Edge verifies the signature at load with the EXISTING verification
 *      recipe — the `P256KeyImporter` shape, against a public key pinned in
 *      Edge's deployment as trust material, following the fail-closed,
 *      default-absent pattern the `ANDROID_ATTESTATION_*` block already
 *      establishes.
 *
 * Step 3 introduces no new cryptography — it is the verification Sentinel
 * already performs. Steps 1 and 2 are contract and key-custody decisions above
 * this lane's authority, so nothing in this file attempts them.
 */
export interface EdgeTrustedTimeAnchorStore {
  /** The anchor to resume with, or `null`. `null` is an ordinary answer. */
  load(): Promise<EdgeTrustedTimeAnchorRecord | null>;
  /** Persist an anchor central issued. May legitimately do nothing. */
  save(anchor: EdgeTrustedTimeAnchorRecord): Promise<void>;
}

/**
 * The only implementation WP-29B is authorised to ship: it holds no anchor
 * across a restart and writes none.
 *
 * `save` is a deliberate silent no-op rather than a throw. The caller's job is
 * to keep the site working, and an exception on a path that runs every time
 * central refreshes the anchor would turn a known, accepted limitation into
 * repeated error noise — or, worse, into a `catch {}` somewhere that later
 * hides a real failure. The limitation is documented at the top of this file
 * and asserted in the spec, which is where a reader will actually look.
 */
@Injectable()
export class NonPersistentEdgeTrustedTimeAnchorStore implements EdgeTrustedTimeAnchorStore {
  async load(): Promise<EdgeTrustedTimeAnchorRecord | null> {
    return null;
  }

  async save(_anchor: EdgeTrustedTimeAnchorRecord): Promise<void> {
    // Intentionally nothing. See the FW2-11 note above: writing an
    // unauthenticated anchor to disk would hand an attacker with file-write
    // access the ability to choose what time Edge believes it is.
  }
}
