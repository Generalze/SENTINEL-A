import { Injectable, Logger, type Provider } from '@nestjs/common';
import { X509Certificate } from 'node:crypto';
import { z } from 'zod';
import { AppConfigService } from '../../config/config.service';
import type { AppConfig } from '../../config/env.schema';
import {
  ANDROID_ATTESTATION_TRUST_MATERIAL,
  UNCONFIGURED_VERSION,
  UnconfiguredAndroidAttestationTrustMaterial,
  normaliseCertificateSerial,
  revocationSnapshotIsFresh,
  type AndroidAttestationTrustMaterial,
  type AndroidAttestationTrustMaterialProvider,
  type AndroidCertificateRevocationEntry,
} from './android-attestation.trust-material';

/**
 * ============================================================================
 * WP-26/D26-04B/C18-01 — THE CONFIGURATION-BACKED TRUST MATERIAL PROVIDER.
 *
 * THE PROBLEM THIS FILE EXISTS TO CLOSE
 * -------------------------------------
 * `android-attestation.trust-material.ts` has always said that supplying the
 * real Google roots "is a deployment act". Until this file existed that was not
 * operationally TRUE: the module hard-bound `UnconfiguredAndroidAttestationTrustMaterial`,
 * so there was no provider in the tree to supply anything TO. The only way to
 * reach `VERIFIED` was a Vitest `.overrideProvider(...)`, which means the exact
 * candidate SHA could not perform its own physical-device acceptance without a
 * test-only edit — and an acceptance run that needs a test override is an
 * acceptance run of something other than the shipping code.
 *
 * So: the anchors, the revocation snapshot, the expected package and the
 * allowed signing digests come from ORDINARY SERVER CONFIGURATION, validated at
 * boot the way every other environment variable in this service is
 * (`config/env.schema.ts`, zod, fail-fast). Setting them — and nothing else —
 * makes a deployment able to reach `VERIFIED`.
 *
 * WHAT IS DELIBERATELY NOT HERE
 * -----------------------------
 * NO GOOGLE ROOT BYTES. Not a constant, not a fixture, not a fallback. There
 * are two real Google hardware-attestation roots in the world and a wrong
 * pinned root is worse than a missing one: a missing one fails CLOSED
 * (`UNAVAILABLE`; the device enrols DEGRADED and can never be TRUSTED), a wrong
 * one fails OPEN. Configuration supplies them.
 *
 * NO NETWORK FETCH, NO SCHEDULER, NO CACHE REFRESH (D25-08, still binding).
 * The revocation snapshot is a configured VALUE with a configured `fetched-at`,
 * and its freshness is a comparison taken at REQUEST TIME against
 * `ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_MAX_AGE_MS`. This class starts
 * nothing and reads no clock of its own.
 *
 * THE FOUR RULES THIS FILE ENFORCES, EACH OF WHICH IS A TEST
 * ----------------------------------------------------------
 *   1. ALL OR NOTHING. Anchors without a revocation snapshot, a snapshot
 *      without a fetched-at, anchors with no expected package — every partial
 *      combination is `configured: false`. Trust material is a conjunction and
 *      a conjunction with a missing term is not a weaker conjunction, it is no
 *      answer at all.
 *   2. NEVER SILENTLY SUBSTITUTE. There is no default value for any field
 *      below, and no fallback to the unconfigured provider's opinion of what a
 *      "reasonable" anchor might be.
 *   3. A MALFORMED ANCHOR POISONS THE WHOLE SET. Not "keep the anchors that
 *      parsed" — a set that quietly shrank is a set nobody chose, and the one
 *      that failed to parse might have been the only one that mattered.
 *   4. STALE IS UNAVAILABLE. Past the named bound the material declines to
 *      answer, exactly as C14-05 requires, rather than serving revocation data
 *      nobody can still vouch for.
 *
 * PARSING HAPPENS ONCE, AT CONSTRUCTION. `current()` applies only the freshness
 * comparison, because that is the only part of the answer that depends on the
 * instant it is asked at. A boot with malformed material therefore fails to
 * `VERIFIED` immediately and visibly in the log, rather than on the first
 * enrolment attempt weeks later.
 * ============================================================================
 */

/**
 * Google's certificate status list, as the deployment supplies it verbatim.
 *
 *     { "entries": { "<serial hex>": { "status": "REVOKED", "reason": "..." } } }
 *
 * `status` is required because it is the fact; `reason` is optional because
 * Google's own list omits it for some entries. `.catchall` is deliberately NOT
 * relaxed on the entry object: an entry carrying keys this reader does not
 * understand is still a revocation, and only `status`/`reason` are read.
 */
const RevocationEntrySchema = z
  .object({
    status: z.string().min(1),
    reason: z.string().min(1).nullish(),
  })
  .passthrough();

const RevocationSnapshotSchema = z.object({
  entries: z.record(z.string().min(1), RevocationEntrySchema),
});

/** Why the configured material could not be used. Recorded, never returned to a caller. */
export type ConfiguredTrustMaterialRefusal =
  | 'TRUST_MATERIAL_INCOMPLETE'
  | 'TRUST_ANCHORS_UNPARSEABLE'
  | 'TRUST_ANCHORS_EMPTY'
  | 'TRUST_ANCHOR_NOT_CERTIFICATE_AUTHORITY'
  | 'REVOCATION_SNAPSHOT_UNPARSEABLE'
  | 'REVOCATION_SNAPSHOT_FETCHED_AT_INVALID'
  | 'REVOCATION_SNAPSHOT_STALE'
  | 'SIGNING_DIGESTS_INVALID';

/** Every configuration key this provider reads. Named once so nothing drifts. */
export const ANDROID_ATTESTATION_TRUST_MATERIAL_KEYS = [
  'ANDROID_ATTESTATION_TRUST_ANCHORS',
  'ANDROID_ATTESTATION_TRUST_ANCHOR_SET_VERSION',
  'ANDROID_ATTESTATION_REVOCATION_SNAPSHOT',
  'ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_VERSION',
  'ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_FETCHED_AT',
  'ANDROID_ATTESTATION_PACKAGE_NAME',
  'ANDROID_ATTESTATION_SIGNING_DIGESTS',
] as const satisfies readonly (keyof AppConfig)[];

/**
 * Has this deployment SAID ANYTHING about trust material?
 *
 * ANY key present counts, deliberately — not "all of them". A deployment that
 * set six of the seven keys has attempted to configure trust material and got it
 * wrong, and it must learn that from an `UNAVAILABLE` verdict carrying a named
 * reason, not from silently falling back to the shipped default as though it had
 * never tried. "Absent" means absent ENTIRELY, which is the only state the
 * fallback is honest about.
 */
export function androidAttestationTrustMaterialIsConfigured(config: AppConfig): boolean {
  return ANDROID_ATTESTATION_TRUST_MATERIAL_KEYS.some((key) => config[key] !== undefined);
}

/** The material as it stands once configuration has been parsed. */
type LoadedMaterial =
  | { readonly loaded: false; readonly refusal: ConfiguredTrustMaterialRefusal }
  | {
      readonly loaded: true;
      readonly anchors: readonly X509Certificate[];
      readonly revocations: ReadonlyMap<string, AndroidCertificateRevocationEntry>;
      readonly revocationFetchedAt: Date;
      readonly expectedPackageName: string;
      readonly expectedSigningDigests: readonly string[];
    };

@Injectable()
export class ConfiguredAndroidAttestationTrustMaterial implements AndroidAttestationTrustMaterialProvider {
  private readonly logger = new Logger(ConfiguredAndroidAttestationTrustMaterial.name);

  private readonly loaded: LoadedMaterial;
  private readonly trustAnchorSetVersion: string;
  private readonly revocationSnapshotVersion: string;

  constructor(config: AppConfig) {
    // The versions are recorded on EVERY artifact, including the refusals, so
    // they are resolved even when the material itself did not load. A row that
    // cannot name the trust material it was judged against is not evidence.
    this.trustAnchorSetVersion = config.ANDROID_ATTESTATION_TRUST_ANCHOR_SET_VERSION ?? UNCONFIGURED_VERSION;
    this.revocationSnapshotVersion = config.ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_VERSION ?? UNCONFIGURED_VERSION;
    this.loaded = loadConfiguredTrustMaterial(config);
    if (!this.loaded.loaded) {
      // A REASON CODE ONLY. No certificate bytes, no configuration values — the
      // same discipline the ingress's internal reason log follows. An operator
      // who set these keys needs to know the material was refused and why; the
      // material itself is not a log line.
      this.logger.error(
        `android attestation trust material NOT USABLE: reason=${this.loaded.refusal} ` +
          `trust_anchor_set_version=${this.trustAnchorSetVersion} revocation_snapshot_version=${this.revocationSnapshotVersion}. ` +
          'Every attestation verdict will be UNAVAILABLE until this is corrected.',
      );
    }
  }

  async current(now: Date): Promise<AndroidAttestationTrustMaterial> {
    if (!this.loaded.loaded) return this.unusable(this.loaded.refusal);

    // FRESHNESS IS THE ONE THING DECIDED AT REQUEST TIME, because it is the one
    // thing that depends on when the question was asked. Bounded by the named
    // constant, exclusive boundary, and a `fetchedAt` in the future is refused
    // too — it does not describe a possible history.
    if (!revocationSnapshotIsFresh(this.loaded.revocationFetchedAt, now)) {
      return this.unusable('REVOCATION_SNAPSHOT_STALE');
    }

    return {
      configured: true,
      anchors: this.loaded.anchors,
      trustAnchorSetVersion: this.trustAnchorSetVersion,
      revocations: this.loaded.revocations,
      revocationSnapshotVersion: this.revocationSnapshotVersion,
      revocationFetchedAt: this.loaded.revocationFetchedAt,
      expectedPackageName: this.loaded.expectedPackageName,
      expectedSigningDigests: this.loaded.expectedSigningDigests,
    };
  }

  private unusable(reason: ConfiguredTrustMaterialRefusal): AndroidAttestationTrustMaterial {
    return {
      configured: false,
      reason,
      trustAnchorSetVersion: this.trustAnchorSetVersion,
      revocationSnapshotVersion: this.revocationSnapshotVersion,
    };
  }
}

/**
 * Parses configuration into usable material, or names the reason it could not.
 *
 * Exported so the rules above are testable as RULES rather than only through a
 * booted injector.
 */
export function loadConfiguredTrustMaterial(config: AppConfig): LoadedMaterial {
  // 1. ALL OR NOTHING. Every key is required together; a missing term makes the
  //    conjunction unanswerable rather than weaker.
  const missing = ANDROID_ATTESTATION_TRUST_MATERIAL_KEYS.some((key) => {
    const value = config[key];
    return typeof value !== 'string' || value.trim().length === 0;
  });
  if (missing) return { loaded: false, refusal: 'TRUST_MATERIAL_INCOMPLETE' };

  const anchors = parseTrustAnchors(config.ANDROID_ATTESTATION_TRUST_ANCHORS as string);
  if (anchors === null) return { loaded: false, refusal: 'TRUST_ANCHORS_UNPARSEABLE' };
  if (anchors.length === 0) return { loaded: false, refusal: 'TRUST_ANCHORS_EMPTY' };
  // C18-04's rule applied to the anchor set itself: a pinned root that is not a
  // CA cannot have been authorised to issue the chain it is being asked to
  // anchor, and pinning one would be pinning a mistake.
  if (anchors.some((anchor) => !anchor.ca)) return { loaded: false, refusal: 'TRUST_ANCHOR_NOT_CERTIFICATE_AUTHORITY' };

  const revocations = parseRevocationSnapshot(config.ANDROID_ATTESTATION_REVOCATION_SNAPSHOT as string);
  if (revocations === null) return { loaded: false, refusal: 'REVOCATION_SNAPSHOT_UNPARSEABLE' };

  const fetchedAt = new Date(config.ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_FETCHED_AT as string);
  if (!Number.isFinite(fetchedAt.getTime())) return { loaded: false, refusal: 'REVOCATION_SNAPSHOT_FETCHED_AT_INVALID' };

  const expectedSigningDigests = parseSigningDigests(config.ANDROID_ATTESTATION_SIGNING_DIGESTS as string);
  if (expectedSigningDigests === null) return { loaded: false, refusal: 'SIGNING_DIGESTS_INVALID' };

  return {
    loaded: true,
    anchors,
    revocations,
    revocationFetchedAt: fetchedAt,
    expectedPackageName: (config.ANDROID_ATTESTATION_PACKAGE_NAME as string).trim(),
    expectedSigningDigests,
  };
}

/**
 * One or more certificates, as concatenated PEM or as base64 DER.
 *
 * `null` — never a shorter list — when ANY of them fails to parse. Rule 3: a
 * silently smaller anchor set is an anchor set nobody chose, and the anchor that
 * failed to parse may be the only one a given device chains to.
 */
function parseTrustAnchors(raw: string): X509Certificate[] | null {
  const trimmed = raw.trim();
  if (trimmed.length === 0) return null;

  const pemBlocks = trimmed.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu);
  const sources: string[] =
    pemBlocks !== null && pemBlocks.length > 0
      ? pemBlocks
      : trimmed.split(/[\s,]+/u).filter((candidate) => candidate.length > 0);

  // A value that LOOKED like PEM but yielded no complete block is malformed, not
  // a list of base64 DER tokens to be re-read a different way.
  if (pemBlocks === null && trimmed.includes('-----BEGIN')) return null;

  const anchors: X509Certificate[] = [];
  for (const source of sources) {
    const input: string | Buffer | null = source.includes('-----BEGIN CERTIFICATE-----') ? source : decodeStrictBase64(source);
    if (input === null) return null;
    try {
      anchors.push(new X509Certificate(input));
    } catch {
      return null;
    }
  }
  return anchors;
}

/**
 * Standard base64, decoded STRICTLY — the same discipline the verifier applies
 * to a submitted certificate, and for the same reason: "what did this string
 * mean?" must have exactly one answer on a security path. Whitespace inside the
 * value is stripped first, because a multi-line environment variable is an
 * ordinary way to write a long DER blob.
 */
function decodeStrictBase64(value: string): Buffer | null {
  const compact = value.replace(/\s+/gu, '');
  if (compact.length === 0) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(compact)) return null;
  const decoded = Buffer.from(compact, 'base64');
  if (decoded.length === 0) return null;
  return decoded.toString('base64') === compact ? decoded : null;
}

/**
 * Google's status-list JSON into the map the verifier looks a serial up in.
 *
 * Serials are normalised through the ONE function that also normalises a
 * certificate's own serial, because a revocation check that silently never
 * matches is a check that fails OPEN — the single worst outcome available here.
 */
function parseRevocationSnapshot(raw: string): ReadonlyMap<string, AndroidCertificateRevocationEntry> | null {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return null;
  }
  const parsed = RevocationSnapshotSchema.safeParse(json);
  if (!parsed.success) return null;

  const revocations = new Map<string, AndroidCertificateRevocationEntry>();
  for (const [serial, entry] of Object.entries(parsed.data.entries)) {
    const key = normaliseCertificateSerial(serial);
    if (key.length === 0) return null;
    revocations.set(key, { status: entry.status, reason: entry.reason ?? null });
  }
  return revocations;
}

/**
 * SHA-256 signing-certificate digests, hex, one or more.
 *
 * Lowercased because that is the ONE form the verifier compares in, and length
 * checked because a truncated digest would compare against nothing and quietly
 * refuse every genuine device.
 */
function parseSigningDigests(raw: string): string[] | null {
  const digests = raw
    .split(/[\s,]+/u)
    .filter((candidate) => candidate.length > 0)
    .map((candidate) => candidate.toLowerCase());
  if (digests.length === 0) return null;
  if (digests.some((digest) => !/^[0-9a-f]{64}$/u.test(digest))) return null;
  return digests;
}

/**
 * THE BINDING ITSELF, and the reason it lives here rather than inline in the
 * module.
 *
 * `device-enrollment-ingress.module.ts` uses this exact provider object, so a
 * spec can compile it into a small injector and exercise THE SHIPPING WIRING —
 * no `.overrideProvider(...)`, no test-only branch. That matters because
 * D26-10's physical-device acceptance has to run against the code that ships,
 * and an acceptance that needs a Vitest override is an acceptance of something
 * else.
 *
 * The fallback is the SAFE default and stays that way: a deployment that has
 * said nothing about trust material gets `UnconfiguredAndroidAttestationTrustMaterial`,
 * which pins nothing and can never reach `VERIFIED`.
 */
export const ANDROID_ATTESTATION_TRUST_MATERIAL_PROVIDER: Provider = {
  provide: ANDROID_ATTESTATION_TRUST_MATERIAL,
  inject: [AppConfigService],
  useFactory: (config: AppConfigService): AndroidAttestationTrustMaterialProvider =>
    androidAttestationTrustMaterialIsConfigured(config.values)
      ? new ConfiguredAndroidAttestationTrustMaterial(config.values)
      : new UnconfiguredAndroidAttestationTrustMaterial(),
};
