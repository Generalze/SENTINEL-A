import { Inject, Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import type { AndroidAttestationClaims } from './android-key-attestation.verifier';

/**
 * WP-26 device enrollment ingress persistence primitives.
 *
 * THIS REPOSITORY HOLDS NO SECURITY POLICY. Every enrollment rule lives in the
 * frozen contracts and in Shield's services; every attestation rule lives in
 * `android-key-attestation.verifier.ts`. What lives here is the set of storage
 * operations those decisions need, each carrying exactly the concurrency
 * guarantee D26-04A requires — nothing more.
 *
 * IT TOUCHES EXACTLY TWO TABLES, AND NEITHER IS SHIELD'S (D26-09)
 * ---------------------------------------------------------------
 * `device_attestation_challenges` and `android_key_attestation_artifacts`. The
 * ingress calls Shield SERVICES for everything else; it never writes a Shield
 * table, never writes a registry row and never writes a device security event.
 * `test/device-enrollment-ingress-boundary.architecture.spec.ts` asserts that
 * as a SOURCE SCAN, for the reason the WP-25 boundary guard gives: a property
 * protected by review is a property protected until the first busy week.
 *
 * THE ARTIFACT TABLE IS APPEND-ONLY. There is exactly one writer below,
 * `recordAttestationArtifact`, and it calls `create`. There is no update, no
 * delete, no upsert, no `deleteMany` and no `updateMany` against it anywhere in
 * this module.
 */
@Injectable()
export class DeviceEnrollmentIngressRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  /**
   * The authoritative server clock.
   *
   * `clock_timestamp()`, never `now()`, for the reason `ShieldRepository`
   * states: Postgres pins `now()` to transaction start, and every WP-26 timing
   * rule is a comparison against a real instant rather than against the moment
   * a transaction happened to open.
   */
  async now(): Promise<Date> {
    const rows = await this.prisma.$queryRaw<Array<{ now: Date }>>(Prisma.sql`SELECT clock_timestamp() AS now`);
    const row = rows[0];
    if (row === undefined) throw new Error('clock_timestamp returned no row');
    return row.now;
  }

  // -------------------------------------------------------------------------
  // D26-04A — the attestation challenge
  // -------------------------------------------------------------------------

  async createAttestationChallenge(input: {
    organisationId: string;
    siteId: string;
    intendedUserId: string;
    bootstrapGrantId: string;
    challengeValue: string;
    issuedAt: Date;
    expiresAt: Date;
  }): Promise<{ id: string; expiresAt: Date }> {
    const row = await this.prisma.deviceAttestationChallenge.create({
      data: {
        organisationId: input.organisationId,
        siteId: input.siteId,
        intendedUserId: input.intendedUserId,
        bootstrapGrantId: input.bootstrapGrantId,
        challengeValue: input.challengeValue,
        issuedAt: input.issuedAt,
        expiresAt: input.expiresAt,
      },
      select: { id: true, expiresAt: true },
    });
    return row;
  }

  /**
   * Reads one challenge, scoped to the SESSION'S organisation.
   *
   * C17-02: the organisation passed in is always the authenticated principal's,
   * never one a request body named. A challenge in another tenant is
   * indistinguishable from an id that has never existed, which is the isolation
   * rule Shield's own refusal vocabulary is built around.
   */
  async findAttestationChallenge(
    organisationId: string,
    challengeId: string,
  ): Promise<{
    id: string;
    organisationId: string;
    siteId: string;
    intendedUserId: string;
    bootstrapGrantId: string;
    challengeValue: string;
    issuedAt: Date;
    expiresAt: Date;
    consumedAt: Date | null;
    submissionFingerprint: string | null;
    enrollmentRequestId: string | null;
    enrollmentRequestFingerprint: string | null;
    attestationOutcome: string | null;
    keyStorage: string | null;
  } | null> {
    return this.prisma.deviceAttestationChallenge.findFirst({
      where: { id: challengeId, organisationId },
      select: {
        id: true,
        organisationId: true,
        siteId: true,
        intendedUserId: true,
        bootstrapGrantId: true,
        challengeValue: true,
        issuedAt: true,
        expiresAt: true,
        consumedAt: true,
        // C18-03: the durable receipt. Selected here so the ONE read the service
        // already performs can also answer "did this exact submission already
        // succeed?", rather than a second query racing the first.
        submissionFingerprint: true,
        enrollmentRequestId: true,
        enrollmentRequestFingerprint: true,
        attestationOutcome: true,
        keyStorage: true,
      },
    });
  }

  /**
   * ONE-SHOT, AS A DATABASE FACT.
   *
   * A fenced conditional update: `consumed_at` is stamped only where it is still
   * NULL, and the returned COUNT is the concurrency signal. Two simultaneous
   * submissions against one challenge therefore produce exactly one winner, and
   * the loser is told the challenge is spent rather than both being allowed
   * through by a read-then-write that raced.
   *
   * It is never cleared. A spent challenge does not become unspent, and a
   * verification that then failed does not hand the value back — the phone
   * discards the unfinished key and restarts with a fresh challenge, which is
   * what D26-04A prescribes.
   *
   * C18-03: `submissionFingerprint` is stamped BY THE SAME STATEMENT. The row
   * can therefore never say "consumed" without saying by WHAT, which is what
   * makes lost-response resolution a proof rather than a guess — and it costs
   * nothing, because the winning update is the one that already had to happen.
   */
  async consumeAttestationChallenge(
    organisationId: string,
    challengeId: string,
    at: Date,
    submissionFingerprint: string,
  ): Promise<boolean> {
    const result = await this.prisma.deviceAttestationChallenge.updateMany({
      where: { id: challengeId, organisationId, consumedAt: null },
      data: { consumedAt: at, submissionFingerprint },
    });
    return result.count === 1;
  }

  /**
   * Records the enrollment request ONE consumed challenge produced (C18-03).
   *
   * WRITE-ONCE, AS A DATABASE FACT. The `enrollmentRequestId: null` predicate
   * makes this a fenced update exactly as `consumeAttestationChallenge` is: the
   * outcome of a challenge is written by the submission that reached it, once,
   * and no later call can rewrite what an earlier one recorded. That matters
   * because the recorded outcome is what a retry is answered FROM — a mutable
   * receipt would be a receipt an attacker could aim.
   *
   * It writes only to the challenge's OWN row and only to columns that were
   * NULL. It does not touch `consumed_at`, `expires_at`, or any Shield table.
   * The return value is deliberately ignored by the caller: the request already
   * exists either way, and failing the ceremony because a receipt could not be
   * written would trade a real success for a bookkeeping error.
   */
  async recordEnrollmentOutcome(input: {
    organisationId: string;
    challengeId: string;
    enrollmentRequestId: string;
    enrollmentRequestFingerprint: string;
    attestationOutcome: string;
    keyStorage: string;
  }): Promise<boolean> {
    const result = await this.prisma.deviceAttestationChallenge.updateMany({
      where: { id: input.challengeId, organisationId: input.organisationId, enrollmentRequestId: null },
      data: {
        enrollmentRequestId: input.enrollmentRequestId,
        enrollmentRequestFingerprint: input.enrollmentRequestFingerprint,
        attestationOutcome: input.attestationOutcome,
        keyStorage: input.keyStorage,
      },
    });
    return result.count === 1;
  }

  // -------------------------------------------------------------------------
  // D26-04B — the restricted provider record
  // -------------------------------------------------------------------------

  /**
   * Appends ONE attestation artifact and returns its SERVER-GENERATED id.
   *
   * The id is Prisma's `@default(uuid())`, so there is no parameter here through
   * which a caller could supply one — the same construction D24-04 uses for the
   * sequence namespace and D24-10A for a proposed key identity.
   *
   * `certificateChainDer` is the RESTRICTED column. This method is the only
   * place in Sentinel that writes it, and nothing anywhere reads it back:
   * `AndroidAttestationArtifactReader` — the ONLY reader of this table — selects
   * the verdict and the binding columns and deliberately does not select the
   * chain.
   */
  async recordAttestationArtifact(input: {
    organisationId: string;
    bootstrapGrantId: string;
    attestationChallengeId: string;
    publicKeyThumbprint: string;
    certificateChainHash: string;
    verifierVersion: string;
    trustAnchorSetVersion: string;
    revocationSnapshotVersion: string;
    claims: AndroidAttestationClaims;
    outcome: string;
    outcomeReason: string;
    evaluatedAt: Date;
    certificateChainDer: readonly string[];
  }): Promise<string> {
    const row = await this.prisma.androidKeyAttestationArtifact.create({
      data: {
        organisationId: input.organisationId,
        bootstrapGrantId: input.bootstrapGrantId,
        attestationChallengeId: input.attestationChallengeId,
        publicKeyThumbprint: input.publicKeyThumbprint,
        certificateChainHash: input.certificateChainHash,
        verifierVersion: input.verifierVersion,
        trustAnchorSetVersion: input.trustAnchorSetVersion,
        revocationSnapshotVersion: input.revocationSnapshotVersion,
        attestationVersion: input.claims.attestationVersion,
        attestationSecurityLevel: input.claims.attestationSecurityLevel,
        keymasterSecurityLevel: input.claims.keymasterSecurityLevel,
        keyPurposes: [...input.claims.keyPurposes],
        keyAlgorithm: input.claims.keyAlgorithm,
        keySize: input.claims.keySize,
        keyEcCurve: input.claims.keyEcCurve,
        keyOrigin: input.claims.keyOrigin,
        noAuthRequired: input.claims.noAuthRequired,
        verifiedBootState: input.claims.verifiedBootState,
        deviceLocked: input.claims.deviceLocked,
        attestationPackageName: input.claims.attestationPackageName,
        attestationSigningDigest: input.claims.attestationSigningDigest,
        outcome: input.outcome,
        outcomeReason: input.outcomeReason,
        evaluatedAt: input.evaluatedAt,
        certificateChainDer: [...input.certificateChainDer],
      },
      select: { id: true },
    });
    return row.id;
  }
}
