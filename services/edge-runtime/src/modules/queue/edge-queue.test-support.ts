import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DeviceEdgeReceiptSchema,
  DeviceOfflineOperationEnvelopeSchema,
  canonicalDeviceJson,
  deviceCanonicalDigest,
  type DeviceEdgeReceipt,
  type DeviceOfflineOperationEnvelope,
} from '@sentinel/contracts';
import type { EdgeMonotonicClock } from './edge-queue.store';

/**
 * Fixtures for the durable queue's specs.
 *
 * The envelopes below are STRUCTURALLY valid and are not cryptographically
 * meaningful, which is exactly right for a store's tests: the store is a byte
 * pipe with no opinion, it never verifies a device signature, and a spec that
 * needed a real signing key to exercise a capacity bound would be testing the
 * wrong thing. What the fixtures DO have to get right is the payload/digest
 * binding, because `EdgeStoredOperationSchema` re-derives it on every read and
 * a fixture that faked it would make every read test vacuous.
 */

/** A base64url `r || s` that `DeviceSignatureSchema` decodes: nonzero, low-S. */
export const FIXTURE_SIGNATURE = Buffer.from(new Uint8Array(64).fill(11)).toString('base64url');
export const FIXTURE_EDGE_SIGNATURE = Buffer.from(new Uint8Array(64).fill(12)).toString('base64url');

/** Canonical payload text and the digest the envelope must carry for it. */
export function canonicalPayload(value: unknown): { readonly text: string; readonly digest: string } {
  return { text: canonicalDeviceJson(value), digest: deviceCanonicalDigest(value) };
}

let uuidCounter = 0;

/** Deterministic v4-shaped ids, so a failing spec names the same entry every run. */
export function fixtureOperationId(): string {
  uuidCounter += 1;
  const tail = uuidCounter.toString(16).padStart(12, '0');
  return `a3bb1a10-2c3d-4e5f-8a9b-${tail}`;
}

export interface FixtureOperation {
  readonly envelope: DeviceOfflineOperationEnvelope;
  readonly payloadCanonicalJson: string;
}

/**
 * One storable operation. `payload` and `payload_digest` are bound by
 * construction — override `payload_digest` explicitly to build the corrupt case.
 */
export function fixtureOperation(
  overrides: Record<string, unknown> = {},
  payload: unknown = { message_id: '22222222-2222-4222-8222-222222222222' },
): FixtureOperation {
  const { text, digest } = canonicalPayload(payload);
  const envelope = DeviceOfflineOperationEnvelopeSchema.parse({
    schema_version: 1,
    offline_operation_id: fixtureOperationId(),
    organisation_id: 'org-1',
    site_id: 'site-1',
    actor_user_id: 'user-1',
    device_id: 'device-1',
    key_id: 'key-1',
    key_version: 4,
    operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE',
    device_sequence: 0,
    idempotency_key: 'client-key-1',
    payload_digest: digest,
    policy_lease_id: 'lease-1',
    nonce: 'nonce-0123456789abcdef',
    created_at: '2026-09-05T10:00:00.000Z',
    claimed_signature_profile: 'P256_ECDSA_SHA256',
    signature: FIXTURE_SIGNATURE,
    ...overrides,
  });
  return { envelope, payloadCanonicalJson: text };
}

/**
 * An Edge receipt for a fixture operation.
 *
 * `witnessed_operation_fingerprint` is a well-formed digest rather than the real
 * fingerprint: the real one depends on the SERVER-resolved signature profile,
 * which Edge does not own, and the frozen schema only checks locally that the
 * receipt NAMES an operation.
 */
export function fixtureReceipt(edgeMonotonicPosition: number, overrides: Record<string, unknown> = {}): DeviceEdgeReceipt {
  return DeviceEdgeReceiptSchema.parse({
    schema_version: 1,
    edge_id: 'edge-17',
    edge_key_id: 'edge-key-1',
    edge_key_version: 1,
    witnessed_operation_fingerprint: 'a'.repeat(64),
    edge_trusted_time: '2026-09-05T10:00:01.000Z',
    edge_monotonic_position: edgeMonotonicPosition,
    claimed_edge_signature_profile: 'P256_ECDSA_SHA256',
    edge_signature: FIXTURE_EDGE_SIGNATURE,
    ...overrides,
  });
}

/**
 * A clock a spec drives by hand.
 *
 * The store's durable clock is monotonic and never a wall clock; a controllable
 * one lets a spec prove a backoff elapses without waiting for it, and lets the
 * restart tests show the durable value resuming rather than restarting.
 */
export class FixtureClock implements EdgeMonotonicClock {
  constructor(private value = 0) {}

  nowMs(): number {
    return this.value;
  }

  advance(ms: number): void {
    this.value += ms;
  }
}

/** A throwaway directory for one spec's store. */
export function temporaryQueueDirectory(): { readonly path: string; remove: () => void } {
  const path = mkdtempSync(join(tmpdir(), 'sentinel-edge-queue-'));
  return { path, remove: () => rmSync(path, { recursive: true, force: true }) };
}
