import { randomUUID } from 'node:crypto';
import { deviceCanonicalDigest } from '@sentinel/contracts';
import { ENDPOINTS } from './topology';

/**
 * WP-30 — DRIVING THE EDGE'S OWN INGRESS AND QUEUE FROM THE HARNESS.
 *
 * Everything here talks to the Edge over HTTP exactly as a Field client would.
 * Nothing reaches into its SQLite file, and that restriction is the point: a
 * harness that inspected the store directly could assert a queue state the
 * Edge's own API would never report, and Proof D would then be evidence about
 * a database rather than about a system.
 */

export interface FieldOperation {
  readonly envelope: Record<string, unknown>;
  readonly payload: Record<string, unknown>;
}

export interface EdgeSubmitOutcome {
  readonly status: number;
  readonly outcome: string | null;
  readonly offlineOperationId: string | null;
}

/**
 * Builds one device-signed-SHAPED envelope.
 *
 * NOT ACTUALLY DEVICE-SIGNED, and the distinction is recorded here rather than
 * buried: the Edge ingress does not verify a device signature -- it is a
 * witness and a buffer, and central re-verifies everything on replay. So these
 * scenarios exercise the Edge's QUEUEING and RECOVERY behaviour truthfully,
 * and they do NOT claim to exercise device authentication. That claim belongs
 * to WP-26/WP-28 with real hardware, and this harness must not appear to make
 * it.
 */
export function buildFieldOperation(input: {
  readonly organisationId: string;
  readonly siteId: string;
  readonly actorUserId: string;
  readonly deviceId: string;
  readonly deviceSequence: number;
  readonly offlineOperationId?: string;
  readonly payload?: Record<string, unknown>;
}): FieldOperation {
  const payload = input.payload ?? { acknowledged_at: '2026-09-07T00:00:00.000Z' };
  return {
    envelope: {
      schema_version: 2,
      offline_operation_id: input.offlineOperationId ?? randomUUID(),
      organisation_id: input.organisationId,
      site_id: input.siteId,
      actor_user_id: input.actorUserId,
      device_id: input.deviceId,
      device_sequence: input.deviceSequence,
      operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE',
      idempotency_key: randomUUID(),
      created_at: '2026-09-07T00:00:00.000Z',
      payload_digest: canonicalDigest(payload),
    },
    payload,
  };
}

/**
 * The digest the Edge recomputes and compares.
 *
 * The CONTRACT's own function, not a local reimplementation. A harness that
 * digested differently would produce submissions the Edge rejects for a reason
 * that has nothing to do with the scenario under test.
 */
function canonicalDigest(payload: Record<string, unknown>): string {
  return deviceCanonicalDigest(payload);
}

/**
 * Hands one operation to the Edge, as a Field client on the site LAN would.
 *
 * Never throws on a refusal: the STATUS is the finding. A helper that threw
 * would make "the Edge refused" indistinguishable from "the harness broke".
 */
export async function submitToEdge(operation: FieldOperation): Promise<EdgeSubmitOutcome> {
  let response: Awaited<ReturnType<typeof fetch>>;
  try {
    response = await fetch(`${ENDPOINTS.edge}/edge/v1/field-operations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(operation),
    });
  } catch {
    return { status: 0, outcome: null, offlineOperationId: null };
  }

  let body: { outcome?: unknown; offline_operation_id?: unknown } = {};
  try {
    body = (await response.json()) as typeof body;
  } catch {
    // A body we cannot read is not a body we may invent.
  }

  return {
    status: response.status,
    outcome: typeof body.outcome === 'string' ? body.outcome : null,
    offlineOperationId: typeof body.offline_operation_id === 'string' ? body.offline_operation_id : null,
  };
}

/** The Edge's own account of its queue, from its health surface. */
export async function edgeQueueDepth(): Promise<{ readonly reachable: boolean; readonly storage: string | null }> {
  try {
    const response = await fetch(`${ENDPOINTS.edge}/health/ready`);
    const body = (await response.json()) as { dependencies?: Record<string, string> };
    return { reachable: response.ok, storage: body.dependencies?.queue_storage ?? null };
  } catch {
    return { reachable: false, storage: null };
  }
}
