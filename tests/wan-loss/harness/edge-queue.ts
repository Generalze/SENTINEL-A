import { createSign, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import {
  P256_CURVE_ORDER,
  P256_HALF_CURVE_ORDER,
  canonicalDeviceOfflineOperationStatement,
  deviceCanonicalDigest,
  deviceOfflineOperationStatementInput,
  encodeCanonicalP256Signature,
} from '@sentinel/contracts';
import { CONTAINERS, execInContainer } from './docker';

/**
 * WP-30 — DRIVING THE EDGE'S OWN INGRESS AND QUEUE FROM THE HARNESS.
 *
 * Everything here talks to the Edge over HTTP exactly as a Field client would.
 * Nothing reaches into its SQLite file, and that restriction is the point: a
 * harness that inspected the store directly could assert a queue state the
 * Edge's own API would never report, and Proof D would then be evidence about
 * a database rather than about a system.
 *
 * FROM THE SITE LAN, NEVER FROM THE HOST.
 * ---------------------------------------
 * An earlier revision of this file posted to the Edge's PUBLISHED port from the
 * test process. Every scenario that submitted during an outage then failed with
 * a transport error, and the cause was the harness rather than the Edge:
 * `wan.cut()` detaches the Edge from the `wan` network, and a published port is
 * a DNAT rule to a container address on a specific network -- so cutting the
 * WAN can take the host's route to the Edge with it, even though the site LAN
 * is untouched and the Edge is serving perfectly.
 *
 * That is not a quirk to work around. It is the harness measuring from a
 * position no Field device occupies. A handset lives on the site LAN, so the
 * harness submits from `field-lan-witness`, which is on the `field` network and
 * nothing else. What it observes is then what a device would observe, and the
 * published port stops being load-bearing for any assertion.
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
 * A P-256 keypair standing in for a Field device, generated per harness run.
 *
 * REAL KEY MATERIAL, REAL SIGNATURES, AND STILL NOT A DEVICE. The envelope
 * schema requires a well-formed low-S signature, so the harness must actually
 * sign -- there is no shortcut past it, which is exactly as intended. What this
 * does NOT establish is hardware-backed identity: the key lives in this
 * process, not in a StrongBox, and the Edge ingress does not verify the
 * signature anyway (it is a witness and a buffer; central re-verifies on
 * replay).
 *
 * So these scenarios exercise QUEUEING and RECOVERY truthfully and assert
 * nothing whatever about device trust. That claim belongs to WP-26/WP-28 with
 * a real handset, and this harness must not appear to make it.
 */
const deviceKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

/** Canonical low-S IEEE-P1363, because the contract brands only low-S (C14-01). */
function signCanonical(message: string): string {
  const signer = createSign('sha256');
  signer.update(Buffer.from(message, 'utf8'));
  signer.end();
  const raw = signer.sign({ key: deviceKey.privateKey, dsaEncoding: 'ieee-p1363' });
  const r = BigInt(`0x${raw.subarray(0, 32).toString('hex')}`);
  const rawS = BigInt(`0x${raw.subarray(32, 64).toString('hex')}`);
  const s = rawS > P256_HALF_CURVE_ORDER ? P256_CURVE_ORDER - rawS : rawS;
  return encodeCanonicalP256Signature(r, s);
}

/**
 * Builds one device-signed offline operation envelope.
 *
 * Every field the FROZEN schema requires, signed over the contract's own
 * canonical statement. An earlier revision invented a `schema_version: 2`
 * shape with half the fields missing; the Edge refused it with a 400, which
 * was the schema doing its job and the harness getting the contract wrong.
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
  const unsigned = {
    schema_version: 1 as const,
    offline_operation_id: input.offlineOperationId ?? randomUUID(),
    organisation_id: input.organisationId,
    site_id: input.siteId,
    actor_user_id: input.actorUserId,
    device_id: input.deviceId,
    key_id: `${input.deviceId}_key`,
    key_version: 1,
    operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE' as const,
    device_sequence: input.deviceSequence,
    idempotency_key: randomUUID(),
    payload_digest: canonicalDigest(payload),
    policy_lease_id: `${input.deviceId}_lease`,
    nonce: randomBytes(24).toString('base64url'),
    created_at: '2026-09-07T00:00:00.000Z',
    claimed_signature_profile: 'P256_ECDSA_SHA256' as const,
  };

  const statement = canonicalDeviceOfflineOperationStatement(
    deviceOfflineOperationStatementInput(
      { ...unsigned, signature: PLACEHOLDER_SIGNATURE } as never,
      'P256_ECDSA_SHA256',
    ),
  );

  return { envelope: { ...unsigned, signature: signCanonical(statement) }, payload };
}

/**
 * A syntactically valid signature used only to satisfy the statement builder,
 * which takes a whole envelope and strips the signature out before
 * canonicalising. It is never transmitted -- the returned envelope carries the
 * real one.
 */
const PLACEHOLDER_SIGNATURE = encodeCanonicalP256Signature(1n, 1n);

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
 * The request the LAN witness runs. Plain `node:http`, because the witness is a
 * minimal container and nothing may be installed into it at test time.
 *
 * It never throws: a transport failure is reported as status 0, which is how
 * "no answer arrived" is expressed everywhere in this system. A helper that
 * threw would make "the Edge refused" indistinguishable from "the harness
 * broke", and those are the two findings a scenario most needs to tell apart.
 */
const REQUEST_SOURCE = `
const http = require('node:http');
const [host, port, path, method, body] = process.argv.slice(1);
const payload = body === '' ? null : Buffer.from(body, 'base64');
const request = http.request(
  { host, port: Number(port), path, method, timeout: 10000,
    headers: payload === null ? {} : { 'content-type': 'application/json', 'content-length': payload.length } },
  (response) => {
    let text = '';
    response.setEncoding('utf8');
    response.on('data', (chunk) => { text += chunk; });
    response.on('end', () => {
      process.stdout.write(JSON.stringify({ status: response.statusCode, text }));
      process.exit(0);
    });
  },
);
request.on('timeout', () => { request.destroy(new Error('ETIMEDOUT')); });
request.on('error', (error) => {
  process.stdout.write(JSON.stringify({ status: 0, text: String(error && error.code ? error.code : error) }));
  process.exit(0);
});
if (payload !== null) request.write(payload);
request.end();
`;

async function requestFromLan(
  path: string,
  method: 'GET' | 'POST',
  body: unknown,
): Promise<{ status: number; text: string }> {
  const encoded = body === undefined ? '' : Buffer.from(JSON.stringify(body), 'utf8').toString('base64');
  const { stdout } = await execInContainer(CONTAINERS.fieldLanWitness, [
    'node',
    '-e',
    REQUEST_SOURCE,
    '--',
    CONTAINERS.edge,
    '3100',
    path,
    method,
    encoded,
  ]);
  try {
    return JSON.parse(stdout) as { status: number; text: string };
  } catch {
    return { status: 0, text: stdout };
  }
}

/**
 * Hands one operation to the Edge, as a Field client on the site LAN would.
 *
 * Never throws on a refusal: the STATUS is the finding.
 */
export async function submitToEdge(operation: FieldOperation): Promise<EdgeSubmitOutcome> {
  const answer = await requestFromLan('/edge/v1/field-operations', 'POST', operation);

  let body: { outcome?: unknown; offline_operation_id?: unknown } = {};
  try {
    body = JSON.parse(answer.text) as typeof body;
  } catch {
    // A body we cannot read is not a body we may invent.
  }

  return {
    status: answer.status,
    outcome: typeof body.outcome === 'string' ? body.outcome : null,
    offlineOperationId: typeof body.offline_operation_id === 'string' ? body.offline_operation_id : null,
  };
}

/** The Edge's own account of its durable store, asked from the site LAN. */
export async function edgeQueueDepth(): Promise<{ readonly reachable: boolean; readonly storage: string | null }> {
  const answer = await requestFromLan('/health/ready', 'GET', undefined);
  if (answer.status === 0) return { reachable: false, storage: null };
  try {
    const body = JSON.parse(answer.text) as { dependencies?: Record<string, string> };
    return { reachable: answer.status >= 200 && answer.status < 300, storage: body.dependencies?.queue_storage ?? null };
  } catch {
    return { reachable: false, storage: null };
  }
}
