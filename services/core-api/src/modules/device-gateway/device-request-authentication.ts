import {
  DeviceRequestProofSchema,
  canonicalDeviceRequestProofStatement,
  deviceRequestProofFingerprint,
  deviceRequestProofReplayKey,
  deviceRequestProofStatementInput,
  type DeviceRequestProof,
  type DeviceSignatureProfile,
} from '@sentinel/contracts';
import type { Principal } from '../../common/security/principal';
import type { P256KeyImporter } from '../shield/p256-key.importer';
import type { DeviceGatewayRepository, GatewayTx, IssuedContextRow } from './device-gateway.repository';
import type { DeviceGatewayRefusal } from './device-gateway.types';

/**
 * M3B §3 — THE DEVICE-AUTHENTICATION CORE, WITH ONE IMPLEMENTATION.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Two request shapes now need the same authentication and diverge only after
 * it:
 *
 *     EFFECT OPERATION      authenticate -> required §62 action -> domain effect
 *     AUTHENTICATED QUERY   authenticate -> site/context authority -> descriptor
 *
 * The wrong ways to get there were both considered and both rejected. Adding an
 * `EDGE_TRANSPORT_DESCRIPTOR` member to the gateway OPERATION KIND enum would
 * have bought authentication by corrupting the domain model: an operation kind
 * selects a target type, a §62 action, a purpose and a semantic payload, and a
 * descriptor lookup is none of those. Audit rows would then say an operation
 * occurred when Sentinel had only returned trust material, and D25-10's
 * property -- that absent operations are structurally unreachable rather than
 * merely unauthorised -- would be weakened by a non-operation added purely as
 * an authentication adapter.
 *
 * Reimplementing the pipeline was worse: a second resolution of device trust,
 * context-site membership, principal equality and signature verification is a
 * second §62.1 path, and the two would diverge on the day one of them was
 * fixed.
 *
 * So the shared part lives here and is called by both. This file deliberately
 * knows nothing about operation kinds, required actions, targets or payloads.
 * If a future change makes it need one, that is the signal that the wrong thing
 * is being shared.
 *
 * WHAT IS NOT HERE, AND WHY
 * -------------------------
 * No audit. Each caller files its own event, because the two record different
 * things -- an operation refusal names a target type and a payload digest; a
 * descriptor refusal names neither and must not pretend to. A shared audit
 * writer would have to invent one shape that fits both, and inventing a target
 * for a query is exactly the pollution this design avoids.
 *
 * No purpose decision. The caller supplies the purpose it expects, and the
 * frozen evaluator does the comparison. This file never chooses what a proof is
 * for.
 */

/**
 * The stage that establishes WHO, before anything is verified.
 *
 * Deliberately ordered: the proof's shape, then the context resolved BY THE
 * SESSION'S TENANT, then the two equality bindings. Nothing here trusts a
 * claimed identifier -- `proof.organisation_id` is compared against the
 * persisted context's and never used to select it (C17-02), and a valid proof
 * carried by a different authenticated human refuses (C17-01), because holding
 * the hardware does not make the caller the operative the context is bound to.
 */
export type ProvenContextResolution =
  | { readonly ok: false; readonly refusal: DeviceGatewayRefusal; readonly proof: DeviceRequestProof | null }
  | {
      readonly ok: true;
      readonly proof: DeviceRequestProof;
      readonly contextRow: IssuedContextRow;
      readonly contextSiteIds: readonly string[];
    };

export async function resolveProvenContext(
  repository: DeviceGatewayRepository,
  principal: Principal,
  rawProof: unknown,
): Promise<ProvenContextResolution> {
  const parsedProof = DeviceRequestProofSchema.safeParse(rawProof);
  if (!parsedProof.success) return { ok: false, refusal: 'PROOF_MALFORMED', proof: null };
  const proof = parsedProof.data;

  // C17-02: resolved by (id, organisation) TOGETHER, so a foreign context and
  // a context that never existed produce one answer from one query, and there
  // is no branch in which they could diverge (D25-13).
  const contextRow = await repository.findContext(principal.organisation_id, proof.context_id);
  if (contextRow === null) return { ok: false, refusal: 'CONTEXT_NOT_USABLE', proof };

  if (proof.organisation_id !== contextRow.organisationId) {
    return { ok: false, refusal: 'PROOF_ORGANISATION_MISMATCH', proof };
  }
  if (principal.user.id !== contextRow.actorUserId) {
    return { ok: false, refusal: 'SESSION_ACTOR_MISMATCH', proof };
  }

  const contextSiteIds = await repository.listContextSiteIdsUnlocked(contextRow.organisationId, contextRow.id);
  return { ok: true, proof, contextRow, contextSiteIds };
}

/**
 * The device credential, resolved from the registry AT USE -- never from the
 * context's snapshot. A device the registry has since downgraded is judged on
 * what it is now, which is the defect `DeviceRegistryFacts` was corrected for.
 *
 * GENERIC OVER THE RECORD TYPES, ON PURPOSE.
 *
 * An earlier draft projected the device and key rows down to the four fields
 * this file happens to name. That was wrong: the operation path reads more of
 * both records downstream -- key version, revocation disposition, the key's own
 * tenant and device binding -- and a narrowing projection here would have
 * silently deleted them, turning a shared resolution into a lossy one.
 *
 * So this owns the ORDER and the REFUSALS, which is the part that must not be
 * duplicated, and passes the records through untouched. What is shared is the
 * decision procedure, not a data shape.
 */
export type DeviceCredentialResolution<TDevice, TKey> =
  | { readonly ok: false; readonly refusal: DeviceGatewayRefusal }
  | {
      readonly ok: true;
      readonly device: TDevice;
      readonly keyRecord: TKey;
      readonly trust: string;
      /** Neither the device row nor the key row has withdrawn the credential. */
      readonly credentialIntact: boolean;
    };

export async function resolveDeviceCredential<TDevice extends { id: string; currentKeyId: string | null }, TKey>(
  deps: {
    readonly findDevice: (organisationId: string, deviceId: string, tx?: GatewayTx) => Promise<TDevice | null>;
    readonly resolveRegistryKeyRecord: (organisationId: string, keyId: string, tx?: GatewayTx) => Promise<TKey | null>;
    readonly effectiveDeviceTrust: (organisationId: string, deviceId: string, tx?: GatewayTx) => Promise<string | null>;
    readonly credentialAdmitsNewOperations: (organisationId: string, deviceId: string, tx?: GatewayTx) => Promise<boolean>;
  },
  organisationId: string,
  deviceId: string,
  tx?: GatewayTx,
): Promise<DeviceCredentialResolution<TDevice, TKey>> {
  const device = await deps.findDevice(organisationId, deviceId, tx);
  if (device === null) return { ok: false, refusal: 'DEVICE_NOT_USABLE' };
  if (device.currentKeyId === null) return { ok: false, refusal: 'REGISTRY_KEY_UNRESOLVABLE' };

  // C17-04: `tx` is threaded. Resolving the registry key on the base client
  // while the transaction holds the device and key row locks would be reading a
  // row nothing is holding still, in the transaction that commits on it.
  const keyRecord = await deps.resolveRegistryKeyRecord(organisationId, device.currentKeyId, tx);
  if (keyRecord === null) return { ok: false, refusal: 'REGISTRY_KEY_UNRESOLVABLE' };

  const trust = await deps.effectiveDeviceTrust(organisationId, device.id, tx);
  if (trust === null) return { ok: false, refusal: 'DEVICE_NOT_USABLE' };

  const credentialIntact = await deps.credentialAdmitsNewOperations(organisationId, device.id, tx);

  return { ok: true, device, keyRecord, trust, credentialIntact };
}

/**
 * Possession, and the two identities a replay decision needs.
 *
 * ONE implementation, because a second signature check is a second opinion
 * about what a valid proof is. The profile binding is C15-01: the CLIENT's
 * claimed profile is equality-bound to the one the SERVER resolved from its own
 * registry, so a device cannot choose the profile its signature is checked
 * under.
 */
export interface VerifiedDeviceProof {
  readonly verified: boolean;
  readonly replayKey: string;
  readonly fingerprint: string;
}

export function verifyDeviceProofPossession(
  keys: P256KeyImporter,
  proof: DeviceRequestProof,
  credential: { readonly publicKey: string; readonly signatureProfile: DeviceSignatureProfile },
): VerifiedDeviceProof {
  const statementInput = deviceRequestProofStatementInput(proof, credential.signatureProfile);
  const verified = keys.verifySignature({
    registeredPublicKey: credential.publicKey,
    message: canonicalDeviceRequestProofStatement(statementInput),
    signature: proof.signature,
    serverResolvedProfile: credential.signatureProfile,
    claimedProfile: proof.claimed_signature_profile,
  });

  return {
    verified,
    replayKey: deviceRequestProofReplayKey(proof),
    fingerprint: deviceRequestProofFingerprint(statementInput),
  };
}
