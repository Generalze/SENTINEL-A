import { Injectable } from '@nestjs/common';
import type { KeyObject } from 'node:crypto';

/**
 * B11-08: THE SERVER-OWNED DEVICE-KEY SEAM.
 *
 * W21-05 fixes the rule this interface exists to serve: signature
 * verification is performed against a key the PLATFORM believes belongs to the
 * device, resolved by `AuthenticatedWhisperDeviceContext.verification_key_id`,
 * and never against a key travelling with the claim it is supposed to
 * authenticate. A submitted result carries a signature; it does not, and must
 * never, carry the key that checks it.
 *
 * THIS IS A SEAM, NOT A FAKE REGISTRY. No production device-identity facility
 * exists yet, and the honest consequence of that is that no key can be
 * resolved — not that keys can be invented. The default implementation below
 * therefore returns `null` for every lookup, which makes every runtime
 * recognition refuse with SIGNATURE_INVALID until a real facility is wired in.
 * A silent duress channel that verified against something improvised would be
 * strictly worse than one that does not fire at all: the operative retains
 * every ordinary alarm path either way, whereas a forgeable signature would
 * hand an attacker a silent dispatch.
 *
 * The lookup is keyed by ORGANISATION AND key id together. A key id is a
 * registry identifier, not a global secret, so keying it by id alone would let
 * one tenant's registered key be selected by another tenant's device context —
 * the §62.1 defence-in-depth argument the persistence layer already makes with
 * its composite (id, organisation_id) references.
 */
export interface WhisperDeviceKeyResolver {
  /**
   * The Ed25519 PUBLIC key registered for `verificationKeyId` inside
   * `organisationId`, or `null` when no such key is registered.
   *
   * `null` is a normal, expected answer and is always FAIL-CLOSED: the caller
   * treats an unresolvable key as an unverifiable signature. An implementation
   * must never throw to mean "not found", and must never return a key it did
   * not resolve from its own registry.
   */
  resolveVerificationKey(organisationId: string, verificationKeyId: string): Promise<KeyObject | null>;
}

/**
 * The Nest injection token for the resolver.
 *
 * An interface has no runtime identity, so the token is explicit. It is
 * exported so a test can provide a deterministic Ed25519 key pair — which is
 * the whole reason the resolver is an injected collaborator rather than a
 * function the verifier calls directly.
 */
export const WHISPER_DEVICE_KEY_RESOLVER = Symbol('WHISPER_DEVICE_KEY_RESOLVER');

/**
 * B11-08: the default, and the only implementation this work package ships.
 *
 * It resolves NOTHING, deliberately. Every parameter is omitted from the
 * signature rather than accepted and ignored, so the code cannot read as
 * though a lookup were being performed: there is no registry to look in.
 * Replacing this provider is the single wiring change a real device-identity
 * facility needs to make; nothing else in the runtime path knows where a key
 * comes from.
 */
@Injectable()
export class FailClosedWhisperDeviceKeyResolver implements WhisperDeviceKeyResolver {
  async resolveVerificationKey(): Promise<KeyObject | null> {
    return null;
  }
}
