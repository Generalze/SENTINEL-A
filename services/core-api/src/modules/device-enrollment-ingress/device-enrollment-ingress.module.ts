import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { ShieldModule } from '../shield/shield.module';
import { AndroidKeyAttestationVerifier } from './android-key-attestation.verifier';
import { ANDROID_ATTESTATION_TRUST_MATERIAL_PROVIDER } from './android-attestation.configured-trust-material';
import { CommandEnrollmentController } from './command-enrollment.controller';
import { DeviceEnrollmentIngressRepository } from './device-enrollment-ingress.repository';
import { DeviceEnrollmentIngressService } from './device-enrollment-ingress.service';
import { MobileEnrollmentController } from './mobile-enrollment.controller';

/**
 * WP-26 Field Mobile Foundation — the device enrollment ingress.
 *
 * WHAT THIS MODULE OWNS
 * ---------------------
 *   the D26-04A attestation challenge (issue, bind, clamp, one-shot consume)
 *   the D26-04B Android Key Attestation verifier and its DER reader
 *   the trust-material seam — pinned anchors and the revocation snapshot
 *   the restricted attestation artifact, and the ONE place a raw chain rests
 *   the two REST controllers: the mobile ceremony and the Command side
 *
 * WHAT IT DOES NOT OWN, AND MAY NOT REIMPLEMENT
 * ---------------------------------------------
 *   the enrollment ceremony          DeviceEnrollmentService owns it
 *   registry / trust semantics       Shield owns them
 *   the frozen evaluators            packages/contracts owns them
 *   the P-256 runtime boundary       P256KeyImporter owns it (D24-05)
 *
 * It imports ShieldModule and calls exported SERVICES, for the reason
 * `device-gateway.module.ts` gives and D26-09 repeats: every effect must go
 * through the same service entry points, so every domain rule, replay row,
 * security event and authorisation check applies identically. The ingress may
 * not write a Shield table, create a device, mint an approval or move trust.
 * `test/device-enrollment-ingress-boundary.architecture.spec.ts` scans the
 * source for a Shield Prisma model rather than trusting review to notice one.
 *
 * SHIELD KEEPS ZERO CONTROLLERS (D24-13 / D26-09). Both controllers live here.
 * That is the whole reason this module exists rather than a second controller
 * inside Shield: the registry stays reviewable as a module with no HTTP surface,
 * and the ingress's different authentication model has exactly ONE
 * implementation.
 *
 * THE ATTESTATION EVALUATOR IS REGISTERED IN `ShieldModule`, NOT HERE
 * -------------------------------------------------------------------
 * `AndroidKeyAttestationEvaluator` lives in this directory — it is WP-26's code,
 * it reads WP-26's table — but the provider binding is in `shield.module.ts`,
 * because `DeviceEnrollmentService` is constructed in Shield's injector and a
 * provider declared here would never reach it. Nest resolves a token in the
 * injector that constructs the consumer, and pretending otherwise would have
 * shipped a verifier that silently never ran.
 *
 * What makes that safe is that the evaluator is a strict superset of the default
 * it replaces: given no server-owned artifact reference it returns EXACTLY what
 * `UnavailableDeviceAttestationEvaluator` returned — `UNAVAILABLE`, no
 * reference. The only path that can produce anything else is one where THIS
 * module verified a chain and wrote the artifact. See that class's header.
 *
 * TRUST MATERIAL IS INJECTED SERVER CONFIGURATION, AND THE DEFAULT PINS NOTHING
 * -----------------------------------------------------------------------------
 * `UnconfiguredAndroidAttestationTrustMaterial` declares itself unconfigured, so
 * a deployment that has been given no anchors and no revocation snapshot gets
 * `UNAVAILABLE` from the verifier and can never reach `VERIFIED`. That is
 * WP-24's rule — never manufacture evidence — applied to the one place where
 * getting it wrong would be invisible: a WRONG pinned root is worse than a
 * missing one, because a missing one fails closed and a wrong one fails open.
 * Supplying the real Google roots is a deployment act and part of what D26-10's
 * physical-device acceptance has to demonstrate.
 *
 * C18-01 — AND THERE IS NOW SOMETHING TO SUPPLY THEM TO.
 *
 * The token below binds `ConfiguredAndroidAttestationTrustMaterial` whenever
 * trust-material CONFIGURATION IS PRESENT, and falls back to the unconfigured
 * provider only when it is absent entirely. Before that this module hard-bound
 * the unconfigured class, which meant "supplying anchors is a deployment act"
 * described nothing a deployment could actually do: the sole route to
 * `VERIFIED` was a Vitest `.overrideProvider(...)`, so the exact candidate SHA
 * could not have performed its own physical-device acceptance without a
 * test-only edit. The configured provider is reachable by SETTING
 * CONFIGURATION and by nothing else, which is what makes D26-10's acceptance an
 * acceptance of the code that ships.
 *
 * Missing, partial, unparseable or stale material still answers `UNAVAILABLE`.
 * See `android-attestation.configured-trust-material.ts` for the four rules and
 * for the exact keys a deployment must set.
 *
 * NO BACKGROUND SCHEDULER (D25-08, still binding). Every expiry this module
 * enforces — the attestation challenge, the revocation snapshot's freshness — is
 * a comparison taken at request time. No job, no sweeper, no timer, and no new
 * cross-suite state coupling.
 *
 * NO WHISPER WIRING (D26-07). This module does not import WhisperModule and
 * never names `WHISPER_DEVICE_KEY_RESOLVER`. A real phone existing does not
 * authorise touching a frozen M2 cryptographic domain; WP-27 owns that path.
 *
 * REST ONLY. No device WebSocket ingress.
 */
@Module({
  imports: [PrismaModule, ShieldModule],
  controllers: [MobileEnrollmentController, CommandEnrollmentController],
  providers: [
    DeviceEnrollmentIngressRepository,
    AndroidKeyAttestationVerifier,
    DeviceEnrollmentIngressService,
    // C18-01: configuration decides, and the UNCONFIGURED provider is still the
    // default. See `android-attestation.configured-trust-material.ts`.
    ANDROID_ATTESTATION_TRUST_MATERIAL_PROVIDER,
  ],
  exports: [DeviceEnrollmentIngressService, DeviceEnrollmentIngressRepository],
})
export class DeviceEnrollmentIngressModule {}
