import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { IncidentsModule } from '../incidents/incidents.module';
import { FailClosedWhisperDeviceKeyResolver, WHISPER_DEVICE_KEY_RESOLVER } from './whisper-key.resolver';
import { WhisperSignatureVerifier } from './whisper-signature.verifier';
import { WhisperController } from './whisper.controller';
import { WhisperRepository } from './whisper.repository';
import { WhisperService } from './whisper.service';

/**
 * WP-21B Whisper.
 *
 * The controller is STUDIO ONLY. There is deliberately no recognition route —
 * see the controller's own header for the W21-05 argument. The runtime is
 * reached through the exported service, so the transport can only be wired by
 * something that can actually establish an authenticated device context.
 *
 * IncidentsModule is imported rather than IncidentsRepository, and that is the
 * point (the WP-20/C10-10 precedent): a recognised signal must enter the SAME
 * already-proven SILENT response path the Fusion source uses — the same
 * PB-PROOF-A tasks, the same Constitution evaluation, the same requirement for
 * two distinct site-commander approvals before anything is dispatched.
 * Reaching past the service to the repository would let this module assemble
 * its own version of that path, which W21-10 exists to prevent: recognition
 * INITIATES the protocol, it never redefines it.
 *
 * FieldModule is deliberately NOT imported. The only Field fact the runtime
 * needs is one operative's own current state, read as a single column to
 * answer a W21-07 server fact — the same shape as patrol's
 * `operativeCanReceive` and this module's own `siteExistsInOrganisation`. It
 * is a read, not a write, so there is no Field rule for it to bypass and no
 * reason to take a module dependency for it.
 *
 * The key resolver is provided by TOKEN so the seam is replaceable: a real
 * device-identity facility swaps this one provider and nothing else in the
 * runtime path changes. Until then it resolves nothing and every recognition
 * refuses with SIGNATURE_INVALID, which is the correct behaviour for a silent
 * duress channel with no way to authenticate a device.
 */
@Module({
  imports: [PrismaModule, IncidentsModule],
  controllers: [WhisperController],
  providers: [
    WhisperRepository,
    WhisperService,
    WhisperSignatureVerifier,
    { provide: WHISPER_DEVICE_KEY_RESOLVER, useClass: FailClosedWhisperDeviceKeyResolver },
  ],
  exports: [WhisperService],
})
export class WhisperModule {}
