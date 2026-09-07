import { BadRequestException, Body, Controller, Inject, Post, ServiceUnavailableException } from '@nestjs/common';
import {
  DeviceOfflineOperationEnvelopeSchema,
  canonicalDeviceJson,
  deviceCanonicalDigest,
} from '@sentinel/contracts';
import { EDGE_OPERATION_STORE } from '../queue/edge-queue.module';
import type { SqliteEdgeOperationStore } from '../queue/edge-queue.store';

/**
 * WP-30 — HOW A FIELD OPERATION ACTUALLY REACHES THE EDGE.
 *
 * WHY THIS DID NOT EXIST UNTIL NOW
 * --------------------------------
 * The Edge had a durable queue, a trusted-time store and a health surface, and
 * no way for a handset to hand it anything. That was the honest state while
 * there was no channel distributing an Edge address and a pinned TLS anchor to
 * a device: an ingress nobody could reach securely would have been a surface
 * with no legitimate caller. M3B §2 built that channel, so this is now the
 * other half of a route that has a trusted client.
 *
 * WHAT THE EDGE IS, AND IS NOT, ON THIS PATH
 * ------------------------------------------
 * The Edge is a WITNESS and a BUFFER. It does not authorise the operation, it
 * does not evaluate the operative's authority, and it does not decide whether
 * the domain will accept it. It records that a device-signed envelope was
 * presented at a time it can attest to, and holds it until central can be
 * reached.
 *
 * So there is deliberately NO authority evaluation here. Adding one would
 * create a second opinion about whether a Field operation is permitted --
 * central's being the first -- and the two would diverge exactly when it
 * mattered. Central re-evaluates everything on replay; that is the design, and
 * an Edge that pre-approved would be an Edge that could disagree.
 *
 * THE RECEIPT IS MINTED INSIDE THE STORE'S TRANSACTION.
 * `edge_monotonic_position` is inside the receipt's signature, so nothing can
 * be signed before the store has allocated a position, and the store must not
 * allocate before it has decided to accept. The callback closes that loop.
 *
 * AN EDGE WITH NO TRUSTED TIME STILL ACCEPTS THE OPERATION and mints no
 * receipt. That is a first-class outcome: central then fails a time-bounded
 * operation closed at NO_TRUSTWORTHY_TIME_WITNESS, which is visible. An Edge
 * that manufactured a time from its host clock would convert that visible
 * refusal into an invisible forgery.
 */
@Controller('edge/v1')
export class FieldIngressController {
  constructor(@Inject(EDGE_OPERATION_STORE) private readonly queue: SqliteEdgeOperationStore) {}

  /**
   * One device-signed operation, buffered for later synchronisation.
   *
   * The response tells the device what the EDGE did -- accepted, already held,
   * or refused for capacity -- and nothing about what central will decide. A
   * device that read an Edge acknowledgement as an application would be making
   * exactly the mistake `CENTRAL_RECEIVED` and `CENTRAL_APPLIED` exist to keep
   * apart.
   */
  @Post('field-operations')
  async accept(@Body() body: unknown): Promise<unknown> {
    const parsed = FieldOperationSubmissionSchema(body);
    if (parsed === null) throw new BadRequestException({ error: 'EDGE_SUBMISSION_MALFORMED' });

    const { envelope, payload } = parsed;

    // The canonical TEXT the device digested, stored byte for byte. Recomputed
    // here from the parsed payload so what the queue holds is what the digest
    // covers -- not a re-serialisation that might differ in key order.
    const payloadCanonicalJson = canonicalDeviceJson(payload);
    if (deviceCanonicalDigest(payload) !== envelope.payload_digest) {
      // The envelope's own digest does not describe the payload beside it. The
      // Edge cannot witness an operation whose contents it cannot bind.
      throw new BadRequestException({ error: 'EDGE_SUBMISSION_DIGEST_MISMATCH' });
    }

    const admission = this.queue.admit({
      envelope,
      payloadCanonicalJson,
      // NO WITNESS CALLBACK IS SUPPLIED, and that is deliberate rather than
      // unfinished.
      //
      // Minting a receipt requires signing with the Edge's application key over
      // a statement containing `edge_trusted_time`, which requires a VERIFIED
      // central-signed anchor. This deployment path does not yet hold one at
      // ingress time, and the store documents omission as a FIRST-CLASS,
      // CORRECT outcome: the operation is queued, no receipt is minted, and
      // central fails a time-bounded operation closed at
      // NO_TRUSTWORTHY_TIME_WITNESS.
      //
      // That refusal is VISIBLE. An Edge that supplied a witness built from its
      // host wall clock, or from an unverified anchor, would convert it into an
      // invisible forgery -- which is the single thing this whole subsystem
      // exists to prevent.
    });

    switch (admission.outcome) {
      case 'ADMITTED':
        return { outcome: 'QUEUED', offline_operation_id: envelope.offline_operation_id };
      case 'DUPLICATE_OPERATION_ID':
        // A RETRYING DEVICE IS EXPECTED TO DO THIS, and it is not an error.
        // Converging tells the device it is safe to stop retrying without
        // implying central applied anything.
        return { outcome: 'ALREADY_QUEUED', offline_operation_id: envelope.offline_operation_id };
      case 'SEQUENCE_POSITION_ALREADY_HELD':
        // A DIFFERENT operation already holds this device position. Accepting
        // would let a changed request hide behind an old sequence number.
        throw new BadRequestException({ error: 'EDGE_SEQUENCE_POSITION_HELD' });
      case 'AT_CAPACITY':
      case 'POSITION_SPACE_EXHAUSTED':
        // 503, not 400. The device did nothing wrong and should retry later;
        // a 4xx would tell it to stop, and the operation would be lost.
        throw new ServiceUnavailableException({ error: 'EDGE_QUEUE_AT_CAPACITY' });
      default:
        throw new ServiceUnavailableException({ error: 'EDGE_QUEUE_UNAVAILABLE' });
    }
  }
}

/**
 * The submission shape, parsed defensively.
 *
 * Returns `null` rather than throwing so the caller owns the response, and
 * narrows to the frozen envelope schema so nothing downstream sees an
 * unvalidated object.
 */
function FieldOperationSubmissionSchema(
  body: unknown,
): { envelope: ReturnType<typeof DeviceOfflineOperationEnvelopeSchema.parse>; payload: unknown } | null {
  if (typeof body !== 'object' || body === null) return null;
  const record = body as Record<string, unknown>;
  const envelope = DeviceOfflineOperationEnvelopeSchema.safeParse(record['envelope']);
  if (!envelope.success) return null;
  if (!('payload' in record)) return null;
  return { envelope: envelope.data, payload: record['payload'] };
}
