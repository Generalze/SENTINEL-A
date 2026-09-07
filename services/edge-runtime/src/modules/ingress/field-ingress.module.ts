import { Module } from '@nestjs/common';
import { EdgeQueueModule } from '../queue/edge-queue.module';
import { FieldIngressController } from './field-ingress.controller';

/**
 * WP-30 — the Field -> Edge ingress.
 *
 * IT IMPORTS THE QUEUE AND NOTHING ELSE. The Edge buffers and witnesses; it
 * does not authorise. Importing an authority module here would be the first
 * step towards an Edge with a second opinion about whether a Field operation
 * is permitted, and central's opinion is the only one that decides.
 *
 * The controller is registered here rather than in `EdgeQueueModule` so the
 * store keeps no HTTP surface of its own -- a durable store that published a
 * route would be a store somebody could reach without going through the one
 * handler that validates a submission.
 */
@Module({
  imports: [EdgeQueueModule],
  controllers: [FieldIngressController],
})
export class FieldIngressModule {}
