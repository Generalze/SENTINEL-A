import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { FieldMessagingModule } from '../field-messaging/field-messaging.module';
import { FieldModule } from '../field/field.module';
import { FieldOfflineRepository } from './field-offline.repository';
import { FieldOfflineReplayService } from './field-offline.service';

/**
 * WP-20 Checkpoint B offline replay.
 *
 * NO CONTROLLER, DELIBERATELY (C10-02). `device_id` read from a JSON body is
 * not authenticated device identity, and this executor's entire safety
 * argument rests on `AuthenticatedFieldDeviceContext` being TRUSTED. Exposing
 * a route before a genuine device-authentication facility exists would mean
 * accepting that context from the wire — the precise trust hole the ruling
 * forbids. The seam is an exported service; whoever builds that facility wires
 * the transport.
 *
 * It imports FieldModule and FieldMessagingModule rather than reaching for
 * their repositories: replay must go through the SAME service entry points the
 * live HTTP routes use, so every domain rule, idempotency table and
 * authorisation check applies identically online and on reconnect (C10-10).
 */
@Module({
  imports: [PrismaModule, FieldModule, FieldMessagingModule],
  providers: [FieldOfflineRepository, FieldOfflineReplayService],
  exports: [FieldOfflineReplayService],
})
export class FieldOfflineModule {}
