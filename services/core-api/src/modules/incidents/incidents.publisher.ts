import { Inject, Injectable, Logger } from '@nestjs/common';
import { JSONCodec } from 'nats';
import { NatsProvider } from '../../infra/nats.provider';
import { incidentUpdatedSubject } from './incidents.constants';
import type { IncidentDetailView } from './incidents.types';

/** Plain NATS notification only: the database remains authoritative when NATS is down. */
@Injectable()
export class IncidentsPublisher {
  private readonly logger = new Logger(IncidentsPublisher.name);
  private readonly codec = JSONCodec<IncidentDetailView>();

  constructor(@Inject(NatsProvider) private readonly nats: NatsProvider) {}

  async publishUpdated(incident: IncidentDetailView): Promise<boolean> {
    if (!this.nats.isConfigured()) return false;
    try {
      const nc = await this.nats.getConnection();
      nc.publish(incidentUpdatedSubject(incident.organisation_id), this.codec.encode(incident));
      return true;
    } catch (error) {
      this.logger.warn(`Incident update publish failed for ${incident.id}: ${error instanceof Error ? error.message : String(error)}`);
      return false;
    }
  }
}
