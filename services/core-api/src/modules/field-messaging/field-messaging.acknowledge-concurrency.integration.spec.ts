import { randomUUID } from 'node:crypto';
import { Prisma } from '@prisma/client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AppConfig } from '../../config/env.schema';
import type { AppConfigService } from '../../config/config.service';
import { PrismaService } from '../../prisma/prisma.service';
import { TIMELINE_MESSAGE_ACKNOWLEDGED } from './field-messaging.constants';
import { FieldMessagingRepository } from './field-messaging.repository';

/**
 * WP-25/D25-16A — the acknowledgement race, proved against real Postgres.
 *
 * Before this correction `acknowledge()` read the recipient through the
 * message relation, checked its state and updated, holding nothing. Two valid
 * acknowledgements carrying DIFFERENT idempotency identities could both
 * observe DELIVERED before either committed, and both would transition —
 * writing two timeline entries and two outbox rows for a transition §76 says
 * happens once.
 *
 * This spec stages exactly that interleaving: two real concurrent
 * transactions, each of which HAS observed DELIVERED before either proceeds,
 * released together by a barrier. It asserts the outcome, not the mechanism:
 * one authoritative ACKNOWLEDGED transition, one timeline entry, one outbox
 * row, one idempotency row.
 *
 * D25-08: this spec boots NO application module, so it starts no scheduler and
 * adds no cross-suite state coupling. It drives the repository directly with
 * its own PrismaService, over fixtures under a unique tag it deletes after
 * itself.
 */

function appConfig(): AppConfigService {
  const values: AppConfig = {
    DATABASE_URL: process.env.DATABASE_URL ?? 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
    NATS_URL: 'nats://127.0.0.1:4222',
    REDIS_URL: 'redis://localhost:6379',
    S3_ENDPOINT: 'http://localhost:9000',
    S3_ACCESS_KEY: 'sentinel',
    S3_SECRET_KEY: 'sentinel123',
    S3_BUCKET: 'sentinel-dev',
    S3_EVIDENCE_BUCKET: 'sentinel-evidence',
    S3_REGION: 'us-east-1',
    PORT: 3000,
    LOG_LEVEL: 'error',
    DEV_AUTH_ENABLED: true,
  };
  return { values } as AppConfigService;
}

const tag = `wp25ack_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;
const fx = {
  org: `${tag}_org`,
  site: `${tag}_site`,
  sender: `${tag}_sender`,
  recipient: `${tag}_recipient`,
  incident: randomUUID(),
};

const siteScope = { orgWide: false, siteIds: [fx.site] };

describe('WP-25/D25-16A concurrent acknowledgement (live stack)', () => {
  const prisma = new PrismaService(appConfig());
  const repository = new FieldMessagingRepository(prisma);

  beforeAll(async () => {
    await prisma.organisation.create({ data: { id: fx.org, name: 'WP-25 ack race' } });
    await prisma.site.create({ data: { id: fx.site, organisationId: fx.org, name: 'ack-race-site' } });
    for (const id of [fx.sender, fx.recipient]) {
      await prisma.user.create({
        data: { id, organisationId: fx.org, email: `${id}@example.invalid`, displayName: id, clearance: 5, roles: { create: [{ role: 'field.operative', siteId: fx.site }] } },
      });
    }
    const hypothesisId = randomUUID();
    await prisma.incident.create({
      data: {
        id: fx.incident,
        hypothesisId,
        incidentCandidateId: randomUUID(),
        sourceKind: 'FUSION_HYPOTHESIS',
        sourceRef: hypothesisId,
        organisationId: fx.org,
        siteId: fx.site,
        incidentType: 'wp25.ack-race',
        severity: 'SEV3',
        threatState: 2,
        confidence: 0.9,
        responseMode: 'STANDARD',
      },
    });
  }, 60_000);

  afterAll(async () => {
    await prisma.incidentFieldMessageActionIdempotency.deleteMany({ where: { message: { organisationId: fx.org } } });
    await prisma.incidentFieldMessageRecipient.deleteMany({ where: { organisationId: fx.org } });
    await prisma.incidentFieldMessageOutbox.deleteMany({ where: { organisationId: fx.org } });
    await prisma.incidentFieldMessage.deleteMany({ where: { organisationId: fx.org } });
    await prisma.incidentTimelineEntry.deleteMany({ where: { incidentId: fx.incident } });
    await prisma.incident.deleteMany({ where: { organisationId: fx.org } });
    await prisma.userRole.deleteMany({ where: { user: { organisationId: fx.org } } });
    await prisma.user.deleteMany({ where: { organisationId: fx.org } });
    await prisma.site.deleteMany({ where: { organisationId: fx.org } });
    await prisma.organisation.deleteMany({ where: { id: fx.org } });
    await prisma.$disconnect();
  }, 30_000);

  /** A DELIVERED recipient row — the only state acknowledgement may advance. */
  async function deliveredMessage(): Promise<string> {
    const created = await prisma.incidentFieldMessage.create({
      data: {
        organisationId: fx.org,
        siteId: fx.site,
        incidentId: fx.incident,
        senderUserId: fx.sender,
        body: 'Proceed to the north gate.',
        retentionClass: 'operational-30d',
        idempotencyKey: `send-${randomUUID()}`,
        traceId: `trace-${randomUUID()}`,
        recipients: {
          create: [{ organisationId: fx.org, siteId: fx.site, recipientUserId: fx.recipient, deliveryState: 'DELIVERED', deliveredAt: new Date() }],
        },
      },
    });
    return created.id;
  }

  it('two concurrent acknowledgements of one DELIVERED recipient produce exactly ONE transition, one timeline entry and one outbox row', async () => {
    const messageId = await deliveredMessage();

    // The barrier: neither transaction proceeds past its observation until
    // BOTH have made it. Without it the two would very likely serialise by
    // accident and the spec would pass on a system that still had the race.
    let arrived = 0;
    let release = (): void => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const barrier = async (): Promise<void> => {
      arrived += 1;
      if (arrived === 2) release();
      return gate;
    };

    const observed: string[] = [];
    const attempt = (idempotencyKey: string) =>
      prisma.$transaction(
        async (tx) => {
          // The stale observation the old code would have decided on.
          const seen = await tx.incidentFieldMessageRecipient.findFirstOrThrow({ where: { messageId, recipientUserId: fx.recipient } });
          observed.push(seen.deliveryState);
          await barrier();
          return repository.acknowledge(fx.org, messageId, fx.recipient, idempotencyKey, siteScope, 'DELIVERED', tx as unknown as Prisma.TransactionClient);
        },
        { timeout: 30_000, maxWait: 30_000 },
      );

    // DIFFERENT idempotency identities: neither the domain idempotency row nor
    // the gateway replay identity can be what serialises them. Only the row
    // lock can.
    const results = await Promise.all([attempt(`ack-a-${randomUUID()}`), attempt(`ack-b-${randomUUID()}`)]);

    // Both really did observe DELIVERED before either committed — the race
    // window was open, and the lock is what closed it.
    expect(observed).toEqual(['DELIVERED', 'DELIVERED']);

    const kinds = results.map((result) => result.kind).sort();
    expect(kinds).toEqual(['acknowledged', 'duplicate']);

    const recipient = await prisma.incidentFieldMessageRecipient.findFirstOrThrow({ where: { messageId, recipientUserId: fx.recipient } });
    expect(recipient.deliveryState).toBe('ACKNOWLEDGED');

    expect(
      await prisma.incidentTimelineEntry.count({
        where: { incidentId: fx.incident, kind: TIMELINE_MESSAGE_ACKNOWLEDGED, payload: { path: ['incident_field_message_id'], equals: messageId } },
      }),
    ).toBe(1);
    expect(await prisma.incidentFieldMessageOutbox.count({ where: { payload: { path: ['message_id'], equals: messageId } } })).toBe(1);
    expect(await prisma.incidentFieldMessageActionIdempotency.count({ where: { messageId, action: 'acknowledge' } })).toBe(1);
  }, 60_000);

  it('an acknowledgement composed into an EXTERNAL transaction that rolls back leaves no trace', async () => {
    const messageId = await deliveredMessage();

    // D25-02's COMMIT TOGETHER, from the other side: if the orchestrator's
    // transaction fails, the acknowledgement must not survive it. That is only
    // true because the seam declines to open a transaction of its own.
    await expect(
      prisma.$transaction(async (tx) => {
        const result = await repository.acknowledge(fx.org, messageId, fx.recipient, `ack-rollback-${randomUUID()}`, siteScope, 'DELIVERED', tx as unknown as Prisma.TransactionClient);
        expect(result.kind).toBe('acknowledged');
        throw new Error('orchestrator failed after the domain effect');
      }),
    ).rejects.toThrow('orchestrator failed after the domain effect');

    const recipient = await prisma.incidentFieldMessageRecipient.findFirstOrThrow({ where: { messageId, recipientUserId: fx.recipient } });
    expect(recipient.deliveryState).toBe('DELIVERED');
    expect(recipient.acknowledgedAt).toBeNull();
    expect(
      await prisma.incidentTimelineEntry.count({
        where: { incidentId: fx.incident, kind: TIMELINE_MESSAGE_ACKNOWLEDGED, payload: { path: ['incident_field_message_id'], equals: messageId } },
      }),
    ).toBe(0);
    expect(await prisma.incidentFieldMessageOutbox.count({ where: { payload: { path: ['message_id'], equals: messageId } } })).toBe(0);
    expect(await prisma.incidentFieldMessageActionIdempotency.count({ where: { messageId, action: 'acknowledge' } })).toBe(0);
  }, 60_000);
});
