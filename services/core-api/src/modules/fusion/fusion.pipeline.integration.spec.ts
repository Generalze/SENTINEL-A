import type { NormalisedEvent } from '@sentinel/contracts';
import { HypothesisSchema } from '@sentinel/contracts';
import { JSONCodec, type Subscription } from 'nats';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { NatsProvider } from '../../infra/nats.provider';
import { PrismaService } from '../../prisma/prisma.service';
import { FUSION_RULES_VERSION, FUSION_RULE_VERSIONS, incidentCandidateSubject } from './fusion.constants';
import { FusionController } from './fusion.controller';
import { FusionPublisherService } from './fusion-publisher.service';
import { FusionRepository } from './fusion.repository';
import { FusionService } from './fusion.service';
import type { IncidentCandidateMessage } from './fusion.types';
import {
  anonymousRequest,
  makeAppConfig,
  makeEvent,
  principalRequest,
  scenarioWindowBase,
  uniqueOrgId,
  uniqueSiteId,
  waitUntil,
} from './test-support';

/**
 * Live-stack integration tests for WP-05 acceptance criteria 1, 2, 4 and 5,
 * plus the incident-candidate latch and the contradiction-surfacing API.
 * Requires the dev compose stack's Postgres (localhost:5433) and NATS
 * (localhost:4222).
 *
 * These drive the real FusionService -> FusionRepository -> PrismaService
 * stack against the actual database (constructed directly, as this repo's
 * other provider tests do), so persistence, the optimistic-concurrency guard
 * and the idempotency constraint are all genuinely exercised. Acceptance
 * criterion 3 and the end-to-end transport path live in
 * fusion.consumer.integration.spec.ts.
 *
 * Every test invents its own organisation and site (uniqueOrgId /
 * uniqueSiteId) so concurrent work packages writing to the same database can
 * never collide with, or be seen by, these assertions. Scenarios are inline
 * fixtures — no dependency on the simulator package.
 */
describe('Fusion pipeline (live stack)', () => {
  const appConfig = makeAppConfig();
  const prisma = new PrismaService(appConfig);
  const nats = new NatsProvider(appConfig);
  const repository = new FusionRepository(prisma);
  const publisher = new FusionPublisherService(nats);
  const service = new FusionService(repository, publisher);
  const controller = new FusionController(service);

  const createdOrgIds: string[] = [];

  function trackOrg(label: string): string {
    const id = uniqueOrgId(label);
    createdOrgIds.push(id);
    return id;
  }

  beforeAll(async () => {
    await prisma.$connect();
  });

  afterEach(async () => {
    if (createdOrgIds.length > 0) {
      // Test-only teardown. Transitions cascade from the hypothesis rows;
      // applied-event rows for ignored events have no hypothesis, so they are
      // deleted by organisation explicitly.
      await prisma.fusionAppliedEvent.deleteMany({ where: { organisationId: { in: createdOrgIds } } });
      await prisma.hypothesis.deleteMany({ where: { organisationId: { in: createdOrgIds } } });
      createdOrgIds.length = 0;
    }
  });

  afterAll(async () => {
    await prisma.onModuleDestroy();
    await nats.onModuleDestroy();
  });

  /**
   * The scripted three-source scenario used by AC1 and AC2.
   *
   * All three events land in one 15-minute correlation window, at one site
   * and zone, from three independent sources:
   *
   *   E1 camera  cam-01     person_detected       trusted  0.5 -> weighted 0.50
   *   E2 sensor  motion-01  motion_detected       trusted  0.5 -> weighted 0.50
   *   E3 access  door-01    access_denied_attempt degraded 0.4 -> weighted 0.20
   *
   * Hand-computed against the certified core's documented formulas:
   *   after E1: support 0.50 -> base 2; diversity 1 -> ceiling 2 -> STATE 2
   *   after E2: support 1-(0.5*0.5) = 0.75 -> base 3; diversity 2 -> STATE 3
   *   after E3: support 1-(0.5*0.5*0.8) = 0.80 -> base 3; the degraded access
   *             source weighs 0.20 so diversity stays 2 -> STATE 3
   */
  function scenarioEvents(organisationId: string, siteId: string): NormalisedEvent[] {
    const base = scenarioWindowBase();
    const at = (offsetSeconds: number): string => new Date(base.getTime() + offsetSeconds * 1000).toISOString();
    const common = { organisation_id: organisationId, site_id: siteId, zone_id: 'zone-lobby' };
    return [
      makeEvent({
        ...common,
        source_type: 'camera',
        source_id: 'cam-01',
        event_type: 'person_detected',
        source_trust: 'trusted',
        confidence: 0.5,
        occurred_at: at(0),
      }),
      makeEvent({
        ...common,
        source_type: 'sensor',
        source_id: 'motion-01',
        event_type: 'motion_detected',
        source_trust: 'trusted',
        confidence: 0.5,
        occurred_at: at(20),
      }),
      makeEvent({
        ...common,
        source_type: 'access',
        source_id: 'door-01',
        event_type: 'access_denied_attempt',
        source_trust: 'degraded',
        confidence: 0.4,
        occurred_at: at(40),
      }),
    ];
  }

  async function replay(events: readonly NormalisedEvent[]): Promise<void> {
    for (const event of events) {
      await service.applyEvent(event);
    }
  }

  it('AC1: a scripted 3-source scenario produces exactly ONE hypothesis that reaches state 3, with transitions and explanations', async () => {
    const orgId = trackOrg('ac1');
    const siteId = uniqueSiteId('ac1');
    const events = scenarioEvents(orgId, siteId);

    await replay(events);

    const rows = await prisma.hypothesis.findMany({ where: { organisationId: orgId } });
    expect(rows).toHaveLength(1);

    const hypothesis = rows[0];
    expect(hypothesis.state).toBe(3);
    expect(hypothesis.threatProbability).toBeCloseTo(0.8, 5);
    expect(hypothesis.detectionConfidence).toBeCloseTo(0.8, 5);
    expect(hypothesis.sourceDiversity).toBe(2);
    expect(hypothesis.supportingEventIds).toEqual(events.map((event) => event.event_id));
    expect(hypothesis.contradictingEventIds).toEqual([]);
    // M1 placeholder impact rule: the ACCESS family arrived with E3.
    expect(hypothesis.potentialImpact).toBe('HIGH');
    expect(hypothesis.operationalSeverity).toBe('SEV3');

    // Transitions logged, in order, each with a non-empty reason.
    const transitions = await prisma.hypothesisTransition.findMany({
      where: { hypothesisId: hypothesis.id },
      orderBy: { sequence: 'asc' },
    });
    expect(transitions.map((t) => [t.sequence, t.fromState, t.toState])).toEqual([
      [0, 0, 2],
      [1, 2, 3],
    ]);
    expect(transitions[0].eventId).toBe(events[0].event_id);
    expect(transitions[1].eventId).toBe(events[1].event_id);
    for (const transition of transitions) {
      expect(transition.reason.length).toBeGreaterThan(0);
    }

    // Explanation strings present and meaningful.
    expect(hypothesis.confidenceExplanation).toContain('Threat state 3 (PROBABLE_THREAT)');
    expect(hypothesis.confidenceExplanation).toContain('Contradicting evidence: none observed');
    expect(hypothesis.confidenceExplanation).toContain('Supporting evidence: 3 signal(s) from 3 source(s) (cam-01, door-01, motion-01)');
    // 3 reporting sources, but only 2 of them cleared the trust-weighted 0.50
    // diversity threshold — the explanation must say both numbers.
    expect(hypothesis.confidenceExplanation).toContain('2 independent supporting sources reached the trust-weighted 0.50 threshold');

    // Every event was recorded exactly once against the hypothesis.
    const applied = await prisma.fusionAppliedEvent.findMany({ where: { organisationId: orgId } });
    expect(applied).toHaveLength(3);
    expect(applied.every((row) => row.hypothesisId === hypothesis.id)).toBe(true);
    expect(applied.every((row) => row.signalKind === 'SUPPORTING')).toBe(true);
  }, 45_000);

  it('AC2: a strong contradicting access event forces the state down and the contradiction is visible in the API output', async () => {
    const orgId = trackOrg('ac2');
    const siteId = uniqueSiteId('ac2');
    const events = scenarioEvents(orgId, siteId);
    await replay(events);

    const before = await prisma.hypothesis.findFirstOrThrow({ where: { organisationId: orgId } });
    expect(before.state).toBe(3);

    // A validly granted credential that ALSO matches the operational schedule:
    // trusted x 0.9 = weighted 0.90, above the core's 0.60 forced-de-escalation
    // threshold, and enough contradiction strength to zero the probability.
    const contradiction = makeEvent({
      organisation_id: orgId,
      site_id: siteId,
      zone_id: 'zone-lobby',
      source_type: 'access',
      source_id: 'door-02',
      event_type: 'access_granted_valid',
      source_trust: 'trusted',
      confidence: 0.9,
      metadata: { schedule_match: true },
      occurred_at: new Date(scenarioWindowBase().getTime() + 60_000).toISOString(),
    });

    const result = await service.applyEvent(contradiction);
    expect(result.outcome).toBe('applied');

    const after = await prisma.hypothesis.findFirstOrThrow({ where: { organisationId: orgId } });
    expect(after.state).toBeLessThan(before.state);
    expect(after.state).toBe(0);
    expect(after.threatProbability).toBe(0);
    // The contradiction is evidence, so detection confidence RISES even as
    // threat probability collapses — the two values are never conflated.
    expect(after.detectionConfidence).toBeGreaterThan(before.detectionConfidence);

    const forcedTransition = await prisma.hypothesisTransition.findFirstOrThrow({
      where: { hypothesisId: after.id, eventId: contradiction.event_id },
    });
    expect(forcedTransition.fromState).toBe(3);
    expect(forcedTransition.toState).toBe(0);
    expect(forcedTransition.reason).toMatch(/strong contradiction/i);

    // --- Contradiction surfacing through the API (deliverable #6) ---
    const req = principalRequest(orgId);
    const list = await controller.list(req, {});
    expect(list.items).toHaveLength(1);
    const listed = list.items[0];
    expect(listed.supporting_event_ids).toEqual(events.map((event) => event.event_id));
    expect(listed.contradicting_event_ids).toEqual([contradiction.event_id]);
    expect(listed.confidence_explanation).toContain('Contradicting evidence: 1 signal(s)');

    const detail = await controller.detail(req, after.id, {});
    expect(detail.contradicting_event_ids).toEqual([contradiction.event_id]);
    expect(detail.supporting_event_ids).toHaveLength(3);
    expect(detail.transitions.map((t) => t.to_state)).toEqual([2, 3, 0]);
    expect(detail.transitions[2].reason).toMatch(/strong contradiction/i);

    // The four separated values travel together and satisfy the §65.3 contract.
    expect(HypothesisSchema.safeParse(detail).success).toBe(true);
    expect(detail.detection_confidence).toBeGreaterThan(0);
    expect(detail.threat_probability).toBe(0);
    expect(detail.potential_impact).toBe('HIGH');
    expect(detail.operational_severity).toBe('SEV4');
  }, 45_000);

  it('AC4: a single prolific source is capped at SUSPICIOUS (2) no matter how much it reports', async () => {
    const orgId = trackOrg('ac4');
    const siteId = uniqueSiteId('ac4');
    const base = scenarioWindowBase();

    const events = Array.from({ length: 5 }, (_unused, index) =>
      makeEvent({
        organisation_id: orgId,
        site_id: siteId,
        zone_id: 'zone-dock',
        source_type: 'camera',
        source_id: 'cam-prolific',
        event_type: 'person_detected',
        source_trust: 'trusted',
        confidence: 0.9,
        occurred_at: new Date(base.getTime() + index * 10_000).toISOString(),
      }),
    );

    await replay(events);

    const rows = await prisma.hypothesis.findMany({ where: { organisationId: orgId } });
    expect(rows).toHaveLength(1);
    const hypothesis = rows[0];

    // Aggregate support saturates (1 - 0.1^5) but diversity never exceeds 1.
    expect(hypothesis.threatProbability).toBeGreaterThan(0.85);
    expect(hypothesis.sourceDiversity).toBe(1);
    expect(hypothesis.state).toBe(2);
    expect(hypothesis.supportingEventIds).toHaveLength(5);
    expect(hypothesis.confidenceExplanation).toMatch(/source-diversity cap holds this hypothesis at SUSPICIOUS/i);

    // Only the first event moved the state; the other four were absorbed.
    const transitions = await prisma.hypothesisTransition.findMany({ where: { hypothesisId: hypothesis.id } });
    expect(transitions).toHaveLength(1);
    expect(transitions[0]).toMatchObject({ fromState: 0, toState: 2, eventId: events[0].event_id });
  }, 45_000);

  it('AC5: the rule-table and core versions are stamped on the hypothesis, every transition, every applied event and the API output', async () => {
    const orgId = trackOrg('ac5');
    const siteId = uniqueSiteId('ac5');
    const events = scenarioEvents(orgId, siteId);
    await replay(events);

    const hypothesis = await prisma.hypothesis.findFirstOrThrow({ where: { organisationId: orgId } });
    expect(hypothesis.ruleVersions).toEqual([...FUSION_RULE_VERSIONS]);
    expect(hypothesis.ruleVersions).toContain('fusion-rules-1.0.0');
    expect(hypothesis.ruleVersions).toContain('fusion-threat-state-1.0.0');

    const transitions = await prisma.hypothesisTransition.findMany({ where: { hypothesisId: hypothesis.id } });
    expect(transitions.length).toBeGreaterThan(0);
    for (const transition of transitions) {
      expect(transition.ruleVersions).toEqual([...FUSION_RULE_VERSIONS]);
    }

    const applied = await prisma.fusionAppliedEvent.findMany({ where: { organisationId: orgId } });
    for (const row of applied) {
      expect(row.ruleVersion).toBe(FUSION_RULES_VERSION);
    }

    // §65.3 rule_or_model_versions reaches the consumer, not just the table.
    const view = await controller.detail(principalRequest(orgId), hypothesis.id, {});
    expect(view.rule_or_model_versions).toEqual([...FUSION_RULE_VERSIONS]);
    expect(view.confidence_explanation).toContain('fusion-rules-1.0.0');
  }, 45_000);

  it('emits an incident-candidate exactly once on crossing state 2, and re-emits with re_escalation after a de-escalation', async () => {
    const orgId = trackOrg('latch');
    const siteId = uniqueSiteId('latch');
    const base = scenarioWindowBase();
    const codec = JSONCodec<IncidentCandidateMessage>();
    const received: IncidentCandidateMessage[] = [];

    const nc = await nats.getConnection();
    const subscription: Subscription = nc.subscribe(incidentCandidateSubject(orgId));
    const drain = (async () => {
      for await (const message of subscription) {
        received.push(codec.decode(message.data));
      }
    })();

    try {
      const common = {
        organisation_id: orgId,
        site_id: siteId,
        zone_id: 'zone-gate',
        event_type: 'person_detected',
        source_type: 'camera' as const,
        source_trust: 'trusted' as const,
      };

      // R1: weighted 0.50 -> support 0.50 -> base 2, diversity 1 -> STATE 2. Crossing.
      const r1 = makeEvent({ ...common, source_id: 'cam-01', confidence: 0.5, occurred_at: base.toISOString() });
      // R2: valid, in-schedule access grant, weighted 0.50 -> support 0.50,
      // contradiction 0.50 -> probability 0 -> STATE 0. De-escalation.
      const r2 = makeEvent({
        organisation_id: orgId,
        site_id: siteId,
        zone_id: 'zone-gate',
        source_type: 'access',
        source_id: 'door-01',
        event_type: 'access_granted_valid',
        source_trust: 'trusted',
        confidence: 0.5,
        metadata: { schedule_match: true },
        occurred_at: new Date(base.getTime() + 20_000).toISOString(),
      });
      // R3: a second independent camera at 0.90 -> support 0.95, contradiction
      // 0.50 -> probability 0.45 -> base 2, diversity 2 -> STATE 2. Re-crossing.
      const r3 = makeEvent({
        ...common,
        source_id: 'cam-02',
        confidence: 0.9,
        occurred_at: new Date(base.getTime() + 40_000).toISOString(),
      });

      const first = await service.applyEvent(r1);
      expect(first.outcome === 'applied' && first.state).toBe(2);
      expect(first.outcome === 'applied' && first.incidentCandidate?.re_escalation).toBe(false);

      const deEscalation = await service.applyEvent(r2);
      expect(deEscalation.outcome === 'applied' && deEscalation.state).toBe(0);
      expect(deEscalation.outcome === 'applied' && deEscalation.incidentCandidate).toBeNull();

      const reEscalation = await service.applyEvent(r3);
      expect(reEscalation.outcome === 'applied' && reEscalation.state).toBe(2);
      expect(reEscalation.outcome === 'applied' && reEscalation.incidentCandidate?.re_escalation).toBe(true);

      const hypothesis = await prisma.hypothesis.findFirstOrThrow({ where: { organisationId: orgId } });
      expect(hypothesis.incidentCandidateEmissions).toBe(2);
      expect(hypothesis.incidentCandidateLatched).toBe(true);

      expect(await waitUntil(async () => received.length >= 2, 10_000)).toBe(true);
      expect(received).toHaveLength(2);
      expect(received[0]).toMatchObject({
        re_escalation: false,
        emission_number: 1,
        threat_state: 2,
        triggering_event_id: r1.event_id,
      });
      expect(received[1]).toMatchObject({
        re_escalation: true,
        emission_number: 2,
        threat_state: 2,
        triggering_event_id: r3.event_id,
      });
      // The candidate id is stable across a re-escalation: WP-07 sees one
      // candidate that came back, not two separate ones.
      expect(received[1].incident_candidate_id).toBe(received[0].incident_candidate_id);
      expect(received[1].incident_candidate_id).toBe(hypothesis.incidentCandidateId);
      // Contradiction travels with the candidate, never stripped.
      expect(received[1].contradicting_event_ids).toEqual([r2.event_id]);
    } finally {
      subscription.unsubscribe();
      await drain.catch(() => undefined);
    }
  }, 45_000);

  it('records unmapped and condition-not-met events without manufacturing a hypothesis', async () => {
    const orgId = trackOrg('ignored');
    const siteId = uniqueSiteId('ignored');
    const base = scenarioWindowBase();

    const unknown = makeEvent({
      organisation_id: orgId,
      site_id: siteId,
      zone_id: 'zone-a',
      event_type: 'weather.forecast.updated',
      occurred_at: base.toISOString(),
    });
    // A valid grant with no schedule match is NOT exculpatory, so it produces
    // no signal at all rather than a weakened contradiction.
    const outOfSchedule = makeEvent({
      organisation_id: orgId,
      site_id: siteId,
      zone_id: 'zone-a',
      source_type: 'access',
      source_id: 'door-09',
      event_type: 'access_granted_valid',
      metadata: { schedule_match: false },
      occurred_at: new Date(base.getTime() + 10_000).toISOString(),
    });

    expect(await service.applyEvent(unknown)).toMatchObject({ outcome: 'ignored', reason: 'no_rule' });
    expect(await service.applyEvent(outOfSchedule)).toMatchObject({ outcome: 'ignored', reason: 'condition_not_met' });

    expect(await prisma.hypothesis.count({ where: { organisationId: orgId } })).toBe(0);

    const applied = await prisma.fusionAppliedEvent.findMany({
      where: { organisationId: orgId },
      orderBy: { appliedAt: 'asc' },
    });
    expect(applied).toHaveLength(2);
    for (const row of applied) {
      expect(row.hypothesisId).toBeNull();
      expect(row.signalKind).toBeNull();
      expect(row.correlationKey.length).toBeGreaterThan(0);
    }
    expect(applied.map((row) => row.ignoreReason).sort()).toEqual(['condition_not_met', 'no_rule']);

    // Redelivering an ignored event is still a no-op.
    expect(await service.applyEvent(unknown)).toMatchObject({ outcome: 'duplicate' });
    expect(await prisma.fusionAppliedEvent.count({ where: { organisationId: orgId } })).toBe(2);
  }, 45_000);

  it('records a quarantined source without letting it move any value', async () => {
    const orgId = trackOrg('quarantine');
    const siteId = uniqueSiteId('quarantine');

    const event = makeEvent({
      organisation_id: orgId,
      site_id: siteId,
      zone_id: 'zone-b',
      source_id: 'cam-compromised',
      source_trust: 'quarantined',
      event_type: 'object.threat_like',
      confidence: 0.99,
      occurred_at: scenarioWindowBase().toISOString(),
    });

    await service.applyEvent(event);

    const hypothesis = await prisma.hypothesis.findFirstOrThrow({ where: { organisationId: orgId } });
    expect(hypothesis.state).toBe(0);
    expect(hypothesis.threatProbability).toBe(0);
    expect(hypothesis.detectionConfidence).toBe(0);
    expect(hypothesis.supportingEventIds).toEqual([]);
    expect(hypothesis.contradictingEventIds).toEqual([]);
    // The THREAT_LIKE family must not raise potential impact from a source we
    // do not trust.
    expect(hypothesis.supportingImpactFamilies).toEqual([]);
    expect(hypothesis.potentialImpact).toBe('MODERATE');
    expect(Array.isArray(hypothesis.ignoredSignals) ? hypothesis.ignoredSignals : []).toHaveLength(1);
  }, 45_000);

  it('scopes reads to the caller tenant and never confirms another tenant hypothesis exists', async () => {
    const orgA = trackOrg('tenant-a');
    const orgB = trackOrg('tenant-b');
    const siteId = uniqueSiteId('tenant');
    await replay(scenarioEvents(orgA, siteId));

    const hypothesis = await prisma.hypothesis.findFirstOrThrow({ where: { organisationId: orgA } });

    const asA = await controller.list(principalRequest(orgA), {});
    expect(asA.items.map((item) => item.hypothesis_id)).toEqual([hypothesis.id]);

    const asB = await controller.list(principalRequest(orgB), {});
    expect(asB.items).toHaveLength(0);

    await expect(controller.detail(principalRequest(orgB), hypothesis.id, {})).rejects.toThrow(/not found/i);

    // A principal's organisation always wins over a query parameter.
    const spoofed = await controller.list(principalRequest(orgB), { organisation_id: orgA });
    expect(spoofed.items).toHaveLength(0);

    // Dev bypass: no principal means the tenant must be stated explicitly.
    await expect(controller.list(anonymousRequest(), {})).rejects.toThrow(/organisation_id query param is required/i);
    const viaBypass = await controller.list(anonymousRequest(), { organisation_id: orgA });
    expect(viaBypass.items).toHaveLength(1);
  }, 45_000);

  it('filters the list by minimum threat state without ever dropping the contradicting evidence', async () => {
    const orgId = trackOrg('filter');
    const siteId = uniqueSiteId('filter');
    await replay(scenarioEvents(orgId, siteId));

    const req = principalRequest(orgId);
    expect((await controller.list(req, { min_state: 3 })).items).toHaveLength(1);
    expect((await controller.list(req, { min_state: 4 })).items).toHaveLength(0);
    expect((await controller.list(req, { site_id: siteId })).items).toHaveLength(1);
    expect((await controller.list(req, { site_id: 'some-other-site' })).items).toHaveLength(0);

    for (const item of (await controller.list(req, { min_state: 3 })).items) {
      expect(item).toHaveProperty('supporting_event_ids');
      expect(item).toHaveProperty('contradicting_event_ids');
      expect(item).toHaveProperty('confidence_explanation');
    }
  }, 45_000);

  it('correlates only within one 15-minute window, site and zone', async () => {
    const orgId = trackOrg('correlate');
    const siteId = uniqueSiteId('correlate');
    const base = scenarioWindowBase();
    const common = {
      organisation_id: orgId,
      site_id: siteId,
      event_type: 'person_detected',
      source_id: 'cam-01',
      confidence: 0.5,
    };

    await service.applyEvent(makeEvent({ ...common, zone_id: 'zone-1', occurred_at: base.toISOString() }));
    // Same window, different zone -> a separate hypothesis.
    await service.applyEvent(
      makeEvent({ ...common, zone_id: 'zone-2', occurred_at: new Date(base.getTime() + 10_000).toISOString() }),
    );
    // Same zone, next window -> a separate hypothesis.
    await service.applyEvent(
      makeEvent({ ...common, zone_id: 'zone-1', occurred_at: new Date(base.getTime() + 16 * 60_000).toISOString() }),
    );
    // No zone at all -> the 'site-wide' bucket, again separate.
    await service.applyEvent(
      makeEvent({ ...common, zone_id: null, occurred_at: new Date(base.getTime() + 20_000).toISOString() }),
    );

    const rows = await prisma.hypothesis.findMany({ where: { organisationId: orgId } });
    expect(rows).toHaveLength(4);
    expect(new Set(rows.map((row) => row.correlationKey)).size).toBe(4);
    expect(rows.filter((row) => row.zoneKey === 'site-wide')).toHaveLength(1);
  }, 45_000);
});
