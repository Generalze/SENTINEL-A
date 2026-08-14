import { describe, it, expect } from 'vitest';
import { NormalisedEventSchema, MAX_TRACK_IDS, MAX_EVIDENCE_REFS, MAX_METADATA_BYTES } from './event';
import { deriveIdempotencyKey } from './idempotency';

const baseValidEvent = {
  event_id: 'evt_m7',
  schema_version: 1 as const,
  organisation_id: 'org_m7',
  site_id: 'site_m7',
  source_type: 'camera' as const,
  source_id: 'cam_m7',
  source_trust: 'trusted' as const,
  event_type: 'motion',
  confidence: 0.5,
  occurred_at: '2026-08-14T10:00:00.000Z',
  ingested_at: '2026-08-14T10:00:00.000Z',
  trace_id: 'trace_m7',
};

describe('NormalisedEvent', () => {
  describe('schema validation', () => {
    it('accepts a minimal valid event exercising defaults', () => {
      const minimal = {
        event_id: 'evt_123',
        schema_version: 1,
        organisation_id: 'org_abc',
        site_id: 'site_xyz',
        source_type: 'camera' as const,
        source_id: 'cam_001',
        source_trust: 'trusted' as const,
        event_type: 'motion_detected',
        confidence: 0.95,
        occurred_at: '2026-08-14T10:00:00Z',
        ingested_at: '2026-08-14T10:00:01Z',
        trace_id: 'trace_999',
      };

      const result = NormalisedEventSchema.parse(minimal);
      expect(result.location).toEqual({});
      expect(result.track_ids).toEqual([]);
      expect(result.evidence_refs).toEqual([]);
      expect(result.metadata).toEqual({});
      expect(result.zone_id).toBeUndefined();
    });

    it('accepts a fully-populated valid event', () => {
      const full = {
        event_id: 'evt_456',
        schema_version: 1,
        organisation_id: 'org_def',
        site_id: 'site_abc',
        zone_id: 'zone_north',
        source_type: 'access' as const,
        source_id: 'reader_002',
        source_trust: 'degraded' as const,
        event_type: 'unauthorized_access_attempt',
        confidence: 0.87,
        occurred_at: '2026-08-14T09:30:00Z',
        ingested_at: '2026-08-14T09:30:05Z',
        location: { x: 100, y: 200 },
        track_ids: ['track_001', 'track_002'],
        evidence_refs: ['img_001', 'vid_002'],
        metadata: { anomaly_score: 0.78, model_version: '2.1' },
        trace_id: 'trace_aaa',
      };

      const result = NormalisedEventSchema.parse(full);
      expect(result.zone_id).toBe('zone_north');
      expect(result.location).toEqual({ x: 100, y: 200 });
      expect(result.track_ids).toHaveLength(2);
      expect(result.metadata).toEqual({ anomaly_score: 0.78, model_version: '2.1' });
    });

    it('rejects confidence > 1', () => {
      const invalid = {
        event_id: 'evt_789',
        schema_version: 1,
        organisation_id: 'org_ghi',
        site_id: 'site_def',
        source_type: 'sensor' as const,
        source_id: 'sensor_003',
        source_trust: 'trusted' as const,
        event_type: 'temperature_anomaly',
        confidence: 1.5,
        occurred_at: '2026-08-14T11:00:00Z',
        ingested_at: '2026-08-14T11:00:02Z',
        trace_id: 'trace_bbb',
      };

      expect(() => NormalisedEventSchema.parse(invalid)).toThrow();
    });

    it('rejects invalid source_type', () => {
      const invalid = {
        event_id: 'evt_101',
        schema_version: 1,
        organisation_id: 'org_jkl',
        site_id: 'site_ghi',
        source_type: 'invalid_type',
        source_id: 'src_004',
        source_trust: 'trusted' as const,
        event_type: 'unknown_event',
        confidence: 0.5,
        occurred_at: '2026-08-14T12:00:00Z',
        ingested_at: '2026-08-14T12:00:01Z',
        trace_id: 'trace_ccc',
      };

      expect(() => NormalisedEventSchema.parse(invalid)).toThrow();
    });

    it('rejects ingested_at earlier than occurred_at', () => {
      const invalid = {
        event_id: 'evt_202',
        schema_version: 1,
        organisation_id: 'org_mno',
        site_id: 'site_jkl',
        source_type: 'cyber' as const,
        source_id: 'detector_005',
        source_trust: 'suspicious' as const,
        event_type: 'intrusion_attempt',
        confidence: 0.92,
        occurred_at: '2026-08-14T13:00:00Z',
        ingested_at: '2026-08-14T12:59:59Z',
        trace_id: 'trace_ddd',
      };

      expect(() => NormalisedEventSchema.parse(invalid)).toThrow();
    });

    it('rejects missing trace_id', () => {
      const invalid = {
        event_id: 'evt_303',
        schema_version: 1,
        organisation_id: 'org_pqr',
        site_id: 'site_mno',
        source_type: 'intel' as const,
        source_id: 'source_006',
        source_trust: 'quarantined' as const,
        event_type: 'malware_detected',
        confidence: 0.99,
        occurred_at: '2026-08-14T14:00:00Z',
        ingested_at: '2026-08-14T14:00:01Z',
      };

      expect(() => NormalisedEventSchema.parse(invalid)).toThrow();
    });
  });

  // M7 regression (WP-14): unbounded jsonb/arrays are attacker-reachable on a
  // raw ingest; the contract caps them so a single delivery can't exhaust
  // memory/storage. Each of these would have parsed successfully before.
  describe('input-safety caps (M7)', () => {
    it('rejects metadata that serializes beyond the cap', () => {
      const huge = { blob: 'x'.repeat(MAX_METADATA_BYTES + 1) };
      expect(() => NormalisedEventSchema.parse({ ...baseValidEvent, metadata: huge })).toThrow();
    });

    it('accepts metadata at/under the cap', () => {
      const ok = { note: 'y'.repeat(1000) };
      expect(() => NormalisedEventSchema.parse({ ...baseValidEvent, metadata: ok })).not.toThrow();
    });

    it('rejects a track_ids array longer than the cap', () => {
      const tooMany = Array.from({ length: MAX_TRACK_IDS + 1 }, (_v, i) => `t${i}`);
      expect(() => NormalisedEventSchema.parse({ ...baseValidEvent, track_ids: tooMany })).toThrow();
    });

    it('rejects an evidence_refs array longer than the cap', () => {
      const tooMany = Array.from({ length: MAX_EVIDENCE_REFS + 1 }, (_v, i) => `e${i}`);
      expect(() => NormalisedEventSchema.parse({ ...baseValidEvent, evidence_refs: tooMany })).toThrow();
    });

    it('accepts arrays at the cap', () => {
      const atCap = Array.from({ length: MAX_TRACK_IDS }, (_v, i) => `t${i}`);
      expect(() => NormalisedEventSchema.parse({ ...baseValidEvent, track_ids: atCap })).not.toThrow();
    });
  });

  describe('idempotency key derivation', () => {
    const ORG = 'org_abc';
    const SITE = 'site_xyz';

    it('produces the same key for two occurred_at values in the same window', () => {
      const sourceId = 'cam_001';
      const sourceEventId = 'evt_123';
      const windowMs = 5000;

      const occurredAt1 = '2026-08-14T10:00:00.000Z';
      const occurredAt2 = '2026-08-14T10:00:02.500Z';

      const key1 = deriveIdempotencyKey(ORG, SITE, sourceId, sourceEventId, occurredAt1, windowMs);
      const key2 = deriveIdempotencyKey(ORG, SITE, sourceId, sourceEventId, occurredAt2, windowMs);

      expect(key1).toBe(key2);
    });

    it('produces different keys for values in different windows', () => {
      const sourceId = 'sensor_002';
      const sourceEventId = 'evt_456';
      const windowMs = 5000;

      const occurredAt1 = '2026-08-14T10:00:00.000Z';
      const occurredAt2 = '2026-08-14T10:00:06.000Z';

      const key1 = deriveIdempotencyKey(ORG, SITE, sourceId, sourceEventId, occurredAt1, windowMs);
      const key2 = deriveIdempotencyKey(ORG, SITE, sourceId, sourceEventId, occurredAt2, windowMs);

      expect(key1).not.toBe(key2);
    });

    // C1 regression (WP-14): the organisation id leads the key, so two
    // tenants that (maliciously or by accident) share a source id, event id
    // and window can NEVER derive the same key. Before the fix the key was
    // `${sourceId}:${sourceEventId}:${bucket}` and these two were equal —
    // the root of the cross-tenant suppression/oracle finding.
    it('C1: two different organisations with a colliding source/event id derive DIFFERENT keys', () => {
      const sourceId = 'cam_shared';
      const sourceEventId = 'evt_shared';
      const occurredAt = '2026-08-14T10:00:00.000Z';
      const windowMs = 5000;

      const keyOrgA = deriveIdempotencyKey('org_A', SITE, sourceId, sourceEventId, occurredAt, windowMs);
      const keyOrgB = deriveIdempotencyKey('org_B', SITE, sourceId, sourceEventId, occurredAt, windowMs);

      expect(keyOrgA).not.toBe(keyOrgB);
    });

    it('C1: the same tenant, source, event id and window derives a STABLE key', () => {
      const args = ['org_A', SITE, 'cam_1', 'evt_1', '2026-08-14T10:00:00.000Z', 5000] as const;
      expect(deriveIdempotencyKey(...args)).toBe(deriveIdempotencyKey(...args));
    });

    it('throws TypeError on unparseable date', () => {
      expect(() => {
        deriveIdempotencyKey(ORG, SITE, 'source_001', 'evt_789', 'not-a-date', 5000);
      }).toThrow(TypeError);
    });

    it('throws TypeError on windowMs <= 0', () => {
      expect(() => {
        deriveIdempotencyKey(ORG, SITE, 'source_002', 'evt_999', '2026-08-14T10:00:00Z', 0);
      }).toThrow(TypeError);

      expect(() => {
        deriveIdempotencyKey(ORG, SITE, 'source_003', 'evt_111', '2026-08-14T10:00:00Z', -1000);
      }).toThrow(TypeError);
    });
  });
});
