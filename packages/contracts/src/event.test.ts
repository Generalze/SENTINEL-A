import { describe, it, expect } from 'vitest';
import { NormalisedEventSchema } from './event';
import { deriveIdempotencyKey } from './idempotency';

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

  describe('idempotency key derivation', () => {
    it('produces the same key for two occurred_at values in the same window', () => {
      const sourceId = 'cam_001';
      const sourceEventId = 'evt_123';
      const windowMs = 5000;

      const occurredAt1 = '2026-08-14T10:00:00.000Z';
      const occurredAt2 = '2026-08-14T10:00:02.500Z';

      const key1 = deriveIdempotencyKey(sourceId, sourceEventId, occurredAt1, windowMs);
      const key2 = deriveIdempotencyKey(sourceId, sourceEventId, occurredAt2, windowMs);

      expect(key1).toBe(key2);
    });

    it('produces different keys for values in different windows', () => {
      const sourceId = 'sensor_002';
      const sourceEventId = 'evt_456';
      const windowMs = 5000;

      const occurredAt1 = '2026-08-14T10:00:00.000Z';
      const occurredAt2 = '2026-08-14T10:00:06.000Z';

      const key1 = deriveIdempotencyKey(sourceId, sourceEventId, occurredAt1, windowMs);
      const key2 = deriveIdempotencyKey(sourceId, sourceEventId, occurredAt2, windowMs);

      expect(key1).not.toBe(key2);
    });

    it('throws TypeError on unparseable date', () => {
      expect(() => {
        deriveIdempotencyKey('source_001', 'evt_789', 'not-a-date', 5000);
      }).toThrow(TypeError);
    });

    it('throws TypeError on windowMs <= 0', () => {
      expect(() => {
        deriveIdempotencyKey('source_002', 'evt_999', '2026-08-14T10:00:00Z', 0);
      }).toThrow(TypeError);

      expect(() => {
        deriveIdempotencyKey('source_003', 'evt_111', '2026-08-14T10:00:00Z', -1000);
      }).toThrow(TypeError);
    });
  });
});
