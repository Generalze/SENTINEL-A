import { describe, it, expect } from 'vitest';
import { SeveritySchema, ResponseModeSchema, IncidentStatusSchema, IncidentSchema } from './incident';

describe('SeveritySchema / ResponseModeSchema / IncidentStatusSchema', () => {
  it('accepts all documented severity values', () => {
    for (const v of ['SEV1', 'SEV2', 'SEV3', 'SEV4', 'SEV5']) {
      expect(SeveritySchema.parse(v)).toBe(v);
    }
  });

  it('rejects an undocumented severity value', () => {
    expect(() => SeveritySchema.parse('SEV6')).toThrow();
  });

  it('accepts all documented response modes', () => {
    for (const v of ['STANDARD', 'DISCREET', 'SILENT']) {
      expect(ResponseModeSchema.parse(v)).toBe(v);
    }
  });

  it('rejects an undocumented response mode', () => {
    expect(() => ResponseModeSchema.parse('COVERT')).toThrow();
  });

  it('accepts all documented status values', () => {
    for (const v of ['open', 'contained', 'closed']) {
      expect(IncidentStatusSchema.parse(v)).toBe(v);
    }
  });

  it('rejects an undocumented status value', () => {
    expect(() => IncidentStatusSchema.parse('escalated')).toThrow();
  });
});

describe('IncidentSchema', () => {
  const base = {
    schema_version: 1 as const,
    id: 'inc_001',
    organisation_id: 'org_abc',
    site_id: 'site_xyz',
    incident_type: 'perimeter_intrusion',
    severity: 'SEV2' as const,
    threat_state: 3 as const,
    confidence: 0.8,
    response_mode: 'DISCREET' as const,
    commander_user_id: null,
    playbook_version: null,
    status: 'open' as const,
    opened_at: '2026-08-14T10:00:00Z',
    closed_at: null,
  };

  it('accepts a minimal open incident with nullable fields explicitly null and default related_event_ids', () => {
    const result = IncidentSchema.parse(base);
    expect(result.commander_user_id).toBeNull();
    expect(result.playbook_version).toBeNull();
    expect(result.closed_at).toBeNull();
    expect(result.related_event_ids).toEqual([]);
  });

  it('accepts a fully-populated closed incident', () => {
    const full = {
      ...base,
      commander_user_id: 'user_commander_1',
      related_event_ids: ['evt_1', 'evt_2'],
      playbook_version: 'playbook-v3',
      status: 'closed' as const,
      closed_at: '2026-08-14T12:00:00Z',
    };
    const result = IncidentSchema.parse(full);
    expect(result.related_event_ids).toHaveLength(2);
    expect(result.closed_at).toBe('2026-08-14T12:00:00Z');
  });

  it('accepts the boundary case closed_at === opened_at', () => {
    expect(() =>
      IncidentSchema.parse({ ...base, status: 'closed' as const, closed_at: base.opened_at })
    ).not.toThrow();
  });

  it('rejects closed_at earlier than opened_at', () => {
    expect(() =>
      IncidentSchema.parse({ ...base, status: 'closed' as const, closed_at: '2026-08-14T09:59:59Z' })
    ).toThrow();
  });

  it('rejects an invalid severity', () => {
    expect(() => IncidentSchema.parse({ ...base, severity: 'CRITICAL' })).toThrow();
  });

  it('rejects an invalid response_mode', () => {
    expect(() => IncidentSchema.parse({ ...base, response_mode: 'HIDDEN' })).toThrow();
  });

  it('rejects a missing organisation_id', () => {
    const rest: Record<string, unknown> = { ...base };
    delete rest.organisation_id;
    expect(() => IncidentSchema.parse(rest)).toThrow();
  });

  it('rejects an omitted (as opposed to null) commander_user_id', () => {
    const rest: Record<string, unknown> = { ...base };
    delete rest.commander_user_id;
    expect(() => IncidentSchema.parse(rest)).toThrow();
  });
});
