import { describe, expect, it } from 'vitest';
import { pickWhitelistedFields } from './payload-whitelist.util';

describe('pickWhitelistedFields', () => {
  it('forwards only the whitelisted keys, dropping everything else', () => {
    const raw = {
      id: 'inc_123',
      organisation_id: 'org_1',
      site_id: 'site_1',
      status: 'open',
      updated_at: '2026-08-14T00:00:00.000Z',
      // Not whitelisted — must never reach the client.
      internal_notes: 'classified operator commentary',
      raw_evidence_refs: ['s3://bucket/key'],
      commander_user_id: 'user_42',
      playbook_version: 'v3',
    };

    const result = pickWhitelistedFields(raw);

    expect(result).toEqual({
      id: 'inc_123',
      organisation_id: 'org_1',
      site_id: 'site_1',
      status: 'open',
      updated_at: '2026-08-14T00:00:00.000Z',
    });
    expect(result).not.toHaveProperty('internal_notes');
    expect(result).not.toHaveProperty('raw_evidence_refs');
    expect(result).not.toHaveProperty('commander_user_id');
    expect(result).not.toHaveProperty('playbook_version');
  });

  it('maps hypothesis_id to id (Hypothesis contract identifies itself differently than Incident)', () => {
    const result = pickWhitelistedFields({ hypothesis_id: 'hyp_1', state: 3, operational_severity: 'SEV2' });
    expect(result.id).toBe('hyp_1');
    expect(result.state).toBe(3);
    // operational_severity is not one of the whitelisted keys (severity is) — dropped.
    expect(result).not.toHaveProperty('operational_severity');
  });

  it('falls back to the subject-derived organisation_id only when the payload omits it', () => {
    const withoutOrg = pickWhitelistedFields({ id: 'x' }, 'org_from_subject');
    expect(withoutOrg.organisation_id).toBe('org_from_subject');

    const withOrg = pickWhitelistedFields({ id: 'x', organisation_id: 'org_from_payload' }, 'org_from_subject');
    expect(withOrg.organisation_id).toBe('org_from_payload');
  });

  it('includes only the state/severity/status keys actually present, never inventing the others', () => {
    const result = pickWhitelistedFields({ id: 'x', severity: 'SEV1' });
    expect(result.severity).toBe('SEV1');
    expect(result).not.toHaveProperty('state');
    expect(result).not.toHaveProperty('status');
  });

  it('degrades to an empty (but well-formed) object for non-object / malformed payloads', () => {
    expect(pickWhitelistedFields(null)).toEqual({});
    expect(pickWhitelistedFields(undefined)).toEqual({});
    expect(pickWhitelistedFields('not-json-object')).toEqual({});
    expect(pickWhitelistedFields(42)).toEqual({});
    expect(pickWhitelistedFields(['array', 'not', 'record'])).toEqual({});
  });

  it('never includes an id field when no alias is present', () => {
    const result = pickWhitelistedFields({ status: 'closed' });
    expect(result).not.toHaveProperty('id');
  });

  it('allows Field invalidation keys without forwarding full assignment records', () => {
    const result = pickWhitelistedFields({
      kind: 'FIELD_ASSIGNMENT_ACCEPTED',
      assignment_id: 'assignment-1',
      user_id: 'user-field',
      organisation_id: 'org-1',
      site_id: 'site-1',
      need_to_know_summary: 'must not ride websocket',
      location: { lat: 1 },
    });
    expect(result).toEqual({
      kind: 'FIELD_ASSIGNMENT_ACCEPTED',
      assignment_id: 'assignment-1',
      user_id: 'user-field',
      organisation_id: 'org-1',
      site_id: 'site-1',
    });
  });
});
