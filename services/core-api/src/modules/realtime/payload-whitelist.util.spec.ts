import { describe, expect, it } from 'vitest';
import { pickFieldRealtimeFields, pickWhitelistedFields } from './payload-whitelist.util';

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

  it('no longer carries Field-only keys on the organisation room (WP-17/D4)', () => {
    const result = pickWhitelistedFields({
      kind: 'INCIDENT_OPENED',
      assignment_id: 'assignment-1',
      user_id: 'user-field',
      organisation_id: 'org-1',
    });
    expect(result).toEqual({ kind: 'INCIDENT_OPENED', organisation_id: 'org-1' });
    expect(result).not.toHaveProperty('assignment_id');
    expect(result).not.toHaveProperty('user_id');
  });
});

describe('pickFieldRealtimeFields (WP-17/D4, C7-08)', () => {
  it('forwards scope and kind only — never the domain record', () => {
    const result = pickFieldRealtimeFields(
      {
        kind: 'FIELD_ASSIGNMENT_ACCEPTED',
        assignment_id: 'assignment-1',
        user_id: 'user-field',
        need_to_know_summary: 'must not ride websocket',
        location: { lat: 1 },
        priority: 'SEV1',
      },
      'org-1',
      'site-1',
    );

    expect(result).toEqual({
      kind: 'FIELD_ASSIGNMENT_ACCEPTED',
      organisation_id: 'org-1',
      site_id: 'site-1',
    });
    expect(result).not.toHaveProperty('need_to_know_summary');
    expect(result).not.toHaveProperty('location');
    expect(result).not.toHaveProperty('priority');
  });

  it('C7-08: never forwards a peer object identifier on the shared site channel', () => {
    // The Field site room holds every principal with a Field visibility action
    // at that site, and REST answers 404 (not 403) when one operative asks for
    // another's assignment. Forwarding the id here would let the socket
    // disclose the existence of an object REST says the caller may not know
    // exists.
    const result = pickFieldRealtimeFields({ kind: 'FIELD_ASSIGNMENT_CREATED', assignment_id: 'peer-assignment', user_id: 'peer-operative' }, 'org-1', 'site-1');
    expect(result).toEqual({ kind: 'FIELD_ASSIGNMENT_CREATED', organisation_id: 'org-1', site_id: 'site-1' });
    expect(result).not.toHaveProperty('assignment_id');
    expect(result).not.toHaveProperty('user_id');
  });

  it('never forwards operative state, even when the payload carries it', () => {
    const result = pickFieldRealtimeFields({ kind: 'FIELD_STATE_UPDATED', user_id: 'user-field', state: 'COMPROMISED' }, 'org-1', 'site-1');
    expect(result).toEqual({ kind: 'FIELD_STATE_UPDATED', organisation_id: 'org-1', site_id: 'site-1' });
    expect(result).not.toHaveProperty('state');
    expect(result).not.toHaveProperty('user_id');
  });

  it('takes scope from the subject, never from the payload body', () => {
    const result = pickFieldRealtimeFields({ kind: 'FIELD_ASSIGNMENT_CREATED', organisation_id: 'org-attacker', site_id: 'site-attacker' }, 'org-1', 'site-1');
    expect(result.organisation_id).toBe('org-1');
    expect(result.site_id).toBe('site-1');
  });

  it('degrades to scope-only output for malformed payloads', () => {
    expect(pickFieldRealtimeFields(null, 'org-1', 'site-1')).toEqual({ organisation_id: 'org-1', site_id: 'site-1' });
    expect(pickFieldRealtimeFields(['not', 'a', 'record'], 'org-1', 'site-1')).toEqual({ organisation_id: 'org-1', site_id: 'site-1' });
  });
});
