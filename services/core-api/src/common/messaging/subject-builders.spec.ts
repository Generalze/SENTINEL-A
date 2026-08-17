import { describe, expect, it } from 'vitest';
import { buildSubject } from '../../modules/events/events-publisher.service';
import { fieldUpdatedSubject } from '../../modules/field/field.constants';
import { hypothesisSubject, incidentCandidateSubject } from '../../modules/fusion/fusion.constants';
import { incidentUpdatedSubject } from '../../modules/incidents/incidents.constants';

/**
 * WP-17/C7-06: asserts that each of the five NATS subject builders known to
 * this service applies the same canonical token rule.
 *
 * WP-17 hardened the Field subject only; the Wave-7 audit found four more
 * builders interpolating dynamic ids, and this pins all of them.
 *
 * Scope of the guarantee — `BUILDERS` is a hand-maintained list. A sixth
 * builder added elsewhere and never registered here will NOT fail this suite,
 * so this is a regression pin for the builders that exist, not an automatic
 * bar on adding an unvalidated one. Getting that stronger property means
 * centralising subject construction behind one module so there is no second
 * place to add a builder; that is not WP-17 work.
 */
const UNSAFE_TOKENS = ['org.evil', 'org-a.>', 'org *', 'org a', ''];

const BUILDERS: ReadonlyArray<{ name: string; build: (token: string) => string; safe: string }> = [
  { name: 'events (organisation_id)', build: (token) => buildSubject(token, 'site-a'), safe: 'sentinel.events.org-1.site-a' },
  { name: 'events (site_id)', build: (token) => buildSubject('org-1', token), safe: 'sentinel.events.org-1.org-1' },
  { name: 'fusion hypothesis', build: (token) => hypothesisSubject(token), safe: 'sentinel.fusion.hypothesis.org-1' },
  { name: 'fusion incident-candidate', build: (token) => incidentCandidateSubject(token), safe: 'sentinel.fusion.incident-candidate.org-1' },
  { name: 'incidents updated', build: (token) => incidentUpdatedSubject(token), safe: 'sentinel.incidents.updated.org-1' },
  { name: 'field updated (organisation_id)', build: (token) => fieldUpdatedSubject(token, 'site-a'), safe: 'sentinel.field.updated.org-1.site-a' },
  { name: 'field updated (site_id)', build: (token) => fieldUpdatedSubject('org-1', token), safe: 'sentinel.field.updated.org-1.org-1' },
];

describe('every NATS subject builder applies the canonical token rule (WP-17/C7-06)', () => {
  for (const builder of BUILDERS) {
    it(`${builder.name} builds a well-formed subject for a safe token`, () => {
      expect(builder.build('org-1')).toBe(builder.safe);
    });

    it(`${builder.name} refuses a token that would re-shape or widen the subject`, () => {
      for (const unsafe of UNSAFE_TOKENS) {
        expect(() => builder.build(unsafe)).toThrow(/not a safe NATS subject token/);
      }
    });
  }

  it('every builder produces a subject whose segment count is fixed regardless of input', () => {
    // The property that actually matters: consumers parse organisation (and,
    // for Field, site) by segment index, so a builder must never let a token
    // add a segment.
    expect(buildSubject('org-1', 'site-a').split('.')).toHaveLength(4);
    expect(fieldUpdatedSubject('org-1', 'site-a').split('.')).toHaveLength(5);
    expect(hypothesisSubject('org-1').split('.')).toHaveLength(4);
    expect(incidentCandidateSubject('org-1').split('.')).toHaveLength(4);
    expect(incidentUpdatedSubject('org-1').split('.')).toHaveLength(4);
  });
});
