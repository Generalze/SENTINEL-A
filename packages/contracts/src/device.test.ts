import { describe, expect, it } from 'vitest';
import { DeviceTrustSchema } from './device';

describe('DeviceTrustSchema', () => {
  it('accepts the canonical architecture device-trust vocabulary', () => {
    for (const trust of ['TRUSTED', 'DEGRADED', 'SUSPICIOUS', 'QUARANTINED', 'COMPROMISED', 'OFFLINE']) {
      expect(DeviceTrustSchema.parse(trust)).toBe(trust);
    }
  });

  it('rejects local competing trust labels', () => {
    expect(() => DeviceTrustSchema.parse('UNTRUSTED')).toThrow();
  });
});
