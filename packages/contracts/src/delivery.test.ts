import { describe, it, expect } from 'vitest';
import { DeliveryStateSchema, ALLOWED_DELIVERY_TRANSITIONS, canTransition } from './delivery';

describe('DeliveryStateSchema', () => {
  it('accepts all six documented states', () => {
    for (const v of ['REQUESTED', 'DELIVERED', 'ACKNOWLEDGED', 'EXECUTED', 'FAILED', 'UNKNOWN']) {
      expect(DeliveryStateSchema.parse(v)).toBe(v);
    }
  });

  it('rejects an undocumented state', () => {
    expect(() => DeliveryStateSchema.parse('PENDING')).toThrow();
  });

  it('rejects a lowercase state', () => {
    expect(() => DeliveryStateSchema.parse('requested')).toThrow();
  });
});

describe('canTransition / ALLOWED_DELIVERY_TRANSITIONS', () => {
  it('allows the normal forward progression', () => {
    expect(canTransition('REQUESTED', 'DELIVERED')).toBe(true);
    expect(canTransition('DELIVERED', 'ACKNOWLEDGED')).toBe(true);
    expect(canTransition('ACKNOWLEDGED', 'EXECUTED')).toBe(true);
  });

  it('disallows skipping a stage backwards without going through FAILED/UNKNOWN', () => {
    expect(canTransition('DELIVERED', 'REQUESTED')).toBe(false);
    expect(canTransition('ACKNOWLEDGED', 'REQUESTED')).toBe(false);
  });

  it('allows FAILED and UNKNOWN to retry back to REQUESTED', () => {
    expect(canTransition('FAILED', 'REQUESTED')).toBe(true);
    expect(canTransition('UNKNOWN', 'REQUESTED')).toBe(true);
  });

  it('treats EXECUTED as terminal (boundary: empty transition set)', () => {
    expect(ALLOWED_DELIVERY_TRANSITIONS.EXECUTED).toEqual([]);
    expect(canTransition('EXECUTED', 'REQUESTED')).toBe(false);
    expect(canTransition('EXECUTED', 'FAILED')).toBe(false);
  });

  it('allows any pre-EXECUTED state to move to FAILED or UNKNOWN', () => {
    expect(canTransition('REQUESTED', 'FAILED')).toBe(true);
    expect(canTransition('REQUESTED', 'UNKNOWN')).toBe(true);
    expect(canTransition('DELIVERED', 'FAILED')).toBe(true);
    expect(canTransition('DELIVERED', 'UNKNOWN')).toBe(true);
    expect(canTransition('ACKNOWLEDGED', 'FAILED')).toBe(true);
    expect(canTransition('ACKNOWLEDGED', 'UNKNOWN')).toBe(true);
  });

  it('rejects a transition to a state not in the allowed set', () => {
    expect(canTransition('FAILED', 'EXECUTED')).toBe(false);
  });
});
