import { BadRequestException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { decodeCursor, encodeCursor } from './pagination.util';

describe('pagination.util', () => {
  it('round-trips a cursor through encode/decode', () => {
    const cursor = { occurredAt: '2026-01-01T00:00:00.000Z', id: 'abc-123' };
    expect(decodeCursor(encodeCursor(cursor))).toEqual(cursor);
  });

  it('rejects a cursor that is not valid base64url JSON', () => {
    expect(() => decodeCursor('not-a-cursor!!!')).toThrow(BadRequestException);
  });

  it('rejects a cursor missing required fields', () => {
    const malformed = Buffer.from(JSON.stringify({ occurredAt: '2026-01-01T00:00:00.000Z' }), 'utf8').toString('base64url');
    expect(() => decodeCursor(malformed)).toThrow(BadRequestException);
  });

  it('rejects a cursor whose fields have the wrong type', () => {
    const malformed = Buffer.from(JSON.stringify({ occurredAt: 123, id: 'abc' }), 'utf8').toString('base64url');
    expect(() => decodeCursor(malformed)).toThrow(BadRequestException);
  });
});
