import { BadRequestException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { decodeCursor, encodeCursor } from './ledger.pagination';

describe('ledger.pagination', () => {
  it('round-trips a cursor through encode/decode', () => {
    const cursor = { decidedAt: '2026-01-01T00:00:00.000Z', entryId: 'abc-123' };
    expect(decodeCursor(encodeCursor(cursor))).toEqual(cursor);
  });

  it('rejects a cursor that is not valid base64url JSON', () => {
    expect(() => decodeCursor('not-a-cursor!!!')).toThrow(BadRequestException);
  });

  it('rejects a cursor missing required fields', () => {
    const malformed = Buffer.from(JSON.stringify({ decidedAt: '2026-01-01T00:00:00.000Z' }), 'utf8').toString('base64url');
    expect(() => decodeCursor(malformed)).toThrow(BadRequestException);
  });

  it('rejects a cursor whose fields have the wrong type', () => {
    const malformed = Buffer.from(JSON.stringify({ decidedAt: 123, entryId: 'abc' }), 'utf8').toString('base64url');
    expect(() => decodeCursor(malformed)).toThrow(BadRequestException);
  });
});
