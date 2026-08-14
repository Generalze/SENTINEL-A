import { BadRequestException } from '@nestjs/common';

/**
 * Keyset ("newest first") pagination cursor: the `(decided_at, entry_id)` of the last row on
 * the previous page. Mirrors events/pagination.util.ts's approach — keyset rather than offset
 * pagination keeps results correct even as new entries are appended between page fetches.
 */
export interface LedgerCursor {
  decidedAt: string;
  entryId: string;
}

export function encodeCursor(cursor: LedgerCursor): string {
  return Buffer.from(JSON.stringify(cursor), 'utf8').toString('base64url');
}

export function decodeCursor(raw: string): LedgerCursor {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
  } catch {
    throw new BadRequestException('Invalid cursor');
  }

  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    typeof (parsed as Record<string, unknown>).decidedAt !== 'string' ||
    typeof (parsed as Record<string, unknown>).entryId !== 'string'
  ) {
    throw new BadRequestException('Invalid cursor');
  }

  return parsed as LedgerCursor;
}
