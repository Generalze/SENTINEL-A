import { BadRequestException } from '@nestjs/common';

/**
 * Keyset ("newest first") pagination cursor: the (occurred_at, id) of the
 * last row on the previous page. Using occurred_at + a tiebreaker (rather
 * than offset pagination) keeps results correct even as new events are
 * ingested between page fetches.
 */
export interface EventsCursor {
  occurredAt: string;
  id: string;
}

export function encodeCursor(cursor: EventsCursor): string {
  return Buffer.from(JSON.stringify(cursor), 'utf8').toString('base64url');
}

export function decodeCursor(raw: string): EventsCursor {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
  } catch {
    throw new BadRequestException('Invalid cursor');
  }

  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    typeof (parsed as Record<string, unknown>).occurredAt !== 'string' ||
    typeof (parsed as Record<string, unknown>).id !== 'string'
  ) {
    throw new BadRequestException('Invalid cursor');
  }

  return parsed as EventsCursor;
}
