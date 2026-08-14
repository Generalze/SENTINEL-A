import { z } from 'zod';
import { MAX_LIST_LIMIT } from './list-pagination';

/**
 * WP-14/M6: the query params every identity list endpoint accepts. `limit` is
 * capped at `MAX_LIST_LIMIT` at the schema boundary (an over-cap value is a
 * 400, never a silently-unbounded read); `cursor` is the opaque id from a
 * previous page's `next_cursor`.
 */
export const ListQuerySchema = z.object({
  limit: z.coerce.number().int().positive().max(MAX_LIST_LIMIT).optional(),
  cursor: z.string().min(1).optional(),
});

export type ListQueryDto = z.infer<typeof ListQuerySchema>;

/** Shape every identity list endpoint returns: a page of items plus the next cursor. */
export interface ListPageResponse<T> {
  items: T[];
  next_cursor: string | null;
}
