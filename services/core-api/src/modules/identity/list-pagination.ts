import type { Principal } from '../../common/security/principal';
import { roleHasAction } from './roles';

/**
 * WP-14/M6: bounded, cursor-paged identity list reads.
 *
 * Every identity list endpoint (organisations/sites/zones/users) previously
 * returned its whole tenant unbounded. This applies the same keyset-cursor +
 * hard cap the events module uses: `limit` is clamped to `MAX_LIST_LIMIT`, and
 * `cursor` is the id of the last row of the previous page (rows are ordered
 * `createdAt desc, id desc`, so id is a stable keyset cursor).
 */
export const DEFAULT_LIST_LIMIT = 50;
export const MAX_LIST_LIMIT = 200;

export interface ListPageQuery {
  limit?: number;
  cursor?: string;
}

export interface ListPageResult<T> {
  items: T[];
  next_cursor: string | null;
}

export interface ResolvedListPage {
  readonly limit: number;
  readonly cursor: string | undefined;
  /** Trims the `limit + 1` fetched rows to a page and derives the next cursor. */
  toResult<T extends { id: string }>(rows: T[]): ListPageResult<T>;
}

export function resolveListPage(query: ListPageQuery = {}): ResolvedListPage {
  const requested = query.limit ?? DEFAULT_LIST_LIMIT;
  const limit = Math.min(Math.max(Math.trunc(requested), 1), MAX_LIST_LIMIT);
  const cursor = query.cursor;
  return {
    limit,
    cursor,
    toResult<T extends { id: string }>(rows: T[]): ListPageResult<T> {
      const hasMore = rows.length > limit;
      const items = hasMore ? rows.slice(0, limit) : rows;
      const last = items[items.length - 1];
      return { items, next_cursor: hasMore && last ? last.id : null };
    },
  };
}

export interface SiteScope {
  /** True when at least one granting assignment is organisation-wide (site_id null). */
  orgWide: boolean;
  /** The distinct sites the granting assignments are scoped to (empty when orgWide). */
  siteIds: string[];
}

/**
 * WP-14/M4: the site scope a principal's grants for `action` imply. When any
 * granting assignment is org-wide the read is unrestricted; otherwise it is
 * limited to the union of the site-scoped grants — so a site-scoped role can
 * never read across the whole organisation.
 */
export function intersectSiteScope(principal: Principal, action: string): SiteScope {
  const granting = principal.roles.filter((assignment) => roleHasAction(assignment.role, action));
  const orgWide = granting.some((assignment) => assignment.site_id === null);
  const siteIds = [...new Set(granting.map((a) => a.site_id).filter((s): s is string => s !== null))];
  return { orgWide, siteIds };
}
