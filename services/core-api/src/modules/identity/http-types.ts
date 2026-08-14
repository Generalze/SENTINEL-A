/**
 * WP-14: `RequestWithPrincipal` is now the canonical shape in
 * `common/security`. Re-exported here so identity's existing `../http-types`
 * imports keep working unchanged.
 */
export type { RequestWithPrincipal } from '../../common/security/principal';
