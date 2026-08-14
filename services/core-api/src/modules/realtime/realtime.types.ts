/**
 * The authenticated caller of a WS connection, as loaded by
 * `realtime-principal.loader.ts`. Deliberately minimal — this module only
 * ever needs `organisation_id` (to pick the one room the socket may join)
 * and `user_id` (for presence tracking).
 */
export interface RealtimePrincipal {
  readonly user_id: string;
  readonly organisation_id: string;
  readonly roles: readonly string[];
}
