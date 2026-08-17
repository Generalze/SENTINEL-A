/**
 * The authenticated caller of a WS connection, as loaded by
 * `realtime-principal.loader.ts`.
 *
 * WP-17/D1: `roles` carries each assignment's `site_id`, not just the role
 * name. Room membership for Field traffic is site-scoped, and a bare role
 * string cannot express "dispatcher, but only at site B" — dropping `site_id`
 * here is what forced the org-wide Field fanout this module used to do.
 * A `null` `site_id` is an organisation-wide assignment.
 */
export interface RealtimeRoleAssignment {
  readonly role: string;
  readonly site_id: string | null;
}

export interface RealtimePrincipal {
  readonly user_id: string;
  readonly organisation_id: string;
  readonly roles: readonly RealtimeRoleAssignment[];
}
