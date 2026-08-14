/**
 * WP-14: the canonical Principal now lives in `common/security` (owned by no
 * feature module) so every HTTP module shares ONE identity type. This file
 * re-exports it to keep the identity module's existing `../principal` imports
 * working unchanged.
 */
export {
  buildPrincipal,
  requirePrincipal,
  type BuildPrincipalInput,
  type Principal,
  type PrincipalRoleAssignment,
  type RequestWithPrincipal,
} from '../../common/security/principal';
