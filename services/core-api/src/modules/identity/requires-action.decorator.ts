/**
 * WP-14: the canonical `@RequiresAction`/`@Public` decorators and their ONE
 * metadata key now live in `common/security`. Re-exported here so identity's
 * existing `../requires-action.decorator` imports keep working unchanged.
 */
export {
  Public,
  RequiresAction,
  IS_PUBLIC_KEY,
  REQUIRES_ACTION_KEY,
  type RequiredActionMetadata,
  type RequiresActionOptions,
} from '../../common/security/requires-action.decorator';
