import { SetMetadata } from '@nestjs/common';

export const ALLOW_RECOVERY_SCOPE_KEY = 'allowRecoveryScope';

/**
 * Marks a route as reachable with a "recovery session" - the restricted access token issued when an
 * account that owns passkeys signs in with a recovery code. Every other authenticated route refuses
 * such a token (see `JwtAuthGuard`). Use it only for what a user who lost their device must be able to
 * do: enrol a new passkey and revoke the lost ones.
 */
export const AllowRecoveryScope = () => SetMetadata(ALLOW_RECOVERY_SCOPE_KEY, true);
