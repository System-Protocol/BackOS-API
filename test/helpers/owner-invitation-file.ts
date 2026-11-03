import * as path from 'path';

/**
 * Where the end-to-end setup leaves the owner's one-time invitation (token, code, e-mail).
 *
 * Three files use it: test/global-setup-e2e.ts writes it, test/helpers/auth.helper.ts reads it, and
 * test/global-teardown-e2e.ts deletes it. They once each computed the path on their own, and the
 * reader was one folder off, so no end-to-end test could sign in. Keep it in this one place.
 *
 * The file is at the root of the repository (ignored by Git).
 */
export const OWNER_INVITATION_FILE = path.resolve(__dirname, '..', '..', '.e2e-owner-invitation.json');

/**
 * Where the first spec file to activate the owner leaves the resulting access token, so the
 * next spec files reuse it. The invitation above is SINGLE-USE and the database is shared by
 * every spec file of the run (`--runInBand`, one seed), so activating twice always fails with
 * 401. A fresh login is no alternative: the TOTP anti-replay (`lastUsedStep`) rejects a code
 * from the time step that was just used to confirm MFA.
 *
 * Deleted by test/global-teardown-e2e.ts (ignored by Git).
 */
export const OWNER_SESSION_FILE = path.resolve(__dirname, '..', '..', '.e2e-owner-session.json');
