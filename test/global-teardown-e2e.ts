import * as fs from 'fs';
import { execSync } from 'child_process';
import { composeFileArgs } from './helpers/compose-files';
import { OWNER_INVITATION_FILE, OWNER_SESSION_FILE } from './helpers/owner-invitation-file';

/**
 * Jest `globalTeardown` - counterpart to global-setup-e2e.ts. Set KEEP_TEST_INFRA=1 to skip
 * this (e.g. while iterating locally on a single spec file repeatedly) and reuse the same
 * containers across runs instead of paying the Postgres/Redis startup cost every time.
 */
export default async function globalTeardown() {
    // Contains the owner's raw activation token/code/email in plaintext (see
    // global-setup-e2e.ts) - always removed, even when KEEP_TEST_INFRA=1 keeps the containers
    // up, since a stale copy would let anyone with repo access activate that owner account.
    if (fs.existsSync(OWNER_INVITATION_FILE)) fs.unlinkSync(OWNER_INVITATION_FILE);
    if (fs.existsSync(OWNER_SESSION_FILE)) fs.unlinkSync(OWNER_SESSION_FILE);

    if (process.env.KEEP_TEST_INFRA === '1') {
        console.log('[e2e] KEEP_TEST_INFRA=1 - leaving test infra running.');
        return;
    }
    console.log('[e2e] Stopping test infra...');
    execSync(`docker compose ${composeFileArgs()} down -v`, { stdio: 'inherit' });
}
