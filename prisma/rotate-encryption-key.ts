/**
 * ENCRYPTION_KEY rotation: re-encrypts every secret stored with the previous key under the new one.
 *
 * What is encrypted with ENCRYPTION_KEY (and therefore handled here):
 *   - user_mfa.secretEncrypted            (TOTP secrets)            -> CryptoService scheme 1
 *   - platform_databases.encryptedPassword (generated DB passwords) -> CryptoService scheme 2
 *   - platform_services.encryptedConfig    (service credentials)    -> CryptoService scheme 2
 *
 * PROCEDURE (do it in a maintenance window, with a database backup taken first):
 *   1. Generate the new key:            openssl rand -hex 32
 *   2. Set  ENCRYPTION_KEY_PREVIOUS=<the OLD key>   and   ENCRYPTION_KEY=<the NEW key>
 *      and restart the app: it now reads old AND new data (writes use the new key).
 *   3. Dry run (changes nothing):       pnpm security:rotate-key
 *   4. Apply:                           pnpm security:rotate-key --apply
 *   5. Once it reports 0 rows left, remove ENCRYPTION_KEY_PREVIOUS and restart. Destroy the old key.
 *
 * Safety: every new value is computed AND verified (decrypted with the new key alone, round-trip
 * compared) in memory BEFORE anything is written; the writes then happen in ONE transaction. Any
 * failure aborts with the database untouched. Safe to re-run (already-migrated rows are skipped).
 */
import 'dotenv/config';
import { ConfigService } from '@nestjs/config';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from './generated/prisma/client';
import { CryptoService } from '../src/common/services/crypto.service';

const HEX64 = /^[0-9a-fA-F]{64}$/;

type Change = { table: 'userMfa' | 'platformDatabase' | 'platformService'; id: string; field: string; value: string };

function buildService(current: string, previous?: string): CryptoService {
    return new CryptoService(
        new ConfigService({ security: { encryptionKey: current, encryptionKeyPrevious: previous } }),
    );
}

async function main() {
    const apply = process.argv.includes('--apply');
    const current = process.env.ENCRYPTION_KEY ?? '';
    const previous = process.env.ENCRYPTION_KEY_PREVIOUS ?? '';

    if (!HEX64.test(current) || !HEX64.test(previous)) {
        throw new Error('ENCRYPTION_KEY and ENCRYPTION_KEY_PREVIOUS must both be set, as 64 hexadecimal characters.');
    }
    if (current.toLowerCase() === previous.toLowerCase()) {
        throw new Error('ENCRYPTION_KEY_PREVIOUS must be different from ENCRYPTION_KEY.');
    }
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not set.');

    const service = buildService(current, previous);
    const strict = buildService(current); // current key ONLY: this is what the app will use afterwards.

    const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL }) });
    try {
        const changes: Change[] = [];
        let scanned = 0;

        for (const row of await prisma.userMfa.findMany({ select: { id: true, secretEncrypted: true } })) {
            scanned++;
            const r = service.reencrypt(row.secretEncrypted);
            if (!r.changed) continue;
            if (strict.decrypt(r.value) !== service.decrypt(row.secretEncrypted)) throw new Error(`Verification failed for user_mfa ${row.id}`);
            changes.push({ table: 'userMfa', id: row.id, field: 'secretEncrypted', value: r.value });
        }

        for (const row of await prisma.platformDatabase.findMany({ select: { id: true, encryptedPassword: true } })) {
            scanned++;
            const r = service.reencryptWithRawKey(row.encryptedPassword);
            if (!r.changed) continue;
            if (strict.decryptWithRawKey(r.value, current) !== service.decryptWithRawKey(row.encryptedPassword, current)) {
                throw new Error(`Verification failed for platform_databases ${row.id}`);
            }
            changes.push({ table: 'platformDatabase', id: row.id, field: 'encryptedPassword', value: r.value });
        }

        for (const row of await prisma.platformService.findMany({ select: { id: true, encryptedConfig: true } })) {
            if (!row.encryptedConfig) continue;
            scanned++;
            const r = service.reencryptWithRawKey(row.encryptedConfig);
            if (!r.changed) continue;
            if (strict.decryptWithRawKey(r.value, current) !== service.decryptWithRawKey(row.encryptedConfig, current)) {
                throw new Error(`Verification failed for platform_services ${row.id}`);
            }
            changes.push({ table: 'platformService', id: row.id, field: 'encryptedConfig', value: r.value });
        }

        console.log(`[rotate] ${scanned} encrypted value(s) scanned, ${changes.length} still under the previous key.`);
        if (!apply) {
            console.log('[rotate] DRY RUN: nothing written. Re-run with --apply (after a database backup).');
            return;
        }
        if (changes.length === 0) {
            console.log('[rotate] Nothing to do: you can now remove ENCRYPTION_KEY_PREVIOUS.');
            return;
        }

        await prisma.$transaction(async (tx) => {
            for (const c of changes) {
                const data = { [c.field]: c.value };
                if (c.table === 'userMfa') await tx.userMfa.update({ where: { id: c.id }, data });
                else if (c.table === 'platformDatabase') await tx.platformDatabase.update({ where: { id: c.id }, data });
                else await tx.platformService.update({ where: { id: c.id }, data });
            }
        });
        console.log(`[rotate] DONE: ${changes.length} value(s) re-encrypted. Remove ENCRYPTION_KEY_PREVIOUS and restart.`);
    } finally {
        await prisma.$disconnect();
    }
}

main().catch((error) => {
    console.error(`[rotate] FAILED, database left untouched: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
});
