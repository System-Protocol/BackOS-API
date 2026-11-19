import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
    createCa,
    createServerCert,
    daysLeft,
    fingerprintSha256,
    firstPem,
    formatFingerprint,
    needsRenewal,
    parseIpList,
} from './pki';

export interface EnsureOptions {
    /** Holds the CA private key. Mounted ONLY in the short-lived tls-init job. */
    caDir: string;
    /** Holds the server key + certificate chain. Mounted read-only in the API. */
    serverDir: string;
    /** Holds the PUBLIC CA certificate only (given to generated backends so they can verify the API). */
    publicDir: string;
    /** Raw `LAN_TLS_IPS` value. */
    ips: string | undefined;
    now?: Date;
    log?: (line: string) => void;
}

export interface EnsureResult {
    caCreated: boolean;
    serverIssued: boolean;
    reason: string | null;
    caFingerprint: string;
    ips: string[];
}

/** Always certified, so the container health check and local tools can verify the API over loopback. */
const ALWAYS_IPS = ['127.0.0.1', '::1'];

function writeAtomic(file: string, content: string, mode: number): void {
    const tmp = `${file}.tmp`;
    writeFileSync(tmp, content, { mode });
    chmodSync(tmp, mode);
    renameSync(tmp, file); // never leaves a half-written certificate or key behind
}

const readIfExists = (file: string): string | undefined => (existsSync(file) ? readFileSync(file, 'utf8') : undefined);

/**
 * Makes sure the LAN stack has a CA and a valid server certificate for the configured addresses.
 * Idempotent: running it again changes nothing until the addresses change or the certificate nears expiry.
 * The CA is NEVER regenerated implicitly (that would force every client to pin it again): a half-present CA
 * is an error you must resolve on purpose.
 */
export async function ensureTls(options: EnsureOptions): Promise<EnsureResult> {
    const now = options.now ?? new Date();
    const log = options.log ?? (() => undefined);

    const configured = parseIpList(options.ips);
    if (configured.length === 0) {
        throw new Error(
            'LAN_TLS_IPS is empty. List the addresses clients use to reach this server, e.g. LAN_TLS_IPS=192.168.1.20,10.8.0.1 (LAN address, then WireGuard address).',
        );
    }
    const ips = [...new Set([...configured, ...ALWAYS_IPS])];

    for (const dir of [options.caDir, options.serverDir, options.publicDir]) mkdirSync(dir, { recursive: true });

    const caCertFile = join(options.caDir, 'ca.crt');
    const caKeyFile = join(options.caDir, 'ca.key');
    let caCert = readIfExists(caCertFile);
    let caKey = readIfExists(caKeyFile);

    let caCreated = false;
    if (!caCert && !caKey) {
        const ca = await createCa(now);
        caCert = ca.certPem;
        caKey = ca.keyPem;
        writeAtomic(caKeyFile, caKey, 0o600);
        writeAtomic(caCertFile, caCert, 0o644);
        caCreated = true;
        log('Created a new private Certificate Authority.');
    } else if (!caCert || !caKey) {
        throw new Error(
            `The CA is incomplete (${caCert ? 'ca.key' : 'ca.crt'} is missing in ${options.caDir}). Restore it from a backup. ` +
                'Regenerating it would force every desktop app to pin the new CA again, so this is never done automatically.',
        );
    }

    const caFingerprint = fingerprintSha256(caCert);
    const caDaysLeft = daysLeft(caCert, now);
    if (caDaysLeft < 365) {
        log(
            `WARNING: the CA expires in ${Math.floor(caDaysLeft)} days. Plan to replace it and pin the new one on every client.`,
        );
    }

    const serverCertFile = join(options.serverDir, 'server.crt');
    const serverKeyFile = join(options.serverDir, 'server.key');
    const existing = readIfExists(serverCertFile);
    const hasKey = existsSync(serverKeyFile);
    const reason = !hasKey ? 'no server key yet' : needsRenewal(existing, ips, now);

    let serverIssued = false;
    if (reason) {
        const server = await createServerCert({ certPem: caCert, keyPem: caKey }, ips, now);
        writeAtomic(serverKeyFile, server.keyPem, 0o600);
        writeAtomic(serverCertFile, server.chainPem, 0o644);
        serverIssued = true;
        log(`Issued a server certificate (${reason}) for: ${ips.join(', ')}.`);
    } else {
        log(`Server certificate is valid for: ${ips.join(', ')} (${Math.floor(daysLeft(existing!, now))} days left).`);
    }

    // Public copy of the CA (certificate only, never the key), for generated backends.
    writeAtomic(join(options.publicDir, 'ca.crt'), firstPem(caCert), 0o644);

    log(`CA fingerprint (SHA-256): ${formatFingerprint(caFingerprint)}`);
    return { caCreated, serverIssued, reason: serverIssued ? reason : null, caFingerprint, ips };
}

export function readCaCertificate(caDir: string): string {
    const pem = readIfExists(join(caDir, 'ca.crt'));
    if (!pem) throw new Error(`No CA found in ${caDir}. Start the stack once so it gets created.`);
    return pem;
}
