import { ensureTls, readCaCertificate } from './ensure';
import { fingerprintSha256, formatFingerprint } from './pki';

/**
 * LAN HTTPS certificates. Run inside the API image by the one-shot `tls-init` service:
 *
 *   node dist/src/tools/lan-tls/cli.js ensure      create the CA / issue or renew the server certificate
 *   node dist/src/tools/lan-tls/cli.js print-ca    CA certificate on stdout, fingerprint on stderr
 *
 * Reads LAN_TLS_IPS, and optionally TLS_CA_DIR / TLS_SERVER_DIR / TLS_PUBLIC_DIR. Never prints a private key.
 */
const dirs = {
    caDir: process.env.TLS_CA_DIR ?? '/tls/ca',
    serverDir: process.env.TLS_SERVER_DIR ?? '/tls/server',
    publicDir: process.env.TLS_PUBLIC_DIR ?? '/tls/public',
};

async function main(): Promise<void> {
    const command = process.argv[2];
    if (command === 'ensure') {
        await ensureTls({ ...dirs, ips: process.env.LAN_TLS_IPS, log: (line) => console.log(`[tls] ${line}`) });
        return;
    }
    if (command === 'print-ca') {
        const pem = readCaCertificate(dirs.caDir);
        process.stdout.write(pem);
        console.error(`CA fingerprint (SHA-256): ${formatFingerprint(fingerprintSha256(pem))}`);
        return;
    }
    throw new Error('Usage: cli.js <ensure|print-ca>');
}

main().catch((error: unknown) => {
    console.error(`[tls] ERROR: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
});
