import { Logger } from '@nestjs/common';
import { X509Certificate } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { createSecureContext } from 'node:tls';

/**
 * Native HTTPS for the API (LAN stack). The API terminates TLS itself - there is no reverse proxy to patch
 * and nothing between the client and the process that holds the key.
 */
export interface TlsFiles {
    keyFile: string;
    certFile: string;
}

const MIN_VERSION = 'TLSv1.2' as const;

/** `TLS_KEY_FILE` and `TLS_CERT_FILE` go together (the env validation enforces it too). Neither = plain HTTP. */
export function tlsFilesFromEnv(env: NodeJS.ProcessEnv = process.env): TlsFiles | undefined {
    const keyFile = env.TLS_KEY_FILE?.trim();
    const certFile = env.TLS_CERT_FILE?.trim();
    if (!keyFile && !certFile) return undefined;
    if (!keyFile || !certFile) {
        throw new Error('TLS_KEY_FILE and TLS_CERT_FILE must be set together.');
    }
    return { keyFile, certFile };
}

export function loadHttpsOptions(files: TlsFiles): { key: Buffer; cert: Buffer; minVersion: typeof MIN_VERSION } {
    const key = readFileSync(files.keyFile);
    const cert = readFileSync(files.certFile);
    // Fails now, with a clear error, if the key does not belong to the certificate.
    createSecureContext({ key, cert });
    return { key, cert, minVersion: MIN_VERSION };
}

export function certificateDaysLeft(certPem: Buffer | string, now = new Date()): number {
    return (new X509Certificate(certPem).validToDate.getTime() - now.getTime()) / 86_400_000;
}

interface ReloadableServer {
    setSecureContext(options: { key: Buffer; cert: Buffer; minVersion: typeof MIN_VERSION }): void;
}

/**
 * Picks up a renewed certificate WITHOUT restarting the API: the one-shot `tls-init` job rewrites the files,
 * this poll notices the change and swaps the TLS context for new connections. A bad file (mismatched key,
 * truncated write) is refused and the previous certificate keeps serving.
 * Returns a function that stops the polling.
 */
export function watchTlsFiles(
    server: ReloadableServer,
    files: TlsFiles,
    options: { intervalMs?: number; logger?: Pick<Logger, 'log' | 'warn' | 'error'> } = {},
): () => void {
    const logger = options.logger ?? new Logger('TLS');
    const signature = () => `${statSync(files.keyFile).mtimeMs}:${statSync(files.certFile).mtimeMs}`;
    let current = signature();

    const timer = setInterval(() => {
        try {
            const next = signature();
            if (next === current) return;
            server.setSecureContext(loadHttpsOptions(files));
            current = next;
            logger.log('TLS certificate reloaded.');
        } catch (error) {
            logger.error(
                `TLS certificate NOT reloaded, keeping the previous one: ${error instanceof Error ? error.message : String(error)}`,
            );
        }
    }, options.intervalMs ?? 3_600_000);
    timer.unref();
    return () => clearInterval(timer);
}
