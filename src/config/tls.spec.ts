import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect } from 'node:tls';
import { ensureTls } from '../tools/lan-tls/ensure';
import { certificateDaysLeft, loadHttpsOptions, tlsFilesFromEnv, watchTlsFiles } from './tls';

describe('tlsFilesFromEnv', () => {
    it('ni l’un ni l’autre : HTTP simple', () => {
        expect(tlsFilesFromEnv({})).toBeUndefined();
        expect(tlsFilesFromEnv({ TLS_KEY_FILE: '  ', TLS_CERT_FILE: '' })).toBeUndefined();
    });
    it('les deux : activé', () => {
        expect(tlsFilesFromEnv({ TLS_KEY_FILE: '/k', TLS_CERT_FILE: '/c' })).toEqual({ keyFile: '/k', certFile: '/c' });
    });
    it('un seul des deux : erreur (jamais de demi-configuration silencieuse)', () => {
        expect(() => tlsFilesFromEnv({ TLS_KEY_FILE: '/k' })).toThrow(/set together/);
        expect(() => tlsFilesFromEnv({ TLS_CERT_FILE: '/c' })).toThrow(/set together/);
    });
});

describe('HTTPS natif de l’API', () => {
    let root: string;
    let server: https.Server;
    let stop: () => void;
    const dirs = () => ({ caDir: join(root, 'ca'), serverDir: join(root, 'server'), publicDir: join(root, 'public') });
    const files = () => ({
        keyFile: join(dirs().serverDir, 'server.key'),
        certFile: join(dirs().serverDir, 'server.crt'),
    });
    const caPem = () => readFileSync(join(dirs().caDir, 'ca.crt'), 'utf8');
    const port = () => (server.address() as AddressInfo).port;

    beforeEach(async () => {
        root = mkdtempSync(join(tmpdir(), 'backos-https-'));
        await ensureTls({ ...dirs(), ips: '192.168.1.20' });
        server = https.createServer(loadHttpsOptions(files()), (_req, res) => res.end('ok'));
        await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
        stop = () => undefined;
    });
    afterEach(async () => {
        stop();
        await new Promise((resolve) => server.close(resolve));
        rmSync(root, { recursive: true, force: true });
    });

    const get = (ca?: string) =>
        new Promise<string>((resolve, reject) => {
            https
                .get({ host: '127.0.0.1', port: port(), path: '/', ca, agent: false }, (res) => {
                    let body = '';
                    res.on('data', (d) => (body += d));
                    res.on('end', () => resolve(body));
                })
                .on('error', reject);
        });
    const serial = () =>
        new Promise<string>((resolve, reject) => {
            const socket = connect({ host: '127.0.0.1', port: port(), ca: caPem(), servername: '' }, () => {
                const { serialNumber } = socket.getPeerCertificate();
                socket.end();
                resolve(serialNumber);
            });
            socket.on('error', reject);
        });

    it('un client qui connaît la CA vérifie le serveur (adresse de bouclage comprise)', async () => {
        await expect(get(caPem())).resolves.toBe('ok');
    });

    it('un client qui ne connaît pas la CA REFUSE la connexion', async () => {
        await expect(get(undefined)).rejects.toThrow(/self-signed|unable to (get local issuer|verify)/i);
    });

    it('un client qui fait confiance à une AUTRE CA refuse la connexion', async () => {
        const other = mkdtempSync(join(tmpdir(), 'backos-other-'));
        try {
            await ensureTls({
                caDir: join(other, 'ca'),
                serverDir: join(other, 's'),
                publicDir: join(other, 'p'),
                ips: '192.168.1.20',
            });
            await expect(get(readFileSync(join(other, 'ca', 'ca.crt'), 'utf8'))).rejects.toThrow();
        } finally {
            rmSync(other, { recursive: true, force: true });
        }
    });

    it('le serveur présente la chaîne (feuille + CA), donc la CA est lisible dans la poignée de main', async () => {
        await new Promise<void>((resolve, reject) => {
            const socket = connect({ host: '127.0.0.1', port: port(), ca: caPem(), servername: '' }, () => {
                const leaf = socket.getPeerCertificate(true);
                socket.end();
                try {
                    expect(leaf.issuerCertificate).toBeDefined();
                    expect(leaf.issuerCertificate.subject.CN).toMatch(/BACKOS LAN Root CA/);
                    resolve();
                } catch (e) {
                    reject(e instanceof Error ? e : new Error(String(e)));
                }
            });
            socket.on('error', reject);
        });
    });

    it('refuse de démarrer avec une clé qui n’appartient pas au certificat', async () => {
        const other = mkdtempSync(join(tmpdir(), 'backos-other-'));
        try {
            await ensureTls({
                caDir: join(other, 'ca'),
                serverDir: join(other, 's'),
                publicDir: join(other, 'p'),
                ips: '192.168.1.20',
            });
            expect(() =>
                loadHttpsOptions({ keyFile: join(other, 's', 'server.key'), certFile: files().certFile }),
            ).toThrow();
        } finally {
            rmSync(other, { recursive: true, force: true });
        }
    });

    it('un certificat renouvelé est pris en compte SANS redémarrage ; un fichier invalide est refusé', async () => {
        const logger = { log: jest.fn(), warn: jest.fn(), error: jest.fn() };
        stop = watchTlsFiles(server, files(), { intervalMs: 40, logger });
        const before = await serial();

        // Renouvellement : le job tls-init réécrit les fichiers (nouvelle adresse => nouveau certificat).
        await new Promise((r) => setTimeout(r, 30)); // garantit une date de modification différente
        await ensureTls({ ...dirs(), ips: '192.168.1.20,192.168.1.77' });
        await new Promise((r) => setTimeout(r, 200));
        const after = await serial();
        expect(after).not.toBe(before);
        expect(logger.log).toHaveBeenCalledWith('TLS certificate reloaded.');

        // Fichier corrompu : l'ancien certificat continue de servir.
        await new Promise((r) => setTimeout(r, 30));
        writeFileSync(files().certFile, 'not a certificate');
        await new Promise((r) => setTimeout(r, 200));
        expect(logger.error).toHaveBeenCalled();
        expect(await serial()).toBe(after);
    });

    it('calcule les jours restants', () => {
        expect(certificateDaysLeft(readFileSync(files().certFile))).toBeGreaterThan(170);
    });
});
