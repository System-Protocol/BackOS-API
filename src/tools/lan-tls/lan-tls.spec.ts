import { X509Certificate } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSecureContext } from 'node:tls';
import { ensureTls } from './ensure';
import {
    DOCKER_HOST_NAME,
    RENEW_BEFORE_DAYS,
    SERVER_VALIDITY_DAYS,
    createCa,
    createServerCert,
    daysLeft,
    firstPem,
    fingerprintSha256,
    isCertifiableIp,
    needsRenewal,
    parseIpList,
} from './pki';

const dayMs = 86_400_000;

describe('private PKI', () => {
    let ca: Awaited<ReturnType<typeof createCa>>;
    beforeAll(async () => {
        ca = await createCa();
    });

    it('la CA est une vraie autorité (pathlen 0) avec une contrainte de noms CRITIQUE', () => {
        const cert = new X509Certificate(ca.certPem);
        expect(cert.ca).toBe(true);
        expect(cert.subject).toMatch(/BACKOS LAN Root CA/);
        // OID 2.5.29.30 = NameConstraints; its criticality byte (0x01 0xFF) must be present in the DER.
        const hex = cert.raw.toString('hex');
        expect(hex).toContain('0603551d1e'); // OID 2.5.29.30
        expect(hex).toMatch(/0603551d1e0101ff/); // ... followed by BOOLEAN TRUE (critical)
    });

    it('le certificat serveur est signé par la CA, valable pour les bonnes adresses uniquement', async () => {
        const leafPair = await createServerCert(ca, ['192.168.1.20', '10.8.0.1']);
        const leaf = new X509Certificate(leafPair.certPem);
        const caCert = new X509Certificate(ca.certPem);

        expect(leaf.ca).toBe(false);
        expect(leaf.checkIssued(caCert)).toBe(true);
        expect(leaf.verify(caCert.publicKey)).toBe(true);
        expect(leaf.checkIP('192.168.1.20')).toBeDefined();
        expect(leaf.checkIP('10.8.0.1')).toBeDefined();
        expect(leaf.checkIP('192.168.1.99')).toBeUndefined();
        expect(leaf.checkHost(DOCKER_HOST_NAME)).toBeDefined();
        expect(leaf.checkHost('localhost')).toBeDefined(); // application et serveur sur le même PC
        expect(leaf.checkHost('localhost.evil.example')).toBeUndefined();
        expect(leaf.checkHost('evil.example')).toBeUndefined();
        expect(leaf.keyUsage).toContain('1.3.6.1.5.5.7.3.1'); // serverAuth
        const lifetime = (leaf.validToDate.getTime() - leaf.validFromDate.getTime()) / dayMs;
        expect(lifetime).toBeLessThanOrEqual(SERVER_VALIDITY_DAYS + 2);
    });

    it('le certificat serveur ne peut pas être signé par une autre CA', async () => {
        const other = await createCa();
        const leaf = new X509Certificate((await createServerCert(other, ['192.168.1.20'])).certPem);
        expect(leaf.verify(new X509Certificate(ca.certPem).publicKey)).toBe(false);
    });

    it('refuse de certifier une adresse publique ou invalide', async () => {
        await expect(createServerCert(ca, ['8.8.8.8'])).rejects.toThrow(/cannot be certified/);
        await expect(createServerCert(ca, [])).rejects.toThrow(/At least one/);
    });

    it('chaque CA et chaque certificat ont un numéro de série et une clé uniques', async () => {
        const a = await createServerCert(ca, ['192.168.1.20']);
        const b = await createServerCert(ca, ['192.168.1.20']);
        expect(new X509Certificate(a.certPem).serialNumber).not.toBe(new X509Certificate(b.certPem).serialNumber);
        expect(a.keyPem).not.toBe(b.keyPem);
        expect(fingerprintSha256(ca.certPem)).toMatch(/^[0-9A-F]{64}$/);
    });

    describe('isCertifiableIp / parseIpList', () => {
        it.each(['10.1.2.3', '172.16.0.1', '172.31.255.254', '192.168.0.1', '127.0.0.1', '::1', 'fd12:3456::1'])(
            'accepte %s',
            (ip) => expect(isCertifiableIp(ip)).toBe(true),
        );
        it.each(['8.8.8.8', '172.32.0.1', '172.15.0.1', '192.169.0.1', '100.64.0.1', '2001:db8::1', 'abc', ''])(
            'refuse %p',
            (ip) => expect(isCertifiableIp(ip)).toBe(false),
        );
        it('découpe, nettoie et dédoublonne la liste', () => {
            expect(parseIpList(' 192.168.1.20 , 10.8.0.1,192.168.1.20 ,')).toEqual(['192.168.1.20', '10.8.0.1']);
            expect(parseIpList('')).toEqual([]);
            expect(parseIpList(undefined)).toEqual([]);
        });
        it('refuse une adresse publique avec un message clair', () => {
            expect(() => parseIpList('192.168.1.20, 203.0.113.9')).toThrow(/not a private-network address/);
            expect(() => parseIpList('not-an-ip')).toThrow(/not a valid IP/);
        });
    });

    describe('needsRenewal', () => {
        it('renouvelle si absent, illisible, adresses nouvelles ou expiration proche', async () => {
            const now = new Date();
            const leaf = (await createServerCert(ca, ['192.168.1.20', '127.0.0.1'], now)).chainPem;
            expect(needsRenewal(undefined, ['192.168.1.20'], now)).toMatch(/no certificate/);
            expect(needsRenewal('garbage', ['192.168.1.20'], now)).toMatch(/unreadable/);
            expect(needsRenewal(leaf, ['192.168.1.20', '10.8.0.1'], now)).toMatch(/addresses changed.*10\.8\.0\.1/);
            expect(needsRenewal(leaf, ['192.168.1.20'], now)).toBeNull();
            const soon = new Date(now.getTime() + (SERVER_VALIDITY_DAYS - RENEW_BEFORE_DAYS + 5) * dayMs);
            expect(needsRenewal(leaf, ['192.168.1.20'], soon)).toMatch(/expires in/);
        });
        it('lit le premier certificat d’un fichier chaîne (feuille + CA)', async () => {
            const { chainPem } = await createServerCert(ca, ['192.168.1.20']);
            expect(chainPem.match(/BEGIN CERTIFICATE/g)).toHaveLength(2);
            // Régression : chaque bloc se termine par un saut de ligne, sinon OpenSSL refuse la chaîne
            // ("PEM routines::bad end line") dès que le serveur la charge.
            expect(chainPem).not.toMatch(/-----END CERTIFICATE----------BEGIN/);
            expect(chainPem.endsWith('-----END CERTIFICATE-----\n')).toBe(true);
            expect(() => createSecureContext({ key: ca.keyPem, cert: chainPem })).toThrow(); // clé de CA != clé du serveur
            expect(() => createSecureContext({ cert: chainPem })).not.toThrow();
            expect(new X509Certificate(firstPem(chainPem)).subject).toMatch(/BACKOS LAN API/);
            expect(daysLeft(chainPem)).toBeGreaterThan(SERVER_VALIDITY_DAYS - 3);
        });
    });
});

describe('ensureTls', () => {
    let root: string;
    const dirs = () => ({ caDir: join(root, 'ca'), serverDir: join(root, 'server'), publicDir: join(root, 'public') });
    beforeEach(() => {
        root = mkdtempSync(join(tmpdir(), 'backos-tls-'));
    });
    afterEach(() => rmSync(root, { recursive: true, force: true }));

    it('premier lancement : crée la CA et le certificat, avec les bons droits', async () => {
        const logs: string[] = [];
        const r = await ensureTls({ ...dirs(), ips: '192.168.1.20,10.8.0.1', log: (l) => logs.push(l) });
        expect(r.caCreated).toBe(true);
        expect(r.serverIssued).toBe(true);
        expect(r.ips).toEqual(['192.168.1.20', '10.8.0.1', '127.0.0.1', '::1']);
        expect(logs.join('\n')).toMatch(/CA fingerprint \(SHA-256\): ([0-9A-F]{2}:){31}[0-9A-F]{2}/);

        const { caDir, serverDir } = dirs();
        if (process.platform !== 'win32') {
            expect(statSync(join(caDir, 'ca.key')).mode & 0o777).toBe(0o600);
            expect(statSync(join(serverDir, 'server.key')).mode & 0o777).toBe(0o600);
        }
        const leaf = new X509Certificate(firstPem(readFileSync(join(serverDir, 'server.crt'), 'utf8')));
        expect(leaf.checkIP('127.0.0.1')).toBeDefined();
        expect(leaf.verify(new X509Certificate(readFileSync(join(caDir, 'ca.crt'))).publicKey)).toBe(true);
    });

    it('la clé de la CA n’est JAMAIS dans le dossier du serveur ni dans le dossier public', async () => {
        await ensureTls({ ...dirs(), ips: '192.168.1.20' });
        const { serverDir, publicDir } = dirs();
        expect(existsSync(join(serverDir, 'ca.key'))).toBe(false);
        expect(existsSync(join(publicDir, 'ca.key'))).toBe(false);
        for (const file of [join(publicDir, 'ca.crt'), join(serverDir, 'server.crt')]) {
            expect(readFileSync(file, 'utf8')).not.toContain('PRIVATE KEY');
        }
        const caKeyPem = readFileSync(join(dirs().caDir, 'ca.key'), 'utf8');
        expect(readFileSync(join(serverDir, 'server.key'), 'utf8')).not.toBe(caKeyPem);
    });

    it('relancer ne change rien (idempotent) : mêmes fichiers, même empreinte de CA', async () => {
        const first = await ensureTls({ ...dirs(), ips: '192.168.1.20' });
        const before = readFileSync(join(dirs().serverDir, 'server.crt'), 'utf8');
        const second = await ensureTls({ ...dirs(), ips: '192.168.1.20' });
        expect(second.caCreated).toBe(false);
        expect(second.serverIssued).toBe(false);
        expect(second.caFingerprint).toBe(first.caFingerprint);
        expect(readFileSync(join(dirs().serverDir, 'server.crt'), 'utf8')).toBe(before);
    });

    it('changement d’adresse : nouveau certificat, MÊME CA (les clients n’ont rien à refaire)', async () => {
        const first = await ensureTls({ ...dirs(), ips: '192.168.1.20' });
        const second = await ensureTls({ ...dirs(), ips: '192.168.1.20,192.168.1.77' });
        expect(second.serverIssued).toBe(true);
        expect(second.reason).toMatch(/addresses changed/);
        expect(second.caFingerprint).toBe(first.caFingerprint);
        const leaf = new X509Certificate(firstPem(readFileSync(join(dirs().serverDir, 'server.crt'), 'utf8')));
        expect(leaf.checkIP('192.168.1.77')).toBeDefined();
    });

    it('renouvelle avant expiration, avec une nouvelle clé, sans toucher à la CA', async () => {
        const start = new Date();
        const first = await ensureTls({ ...dirs(), ips: '192.168.1.20', now: start });
        const keyBefore = readFileSync(join(dirs().serverDir, 'server.key'), 'utf8');
        const later = new Date(start.getTime() + (SERVER_VALIDITY_DAYS - 10) * dayMs);
        const second = await ensureTls({ ...dirs(), ips: '192.168.1.20', now: later });
        expect(second.serverIssued).toBe(true);
        expect(second.reason).toMatch(/expires in/);
        expect(second.caFingerprint).toBe(first.caFingerprint);
        expect(readFileSync(join(dirs().serverDir, 'server.key'), 'utf8')).not.toBe(keyBefore);
    });

    it('réémet si la clé du serveur a disparu', async () => {
        await ensureTls({ ...dirs(), ips: '192.168.1.20' });
        unlinkSync(join(dirs().serverDir, 'server.key'));
        expect((await ensureTls({ ...dirs(), ips: '192.168.1.20' })).serverIssued).toBe(true);
    });

    it('ne régénère JAMAIS une CA incomplète (ce serait forcer tous les clients à ré-épingler)', async () => {
        await ensureTls({ ...dirs(), ips: '192.168.1.20' });
        unlinkSync(join(dirs().caDir, 'ca.key'));
        await expect(ensureTls({ ...dirs(), ips: '192.168.1.20' })).rejects.toThrow(/CA is incomplete.*ca\.key/);
    });

    it('exige des adresses, et refuse les adresses publiques', async () => {
        await expect(ensureTls({ ...dirs(), ips: '' })).rejects.toThrow(/LAN_TLS_IPS is empty/);
        await expect(ensureTls({ ...dirs(), ips: undefined })).rejects.toThrow(/LAN_TLS_IPS is empty/);
        await expect(ensureTls({ ...dirs(), ips: '203.0.113.9' })).rejects.toThrow(/private-network/);
    });
});
