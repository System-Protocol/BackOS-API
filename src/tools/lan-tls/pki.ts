import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { createHash, randomBytes, webcrypto, X509Certificate } from 'node:crypto';
import { BlockList, isIP } from 'node:net';

/**
 * Private PKI for the LAN stack (see docs/deployments/DEPLOIEMENT_LAN.md, "HTTPS").
 *
 * WHY A PRIVATE CA: the LAN API is reached by IP address, so no public CA can certify it. We create our
 * own, with three guard rails:
 *   1. NAME CONSTRAINTS (critical): the CA can only ever certify private network addresses (RFC 1918,
 *      loopback, IPv6 ULA) and the two DNS names `host.docker.internal` and `localhost`. If its key leaked, it still
 *      could not impersonate a public site, even on a computer that trusts it.
 *   2. The CA key lives in its own volume, mounted ONLY in the short-lived `tls-init` job, never in the
 *      long-running API: compromising the API does not hand over the power to issue certificates.
 *   3. The server certificate is short-lived (180 days) and renewed automatically; clients pin the CA.
 */
x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;
const CA_VALIDITY_DAYS = 3650;
export const SERVER_VALIDITY_DAYS = 180;
/** Renew when fewer than this many days are left. */
export const RENEW_BEFORE_DAYS = 45;
/** `host.docker.internal`: how generated backends (Docker containers) reach the API. */
export const DOCKER_HOST_NAME = 'host.docker.internal';
/** The only DNS names the CA may ever certify (everything else it signs is an IP address on a private network). */
export const PERMITTED_DNS_NAMES: readonly string[] = [DOCKER_HOST_NAME, 'localhost'];

interface Cidr {
    ip: string;
    prefix: number;
}

/** Address ranges the CA is allowed to certify. Single source of truth for the constraint AND the checks. */
export const PERMITTED_RANGES: readonly Cidr[] = [
    { ip: '10.0.0.0', prefix: 8 },
    { ip: '172.16.0.0', prefix: 12 },
    { ip: '192.168.0.0', prefix: 16 },
    { ip: '127.0.0.0', prefix: 8 },
    { ip: '::1', prefix: 128 },
    { ip: 'fc00::', prefix: 7 },
];

export interface PemPair {
    certPem: string;
    keyPem: string;
}

// ------------------------------------------------------------------------------------------------
// DER helpers (just enough to encode the NameConstraints extension)
// ------------------------------------------------------------------------------------------------

function derLength(length: number): Uint8Array {
    if (length < 0x80) return Uint8Array.of(length);
    const bytes: number[] = [];
    for (let n = length; n > 0; n >>= 8) bytes.unshift(n & 0xff);
    return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function der(tag: number, ...parts: Uint8Array[]): Uint8Array {
    const body = Buffer.concat(parts);
    return Buffer.concat([Uint8Array.of(tag), derLength(body.length), body]);
}

function ipBytes(ip: string): Uint8Array {
    const family = isIP(ip);
    if (family === 4) return Uint8Array.from(ip.split('.').map(Number));
    if (family === 6) {
        const [head, tail = ''] = ip.split('::');
        const h = head ? head.split(':') : [];
        const t = tail ? tail.split(':') : [];
        const groups = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
        return Uint8Array.from(groups.flatMap((g) => [(parseInt(g, 16) >> 8) & 0xff, parseInt(g, 16) & 0xff]));
    }
    throw new Error(`Not an IP address: ${ip}`);
}

function maskBytes(prefix: number, length: number): Uint8Array {
    const mask = new Uint8Array(length);
    for (let i = 0; i < prefix; i++) mask[i >> 3] |= 0x80 >> (i & 7);
    return mask;
}

/** RFC 5280 NameConstraints: permitted iPAddress ranges + the one permitted dNSName. Encoded as critical. */
function nameConstraintsExtension(): x509.Extension {
    const ipSubtrees = PERMITTED_RANGES.map(({ ip, prefix }) => {
        const addr = ipBytes(ip);
        return der(0x30, der(0x87, addr, maskBytes(prefix, addr.length))); // GeneralSubtree{ base = iPAddress }
    });
    const dnsSubtrees = PERMITTED_DNS_NAMES.map((name) => der(0x30, der(0x82, Buffer.from(name, 'ascii')))); // dNSName
    const permitted = der(0xa0, ...ipSubtrees, ...dnsSubtrees); // [0] permittedSubtrees
    const value = der(0x30, permitted);
    return new x509.Extension('2.5.29.30', true, new Uint8Array(value).buffer);
}

// ------------------------------------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------------------------------------

const allowed = new BlockList();
for (const { ip, prefix } of PERMITTED_RANGES) allowed.addSubnet(ip, prefix, isIP(ip) === 6 ? 'ipv6' : 'ipv4');

/** True when the CA is allowed to certify this address. */
export function isCertifiableIp(ip: string): boolean {
    const family = isIP(ip);
    return family !== 0 && allowed.check(ip, family === 6 ? 'ipv6' : 'ipv4');
}

/**
 * Parses `LAN_TLS_IPS` ("192.168.1.20, 10.8.0.1"). Every address must be a private-network address:
 * the CA's name constraints would make a certificate for anything else invalid anyway, so we refuse early
 * with a clear message instead of producing a certificate that clients reject.
 */
export function parseIpList(raw: string | undefined): string[] {
    const ips = (raw ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    for (const ip of ips) {
        if (isIP(ip) === 0) throw new Error(`LAN_TLS_IPS: "${ip}" is not a valid IP address.`);
        if (!isCertifiableIp(ip)) {
            throw new Error(
                `LAN_TLS_IPS: "${ip}" is not a private-network address (10.x, 172.16-31.x, 192.168.x). Never expose this stack to the Internet.`,
            );
        }
    }
    return [...new Set(ips)];
}

/** One PEM block, always ending with a newline (so blocks can be concatenated into a chain safely). */
const normalizePem = (pem: string): string => pem.trim() + '\n';

function toPem(label: string, der: ArrayBuffer): string {
    const body = Buffer.from(der)
        .toString('base64')
        .replace(/(.{64})/g, '$1\n');
    return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

function serialNumber(): string {
    const bytes = randomBytes(16);
    bytes[0] &= 0x7f; // positive INTEGER
    if (bytes[0] === 0) bytes[0] = 1;
    return bytes.toString('hex');
}

const addDays = (date: Date, days: number) => new Date(date.getTime() + days * 86_400_000);

async function generateKeys(): Promise<CryptoKeyPair> {
    return (await webcrypto.subtle.generateKey(ALGORITHM, true, ['sign', 'verify'])) as CryptoKeyPair;
}

async function exportKeyPem(key: CryptoKey): Promise<string> {
    return toPem('PRIVATE KEY', await webcrypto.subtle.exportKey('pkcs8', key));
}

async function importKeyPem(pem: string): Promise<CryptoKey> {
    const b64 = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
    return (await webcrypto.subtle.importKey('pkcs8', Buffer.from(b64, 'base64'), ALGORITHM, true, [
        'sign',
    ])) as CryptoKey;
}

// ------------------------------------------------------------------------------------------------
// Public API
// ------------------------------------------------------------------------------------------------

export async function createCa(now = new Date()): Promise<PemPair> {
    const keys = await generateKeys();
    const suffix = randomBytes(4).toString('hex').toUpperCase();
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: serialNumber(),
        name: `CN=BACKOS LAN Root CA ${suffix}`,
        notBefore: addDays(now, -1),
        notAfter: addDays(now, CA_VALIDITY_DAYS),
        signingAlgorithm: ALGORITHM,
        keys,
        extensions: [
            new x509.BasicConstraintsExtension(true, 0, true),
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
            await x509.SubjectKeyIdentifierExtension.create(keys.publicKey, false),
            nameConstraintsExtension(),
        ],
    });
    return { certPem: normalizePem(cert.toString('pem')), keyPem: await exportKeyPem(keys.privateKey) };
}

export interface ServerCert extends PemPair {
    /** Leaf + CA, in that order: what the server presents, so clients can read the CA from the handshake. */
    chainPem: string;
}

export async function createServerCert(ca: PemPair, ips: string[], now = new Date()): Promise<ServerCert> {
    if (ips.length === 0) throw new Error('At least one IP address is required.');
    for (const ip of ips) {
        if (!isCertifiableIp(ip))
            throw new Error(`"${ip}" cannot be certified by this CA (not a private-network address).`);
    }
    const caCert = new x509.X509Certificate(ca.certPem);
    const caKey = await importKeyPem(ca.keyPem);
    const keys = await generateKeys();

    const cert = await x509.X509CertificateGenerator.create({
        serialNumber: serialNumber(),
        subject: 'CN=BACKOS LAN API',
        issuer: caCert.subject,
        notBefore: addDays(now, -1),
        notAfter: addDays(now, SERVER_VALIDITY_DAYS),
        signingAlgorithm: ALGORITHM,
        publicKey: keys.publicKey,
        signingKey: caKey,
        extensions: [
            new x509.BasicConstraintsExtension(false, undefined, true),
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
            new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth], true),
            new x509.SubjectAlternativeNameExtension(
                [
                    ...ips.map((value) => ({ type: 'ip' as const, value })),
                    ...PERMITTED_DNS_NAMES.map((value) => ({ type: 'dns' as const, value })),
                ],
                false,
            ),
            await x509.SubjectKeyIdentifierExtension.create(keys.publicKey, false),
            await x509.AuthorityKeyIdentifierExtension.create(caCert, false),
        ],
    });
    const certPem = normalizePem(cert.toString('pem'));
    return { certPem, keyPem: await exportKeyPem(keys.privateKey), chainPem: certPem + normalizePem(ca.certPem) };
}

/** SHA-256 of the certificate, uppercase hex without separators (what the desktop app asks for). */
export function fingerprintSha256(certPem: string): string {
    return createHash('sha256').update(new X509Certificate(certPem).raw).digest('hex').toUpperCase();
}

/** "AB:CD:..." form, easier to compare by eye. */
export function formatFingerprint(hex: string): string {
    return hex.match(/.{2}/g)!.join(':');
}

export interface LeafInfo {
    notAfter: Date;
    ips: string[];
}

/** First certificate of a PEM bundle (the server file holds leaf + CA). */
export function firstPem(bundle: string): string {
    const match = bundle.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
    if (!match) throw new Error('No certificate found in PEM data.');
    return match[0] + '\n';
}

export function inspectLeaf(certPem: string): LeafInfo {
    const cert = new x509.X509Certificate(firstPem(certPem));
    const san = cert.getExtension(x509.SubjectAlternativeNameExtension);
    const ips = (san?.names.items ?? []).filter((n) => n.type === 'ip').map((n) => n.value);
    return { notAfter: cert.notAfter, ips };
}

/** Should the server certificate be (re)issued? Missing/unreadable, other addresses, or close to expiry. */
export function needsRenewal(leafPem: string | undefined, ips: string[], now = new Date()): string | null {
    if (!leafPem) return 'no certificate yet';
    let info: LeafInfo;
    try {
        info = inspectLeaf(leafPem);
    } catch {
        return 'the existing certificate is unreadable';
    }
    const have = new Set(info.ips.map(normalizeIp));
    const missing = ips.filter((ip) => !have.has(normalizeIp(ip)));
    if (missing.length > 0) return `addresses changed (new: ${missing.join(', ')})`;
    const daysLeft = (info.notAfter.getTime() - now.getTime()) / 86_400_000;
    if (daysLeft < RENEW_BEFORE_DAYS) return `expires in ${Math.max(0, Math.floor(daysLeft))} days`;
    return null;
}

function normalizeIp(ip: string): string {
    return Buffer.from(ipBytes(ip)).toString('hex');
}

export function daysLeft(certPem: string, now = new Date()): number {
    return (new X509Certificate(firstPem(certPem)).validToDate.getTime() - now.getTime()) / 86_400_000;
}
