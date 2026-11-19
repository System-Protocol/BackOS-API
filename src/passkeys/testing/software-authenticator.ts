import { createHash, generateKeyPairSync, KeyObject, randomBytes, sign } from 'crypto';

/**
 * TEST HELPER - a software WebAuthn authenticator (ES256, "none" attestation).
 *
 * It produces REAL registration/assertion payloads: genuine P-256 keys, genuine signatures, CBOR and
 * authenticator-data laid out as in the spec. The production code is then verified by the real
 * @simplewebauthn/server library - nothing about the cryptography is mocked in the tests.
 */
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;

const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString('base64url');
const sha256 = (b: Uint8Array | Buffer | string) => createHash('sha256').update(b).digest();

// ---- minimal CBOR encoder (ints, byte strings, text strings, maps) ------------------------------
function head(major: number, n: number): Buffer {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
}
function cbor(v: unknown): Buffer {
    if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
    if (typeof v === 'string') {
        const b = Buffer.from(v, 'utf8');
        return Buffer.concat([head(3, b.length), b]);
    }
    if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
    if (v instanceof Map) {
        return Buffer.concat([head(5, v.size), ...[...v.entries()].flatMap(([k, val]) => [cbor(k), cbor(val)])]);
    }
    throw new Error('unsupported CBOR value');
}

export interface SoftwareAuthenticatorOptions {
    rpId: string;
    origin: string;
    /** Report user verification (PIN / biometric). Default true. */
    userVerified?: boolean;
    /** Synced passkey (BE/BS flags) instead of a hardware-bound credential. Default false. */
    synced?: boolean;
    /** 'increment' = hardware key behaviour; 'zero' = most synced passkeys. Default 'increment'. */
    counterMode?: 'increment' | 'zero';
}

export class SoftwareAuthenticator {
    readonly credentialId = randomBytes(32);
    counter = 0;
    private readonly privateKey: KeyObject;
    private readonly publicJwk: { x: string; y: string };

    constructor(public readonly opts: SoftwareAuthenticatorOptions) {
        const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        this.privateKey = privateKey;
        this.publicJwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
    }

    get id(): string {
        return b64u(this.credentialId);
    }

    private flags(extra = 0): number {
        let f = FLAG_UP | extra;
        if (this.opts.userVerified !== false) f |= FLAG_UV;
        if (this.opts.synced) f |= FLAG_BE | FLAG_BS;
        return f;
    }

    private counterBytes(): Buffer {
        const b = Buffer.alloc(4);
        b.writeUInt32BE(this.counter);
        return b;
    }

    /** Answers `navigator.credentials.create()` for the given creation options. */
    register(options: { challenge: string }, overrides: { origin?: string } = {}) {
        if (this.opts.counterMode !== 'zero') this.counter = 0;
        const clientDataJSON = Buffer.from(
            JSON.stringify({
                type: 'webauthn.create',
                challenge: options.challenge,
                origin: overrides.origin ?? this.opts.origin,
                crossOrigin: false,
            }),
        );
        const cose = cbor(
            new Map<number, unknown>([
                [1, 2],
                [3, -7],
                [-1, 1],
                [-2, Buffer.from(this.publicJwk.x, 'base64url')],
                [-3, Buffer.from(this.publicJwk.y, 'base64url')],
            ]),
        );
        const credIdLen = Buffer.alloc(2);
        credIdLen.writeUInt16BE(this.credentialId.length);
        const authData = Buffer.concat([
            sha256(this.opts.rpId),
            Buffer.from([this.flags(FLAG_AT)]),
            this.counterBytes(),
            Buffer.alloc(16), // AAGUID
            credIdLen,
            this.credentialId,
            cose,
        ]);
        const attestationObject = cbor(
            new Map<string, unknown>([
                ['fmt', 'none'],
                ['attStmt', new Map()],
                ['authData', authData],
            ]),
        );
        return {
            id: this.id,
            rawId: this.id,
            type: 'public-key' as const,
            response: {
                clientDataJSON: b64u(clientDataJSON),
                attestationObject: b64u(attestationObject),
                transports: ['internal'] as string[],
            },
            clientExtensionResults: {},
            authenticatorAttachment: 'platform' as const,
        };
    }

    /** Answers `navigator.credentials.get()`. `userHandle` is what the credential stores (the user id). */
    assert(
        options: { challenge: string },
        extra: { userHandle?: string; origin?: string; tamperSignature?: boolean; counterOverride?: number } = {},
    ) {
        if (extra.counterOverride !== undefined) this.counter = extra.counterOverride;
        else if (this.opts.counterMode !== 'zero') this.counter += 1;

        const clientDataJSON = Buffer.from(
            JSON.stringify({
                type: 'webauthn.get',
                challenge: options.challenge,
                origin: extra.origin ?? this.opts.origin,
                crossOrigin: false,
            }),
        );
        const authData = Buffer.concat([sha256(this.opts.rpId), Buffer.from([this.flags()]), this.counterBytes()]);
        const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.privateKey);
        if (extra.tamperSignature) signature[signature.length - 1] ^= 0xff;
        return {
            id: this.id,
            rawId: this.id,
            type: 'public-key' as const,
            response: {
                clientDataJSON: b64u(clientDataJSON),
                authenticatorData: b64u(authData),
                signature: b64u(signature),
                ...(extra.userHandle !== undefined ? { userHandle: extra.userHandle } : {}),
            },
            clientExtensionResults: {},
        };
    }
}
