import { JwtService } from '@nestjs/jwt';
import { Strategy } from 'passport-jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JWT_ALGORITHM, JWT_AUDIENCE, JWT_ISSUER } from './jwt.constants';

const SECRET = 'x'.repeat(48);
const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');

describe('JWT pinning (step 2)', () => {
    const signer = new JwtService({
        secret: SECRET,
        signOptions: { algorithm: JWT_ALGORITHM, issuer: JWT_ISSUER, audience: JWT_AUDIENCE, expiresIn: '15m' },
    });
    // Same options as JwtStrategy, verified with the real passport-jwt/jsonwebtoken stack.
    const verify = (token: string): Promise<boolean> =>
        new Promise((resolve) => {
            const strategy = new (JwtStrategy as any)(
                { getOrThrow: () => SECRET },
                { user: { findUnique: async () => ({ status: 'ACTIVE' }) } },
            ) as Strategy & { success: unknown; fail: unknown; error: unknown; authenticate: (r: any) => void };
            strategy.success = () => resolve(true);
            strategy.fail = () => resolve(false);
            strategy.error = () => resolve(false);
            strategy.authenticate({ headers: { authorization: `Bearer ${token}` } });
        });

    it('accepte un token émis par le service', async () => {
        expect(await verify(signer.sign({ sub: 'u1', email: 'a@b.c', permissions: [] }))).toBe(true);
    });

    it('refuse un token sans issuer/audience attendus (même secret)', async () => {
        const other = new JwtService({ secret: SECRET, signOptions: { expiresIn: '15m' } });
        expect(await verify(other.sign({ sub: 'u1' }))).toBe(false);
        const wrongAud = new JwtService({
            secret: SECRET,
            signOptions: { issuer: JWT_ISSUER, audience: 'autre', expiresIn: '15m' },
        });
        expect(await verify(wrongAud.sign({ sub: 'u1' }))).toBe(false);
    });

    it('refuse un autre algorithme HMAC (HS512)', async () => {
        const hs512 = new JwtService({
            secret: SECRET,
            signOptions: { algorithm: 'HS512', issuer: JWT_ISSUER, audience: JWT_AUDIENCE, expiresIn: '15m' },
        });
        expect(await verify(hs512.sign({ sub: 'u1' }))).toBe(false);
    });

    it('refuse un token forgé alg=none', async () => {
        const forged = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'u1', iss: JWT_ISSUER, aud: JWT_AUDIENCE, exp: 9999999999 })}.`;
        expect(await verify(forged)).toBe(false);
    });
});
