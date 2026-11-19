import {
    BadRequestException,
    ForbiddenException,
    ServiceUnavailableException,
    UnauthorizedException,
} from '@nestjs/common';
import { PasskeyChallengeStore, PasskeyRedisLike } from './passkey-challenge.store';
import { PasskeysService } from './passkeys.service';
import { SoftwareAuthenticator } from './testing/software-authenticator';

/**
 * End-to-end tests of the passkey policy against the REAL @simplewebauthn/server library and a
 * software authenticator that signs with genuine P-256 keys. Only the infrastructure is faked
 * (an in-memory Prisma subset and an in-memory Redis subset).
 */
const RP_ID = 'localhost';
const ORIGIN = 'http://localhost:3000';
const handle = (userId: string) => Buffer.from(userId).toString('base64url');

class FakeRedis implements PasskeyRedisLike {
    data = new Map<string, string>();
    async set(key: string, value: string) {
        this.data.set(key, value);
    }
    async getdel(key: string) {
        const v = this.data.get(key) ?? null;
        this.data.delete(key);
        return v;
    }
    async quit() {}
}

function matches(row: any, where: any): boolean {
    return Object.entries(where ?? {}).every(([k, v]: [string, any]) => {
        if (v === null) return row[k] === null;
        if (typeof v === 'object' && v !== null && 'lt' in v) return row[k] < v.lt;
        return row[k] === v;
    });
}

function makePrisma() {
    const users = new Map<string, any>();
    const rows: any[] = [];
    let seq = 0;
    const prisma = {
        users,
        rows,
        user: { findUnique: async ({ where }: any) => users.get(where.id) ?? null },
        userPasskey: {
            findMany: async ({ where }: any) => rows.filter((r) => matches(r, where)),
            findFirst: async ({ where }: any) => rows.find((r) => matches(r, where)) ?? null,
            findUnique: async ({ where, include }: any) => {
                const r = rows.find((x) => x.credentialId === where.credentialId);
                if (!r) return null;
                return include?.user ? { ...r, user: users.get(r.userId) } : r;
            },
            count: async ({ where }: any) => rows.filter((r) => matches(r, where)).length,
            create: async ({ data }: any) => {
                if (rows.some((r) => r.credentialId === data.credentialId))
                    throw Object.assign(new Error('dup'), { code: 'P2002' });
                const row = {
                    id: `pk-${++seq}`,
                    lastUsedAt: null,
                    revokedAt: null,
                    revokedReason: null,
                    createdAt: new Date(),
                    ...data,
                };
                rows.push(row);
                return row;
            },
            update: async ({ where, data }: any) =>
                Object.assign(
                    rows.find((r) => r.id === where.id),
                    data,
                ),
            updateMany: async ({ where, data }: any) => {
                const hit = rows.filter((r) => matches(r, where));
                hit.forEach((r) => Object.assign(r, data));
                return { count: hit.length };
            },
        },
    };
    return prisma;
}

describe('PasskeysService (real WebAuthn verification)', () => {
    let prisma: ReturnType<typeof makePrisma>;
    let redis: FakeRedis;
    let authService: any;
    let roleHierarchy: any;
    let auditLog: any;
    let config: Record<string, unknown>;
    let service: PasskeysService;
    const ctx = { ipAddress: '203.0.113.5', userAgent: 'jest' };

    const build = () => {
        service = new PasskeysService(
            prisma as any,
            { get: (k: string, d?: unknown) => (k in config ? config[k] : d) } as any,
            new PasskeyChallengeStore(redis),
            authService,
            roleHierarchy,
            auditLog,
        );
    };

    beforeEach(() => {
        prisma = makePrisma();
        redis = new FakeRedis();
        authService = {
            completePasskeyLogin: jest.fn(async (id: string) => ({
                accessToken: `jwt-${id}`,
                refreshToken: 'refresh',
            })),
            revokeAllRefreshTokens: jest.fn().mockResolvedValue(1),
        };
        roleHierarchy = { assertSeniorToTarget: jest.fn().mockResolvedValue(undefined) };
        auditLog = { log: jest.fn() };
        config = {
            WEBAUTHN_RP_ID: RP_ID,
            WEBAUTHN_ORIGINS: ORIGIN,
            WEBAUTHN_RP_NAME: 'Test',
            PASSKEY_MAX_PER_USER: 10,
        };
        prisma.users.set('user-1', {
            id: 'user-1',
            workEmail: 'a@x.io',
            firstName: 'A',
            lastName: 'B',
            status: 'ACTIVE',
        });
        prisma.users.set('user-2', {
            id: 'user-2',
            workEmail: 'c@x.io',
            firstName: 'C',
            lastName: 'D',
            status: 'ACTIVE',
        });
        build();
    });

    const authenticator = (o: Partial<ConstructorParameters<typeof SoftwareAuthenticator>[0]> = {}) =>
        new SoftwareAuthenticator({ rpId: RP_ID, origin: ORIGIN, ...o });

    async function enroll(userId: string, auth: SoftwareAuthenticator, name = 'Key') {
        const { challengeId, options } = await service.startRegistration(userId);
        const response = auth.register(options);
        return service.finishRegistration(userId, { challengeId, response: response, name }, ctx);
    }

    async function login(auth: SoftwareAuthenticator, userId: string, extra: Record<string, unknown> = {}) {
        const { challengeId, options } = await service.startLogin();
        const response = auth.assert(options, { userHandle: handle(userId), ...extra });
        return service.finishLogin({ challengeId, response: response }, ctx);
    }

    // ---------------------------------------------------------------------------------------------
    describe('configuration', () => {
        it('désactivé tant que WEBAUTHN_RP_ID / WEBAUTHN_ORIGINS ne sont pas définis', async () => {
            config = {};
            build();
            await expect(service.startLogin()).rejects.toThrow(ServiceUnavailableException);
            await expect(service.startRegistration('user-1')).rejects.toThrow(ServiceUnavailableException);
        });
    });

    // ---------------------------------------------------------------------------------------------
    describe('enregistrement', () => {
        it('impose clé résidente + vérification utilisateur, et lie le userID au compte', async () => {
            const { options } = await service.startRegistration('user-1');
            expect(options.rp.id).toBe(RP_ID);
            expect(options.authenticatorSelection).toMatchObject({
                residentKey: 'required',
                userVerification: 'required',
            });
            expect(options.attestation).toBe('none');
            expect(options.user.id).toBe(handle('user-1'));
            expect(options.excludeCredentials ?? []).toHaveLength(0);
        });

        it('enregistre une passkey valide (clé publique seule) et journalise', async () => {
            const auth = authenticator();
            const created = await enroll('user-1', auth, 'YubiKey bureau');
            expect(created).toMatchObject({ name: 'YubiKey bureau', deviceType: 'singleDevice', backedUp: false });
            expect(prisma.rows).toHaveLength(1);
            expect(prisma.rows[0].credentialId).toBe(auth.id);
            expect(Buffer.isBuffer(prisma.rows[0].publicKey)).toBe(true);
            expect(auditLog.log).toHaveBeenCalledWith(
                expect.objectContaining({ action: 'auth.passkey.registered', actorId: 'user-1' }),
            );
        });

        it('exclut les passkeys déjà enregistrées (pas deux fois le même authentificateur)', async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            const { options } = await service.startRegistration('user-1');
            expect(options.excludeCredentials?.map((c) => c.id)).toEqual([auth.id]);
        });

        it("un défi ne sert qu'une fois (rejeu refusé)", async () => {
            const auth = authenticator();
            const { challengeId, options } = await service.startRegistration('user-1');
            const response = auth.register(options);
            await service.finishRegistration('user-1', { challengeId, response: response, name: 'k' }, ctx);
            await expect(
                service.finishRegistration('user-1', { challengeId, response: response as any, name: 'k' }, ctx),
            ).rejects.toThrow(BadRequestException);
        });

        it('un défi échoué est quand même consommé (pas de nouvel essai sur le même défi)', async () => {
            const { challengeId, options } = await service.startRegistration('user-1');
            const bad = authenticator().register(options, { origin: 'https://evil.example' });
            await expect(
                service.finishRegistration('user-1', { challengeId, response: bad as any, name: 'k' }, ctx),
            ).rejects.toThrow(BadRequestException);
            const good = authenticator().register(options);
            await expect(
                service.finishRegistration('user-1', { challengeId, response: good as any, name: 'k' }, ctx),
            ).rejects.toThrow(BadRequestException);
        });

        it('refuse une origine non autorisée (phishing / mauvais site)', async () => {
            const { challengeId, options } = await service.startRegistration('user-1');
            const response = authenticator().register(options, { origin: 'http://localhost:4000' });
            await expect(
                service.finishRegistration('user-1', { challengeId, response: response as any, name: 'k' }, ctx),
            ).rejects.toThrow(BadRequestException);
            expect(prisma.rows).toHaveLength(0);
        });

        it('refuse un défi émis pour un AUTRE utilisateur', async () => {
            const { challengeId, options } = await service.startRegistration('user-1');
            const response = authenticator().register(options);
            await expect(
                service.finishRegistration('user-2', { challengeId, response: response as any, name: 'k' }, ctx),
            ).rejects.toThrow(BadRequestException);
        });

        it('refuse un authentificateur qui ne fait pas de vérification utilisateur (UV)', async () => {
            const { challengeId, options } = await service.startRegistration('user-1');
            const response = authenticator({ userVerified: false }).register(options);
            await expect(
                service.finishRegistration('user-1', { challengeId, response: response as any, name: 'k' }, ctx),
            ).rejects.toThrow(BadRequestException);
        });

        it('PASSKEY_REQUIRE_DEVICE_BOUND refuse les passkeys synchronisées', async () => {
            config.PASSKEY_REQUIRE_DEVICE_BOUND = true;
            build();
            await expect(enroll('user-1', authenticator({ synced: true }))).rejects.toThrow(/hardware-bound/);
            await expect(enroll('user-1', authenticator())).resolves.toBeDefined();
        });

        it('limite le nombre de passkeys par compte', async () => {
            config.PASSKEY_MAX_PER_USER = 2;
            build();
            await enroll('user-1', authenticator());
            await enroll('user-1', authenticator());
            await expect(service.startRegistration('user-1')).rejects.toThrow(BadRequestException);
        });

        it('nettoie le nom (caractères de contrôle, longueur)', async () => {
            const created = await enroll('user-1', authenticator(), '  Ma\u0000 clé\n' + 'x'.repeat(100));
            // eslint-disable-next-line no-control-regex
            expect(created.name).not.toMatch(/[\u0000-\u001f]/);
            expect(created.name.length).toBeLessThanOrEqual(64);
        });
    });

    // ---------------------------------------------------------------------------------------------
    describe('connexion sans identifiant', () => {
        it("connecte le propriétaire de la passkey et délègue l'émission des jetons", async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            const tokens = await login(auth, 'user-1');
            expect(tokens).toEqual({ accessToken: 'jwt-user-1', refreshToken: 'refresh' });
            expect(authService.completePasskeyLogin).toHaveBeenCalledWith('user-1', ctx);
        });

        it('demande toujours la vérification utilisateur et ne révèle aucun identifiant', async () => {
            const { options } = await service.startLogin();
            expect(options.userVerification).toBe('required');
            expect(options.rpId).toBe(RP_ID);
            expect(options.allowCredentials ?? []).toHaveLength(0);
        });

        it("un défi de connexion ne sert qu'une fois", async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            const { challengeId, options } = await service.startLogin();
            const response = auth.assert(options, { userHandle: handle('user-1') });
            await service.finishLogin({ challengeId, response: response }, ctx);
            await expect(service.finishLogin({ challengeId, response: response as any }, ctx)).rejects.toThrow(
                UnauthorizedException,
            );
        });

        it('refuse un identifiant de défi inconnu ou mal formé', async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            const { options } = await service.startLogin();
            const response = auth.assert(options, { userHandle: handle('user-1') });
            for (const challengeId of ['0'.repeat(64), 'not-hex', '']) {
                await expect(service.finishLogin({ challengeId, response: response as any }, ctx)).rejects.toThrow(
                    UnauthorizedException,
                );
            }
        });

        it('refuse une passkey inconnue', async () => {
            const stranger = authenticator();
            const { challengeId, options } = await service.startLogin();
            const response = stranger.assert(options, { userHandle: handle('user-1') });
            await expect(service.finishLogin({ challengeId, response: response as any }, ctx)).rejects.toThrow(
                'Invalid credentials.',
            );
            expect(auditLog.log).toHaveBeenCalledWith(expect.objectContaining({ action: 'auth.passkey.login.failed' }));
        });

        it('refuse une signature falsifiée', async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            const { challengeId, options } = await service.startLogin();
            const response = auth.assert(options, { userHandle: handle('user-1'), tamperSignature: true });
            await expect(service.finishLogin({ challengeId, response: response as any }, ctx)).rejects.toThrow(
                UnauthorizedException,
            );
            expect(authService.completePasskeyLogin).not.toHaveBeenCalled();
        });

        it('refuse une origine non autorisée', async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            const { challengeId, options } = await service.startLogin();
            const response = auth.assert(options, { userHandle: handle('user-1'), origin: 'https://evil.example' });
            await expect(service.finishLogin({ challengeId, response: response as any }, ctx)).rejects.toThrow(
                UnauthorizedException,
            );
        });

        it("refuse un user handle qui n'est pas celui du propriétaire de la passkey", async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            await expect(login(auth, 'user-2')).rejects.toThrow(UnauthorizedException);
            expect(authService.completePasskeyLogin).not.toHaveBeenCalled();
        });

        it('refuse une passkey révoquée', async () => {
            const a = authenticator();
            await enroll('user-1', a);
            await enroll('user-1', authenticator());
            const id = (await service.list('user-1')).passkeys[0].id;
            await service.revoke('user-1', id, ctx);
            await expect(login(a, 'user-1')).rejects.toThrow(UnauthorizedException);
        });

        it('refuse un compte non actif', async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            prisma.users.get('user-1').status = 'DISABLED';
            await expect(login(auth, 'user-1')).rejects.toThrow(UnauthorizedException);
        });

        it("fait avancer le compteur et mémorise l'usage", async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            await login(auth, 'user-1');
            await login(auth, 'user-1');
            expect(prisma.rows[0].counter).toBe(2n);
            expect(prisma.rows[0].lastUsedAt).toBeInstanceOf(Date);
        });

        it('accepte les authentificateurs à compteur 0 (passkeys synchronisées)', async () => {
            const auth = authenticator({ synced: true, counterMode: 'zero' });
            await enroll('user-1', auth);
            await expect(login(auth, 'user-1')).resolves.toBeDefined();
            await expect(login(auth, 'user-1')).resolves.toBeDefined();
            expect(prisma.rows[0].revokedAt).toBeNull();
        });

        it('CLONAGE : un compteur qui recule révoque la passkey, coupe les sessions et alerte', async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            await login(auth, 'user-1');
            await login(auth, 'user-1'); // compteur = 2
            authService.completePasskeyLogin.mockClear();

            await expect(login(auth, 'user-1', { counterOverride: 1 })).rejects.toThrow(UnauthorizedException);

            expect(prisma.rows[0].revokedAt).toBeInstanceOf(Date);
            expect(prisma.rows[0].revokedReason).toBe('clone-suspected');
            expect(authService.revokeAllRefreshTokens).toHaveBeenCalledWith('user-1');
            expect(authService.completePasskeyLogin).not.toHaveBeenCalled();
            expect(auditLog.log).toHaveBeenCalledWith(
                expect.objectContaining({ action: 'auth.passkey.clone-suspected' }),
            );
            await expect(login(auth, 'user-1')).rejects.toThrow(UnauthorizedException); // et elle ne marche plus
        });
    });

    // ---------------------------------------------------------------------------------------------
    describe('step-up par passkey', () => {
        async function stepUp(userId: string, auth: SoftwareAuthenticator) {
            const { challengeId, options } = await service.startStepUp(userId);
            const response = auth.assert(options, { userHandle: handle(userId) });
            return service.finishStepUp(userId, { challengeId, response: response }, ctx);
        }

        it("échange une assertion valide contre un jeton à usage unique lié à l'utilisateur", async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            const { stepUpToken, expiresInSeconds } = await stepUp('user-1', auth);
            expect(stepUpToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
            expect(expiresInSeconds).toBe(60);
            expect(await service.consumeStepUpToken('user-2', stepUpToken)).toBe(false); // autre utilisateur
        });

        it("le jeton ne sert qu'une fois", async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            const { stepUpToken } = await stepUp('user-1', auth);
            expect(await service.consumeStepUpToken('user-1', stepUpToken)).toBe(true);
            expect(await service.consumeStepUpToken('user-1', stepUpToken)).toBe(false);
        });

        it('refuse les jetons mal formés', async () => {
            for (const t of ['', 'x', 'A'.repeat(42), 'A'.repeat(44), '!'.repeat(43)]) {
                expect(await service.consumeStepUpToken('user-1', t)).toBe(false);
            }
        });

        it('le step-up est impossible sans passkey', async () => {
            await expect(service.startStepUp('user-1')).rejects.toThrow(BadRequestException);
        });

        it("n'accepte pas la passkey d'un autre utilisateur", async () => {
            const mine = authenticator();
            const theirs = authenticator();
            await enroll('user-1', mine);
            await enroll('user-2', theirs);
            const { challengeId, options } = await service.startStepUp('user-1');
            const response = theirs.assert(options, { userHandle: handle('user-2') });
            await expect(
                service.finishStepUp('user-1', { challengeId, response: response as any }, ctx),
            ).rejects.toThrow('Re-authentication failed.');
        });

        it('un défi de CONNEXION ne peut pas servir de step-up (défis liés à leur usage)', async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            const { challengeId, options } = await service.startLogin();
            const response = auth.assert(options, { userHandle: handle('user-1') });
            await expect(
                service.finishStepUp('user-1', { challengeId, response: response as any }, ctx),
            ).rejects.toThrow(UnauthorizedException);
        });

        it("un défi de step-up d'un autre utilisateur est refusé", async () => {
            const auth = authenticator();
            await enroll('user-1', auth);
            await enroll('user-2', authenticator());
            const { challengeId, options } = await service.startStepUp('user-1');
            const response = auth.assert(options, { userHandle: handle('user-1') });
            await expect(
                service.finishStepUp('user-2', { challengeId, response: response as any }, ctx),
            ).rejects.toThrow(UnauthorizedException);
        });
    });

    // ---------------------------------------------------------------------------------------------
    describe('gestion', () => {
        it("liste uniquement les passkeys actives de l'utilisateur, sans données secrètes", async () => {
            await enroll('user-1', authenticator(), 'A');
            await enroll('user-2', authenticator(), 'B');
            const { passkeys, recommendedMinimumReached } = await service.list('user-1');
            expect(passkeys).toHaveLength(1);
            expect(recommendedMinimumReached).toBe(false);
            expect(JSON.stringify(passkeys)).not.toMatch(/publicKey|credentialId|counter/);
        });

        it('refuse de révoquer la DERNIÈRE passkey (ce serait un retour silencieux au TOTP)', async () => {
            await enroll('user-1', authenticator());
            const id = (await service.list('user-1')).passkeys[0].id;
            await expect(service.revoke('user-1', id, ctx)).rejects.toThrow(/last passkey/);
            expect(prisma.rows[0].revokedAt).toBeNull();
        });

        it('révoque une passkey quand il en reste une autre, et coupe toutes les sessions', async () => {
            await enroll('user-1', authenticator(), 'A');
            await enroll('user-1', authenticator(), 'B');
            const list = (await service.list('user-1')).passkeys;
            expect((await service.list('user-1')).recommendedMinimumReached).toBe(true);
            await service.revoke('user-1', list[0].id, ctx);
            expect((await service.list('user-1')).passkeys).toHaveLength(1);
            expect(authService.revokeAllRefreshTokens).toHaveBeenCalledWith('user-1');
            expect(auditLog.log).toHaveBeenCalledWith(expect.objectContaining({ action: 'auth.passkey.revoked' }));
        });

        it("ne révoque pas la passkey d'un autre utilisateur", async () => {
            await enroll('user-1', authenticator());
            await enroll('user-2', authenticator());
            const victim = prisma.rows.find((r) => r.userId === 'user-2')!;
            await expect(service.revoke('user-1', victim.id, ctx)).rejects.toThrow('Passkey not found.');
            expect(victim.revokedAt).toBeNull();
        });

        it('réinitialisation par un administrateur : hiérarchie vérifiée, tout est révoqué, sessions coupées', async () => {
            await enroll('user-2', authenticator());
            await enroll('user-2', authenticator());
            const result = await service.adminResetAll('user-1', 'user-2', ctx);
            expect(result).toEqual({ revoked: 2 });
            expect(roleHierarchy.assertSeniorToTarget).toHaveBeenCalledWith('user-1', 'user-2', expect.any(String));
            expect(authService.revokeAllRefreshTokens).toHaveBeenCalledWith('user-2');
            expect(auditLog.log).toHaveBeenCalledWith(
                expect.objectContaining({ action: 'auth.passkey.reset-by-admin' }),
            );
        });

        it("la réinitialisation est refusée si l'administrateur n'est pas hiérarchiquement supérieur", async () => {
            roleHierarchy.assertSeniorToTarget.mockRejectedValue(new ForbiddenException('not senior'));
            await enroll('user-2', authenticator());
            await expect(service.adminResetAll('user-1', 'user-2', ctx)).rejects.toThrow(ForbiddenException);
            expect(prisma.rows[0].revokedAt).toBeNull();
        });

        it('on ne se réinitialise pas soi-même par la route administrateur', async () => {
            await expect(service.adminResetAll('user-1', 'user-1', ctx)).rejects.toThrow(ForbiddenException);
        });
    });
});
