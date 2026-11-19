import { UnauthorizedException } from '@nestjs/common';
import { StepUpGuard } from './step-up.guard';

describe('StepUpGuard', () => {
    const verifyStepUpTotp = jest.fn();
    const passkeysEnforcedFor = jest.fn();
    const consumeStepUpToken = jest.fn();
    // `moduleRef.get(Class)` hands back one fake exposing what AuthService and PasskeysService provide.
    const moduleRef = { get: jest.fn(() => ({ verifyStepUpTotp, passkeysEnforcedFor, consumeStepUpToken })) } as any;
    const make = (stepUpRequired: unknown = true) =>
        new StepUpGuard(moduleRef, {
            get: (_k: string, d: unknown) => (stepUpRequired === undefined ? d : stepUpRequired),
        } as any);
    const ctx = (user: unknown, headers: Record<string, unknown> = {}) =>
        ({
            switchToHttp: () => ({ getRequest: () => ({ user, headers, ip: '203.0.113.9' }) }),
        }) as any;

    beforeEach(() => {
        verifyStepUpTotp.mockReset();
        consumeStepUpToken.mockReset();
        passkeysEnforcedFor.mockReset().mockResolvedValue(false); // default: account without passkey
    });

    it('laisse passer quand le code TOTP est valide, et le vérifie pour le bon utilisateur', async () => {
        verifyStepUpTotp.mockResolvedValue(undefined);
        await expect(make().canActivate(ctx({ userId: 'u1' }, { 'x-totp-code': '123 456' }))).resolves.toBe(true);
        expect(verifyStepUpTotp).toHaveBeenCalledWith(
            'u1',
            '123456',
            expect.objectContaining({ ipAddress: '203.0.113.9' }),
        );
    });

    it("refuse (401 StepUpRequired) quand l'en-tête est absent, sans interroger le service", async () => {
        const promise = make().canActivate(ctx({ userId: 'u1' }));
        await expect(promise).rejects.toThrow(UnauthorizedException);
        await expect(promise).rejects.toMatchObject({ response: expect.objectContaining({ error: 'StepUpRequired' }) });
        expect(verifyStepUpTotp).not.toHaveBeenCalled();
    });

    it.each(['abc123', '12345', '123456789', ''])('refuse un code mal formé: %p', async (bad) => {
        await expect(make().canActivate(ctx({ userId: 'u1' }, { 'x-totp-code': bad }))).rejects.toThrow(
            UnauthorizedException,
        );
        expect(verifyStepUpTotp).not.toHaveBeenCalled();
    });

    it('refuse un en-tête répété (tableau)', async () => {
        await expect(
            make().canActivate(ctx({ userId: 'u1' }, { 'x-totp-code': ['123456', '654321'] })),
        ).rejects.toThrow(UnauthorizedException);
    });

    it('refuse sans utilisateur authentifié', async () => {
        await expect(make().canActivate(ctx(undefined, { 'x-totp-code': '123456' }))).rejects.toThrow(
            UnauthorizedException,
        );
    });

    it('propage le refus du service (mauvais code / rejeu / compte verrouillé)', async () => {
        verifyStepUpTotp.mockRejectedValue(new UnauthorizedException('Re-authentication failed.'));
        await expect(make().canActivate(ctx({ userId: 'u1' }, { 'x-totp-code': '123456' }))).rejects.toThrow(
            'Re-authentication failed.',
        );
    });

    it('STEP_UP_REQUIRED=false désactive la vérification (interrupteur de déploiement)', async () => {
        await expect(make(false).canActivate(ctx({ userId: 'u1' }))).resolves.toBe(true);
        expect(verifyStepUpTotp).not.toHaveBeenCalled();
    });
    describe('passkeys (step 3)', () => {
        const token = 'A'.repeat(43);

        it('accepte un jeton de step-up passkey valide (et ne touche pas au TOTP)', async () => {
            consumeStepUpToken.mockResolvedValue(true);
            await expect(make().canActivate(ctx({ userId: 'u1' }, { 'x-step-up-token': token }))).resolves.toBe(true);
            expect(consumeStepUpToken).toHaveBeenCalledWith('u1', token);
            expect(verifyStepUpTotp).not.toHaveBeenCalled();
        });

        it('refuse un jeton invalide/expiré/déjà utilisé, sans retomber sur le TOTP', async () => {
            consumeStepUpToken.mockResolvedValue(false);
            const promise = make().canActivate(
                ctx({ userId: 'u1' }, { 'x-step-up-token': token, 'x-totp-code': '123456' }),
            );
            await expect(promise).rejects.toMatchObject({
                response: expect.objectContaining({ error: 'StepUpPasskeyRequired' }),
            });
            expect(verifyStepUpTotp).not.toHaveBeenCalled();
        });

        it("compte avec passkey : le code TOTP n'est PLUS accepté (pas de retour en arrière)", async () => {
            passkeysEnforcedFor.mockResolvedValue(true);
            const promise = make().canActivate(ctx({ userId: 'u1' }, { 'x-totp-code': '123456' }));
            await expect(promise).rejects.toMatchObject({
                response: expect.objectContaining({ error: 'StepUpPasskeyRequired' }),
            });
            expect(verifyStepUpTotp).not.toHaveBeenCalled();
        });

        it('session de récupération : laissée passer (elle ne peut atteindre que les routes @AllowRecoveryScope)', async () => {
            await expect(make().canActivate(ctx({ userId: 'u1', scope: 'recovery' }))).resolves.toBe(true);
            expect(verifyStepUpTotp).not.toHaveBeenCalled();
        });
    });
});
