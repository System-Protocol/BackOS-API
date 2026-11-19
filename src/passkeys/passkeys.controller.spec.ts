import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { ThrottlerModule } from '@nestjs/throttler';
import request from 'supertest';
import { AuthService } from '../auth/auth.service';
import { PasskeysController } from './passkeys.controller';
import { PasskeysService } from './passkeys.service';

/** HTTP layer only: routing, input validation, and that step-up protects registration. */
describe('PasskeysController (HTTP)', () => {
    let app: INestApplication;
    const passkeys = {
        startLogin: jest.fn().mockResolvedValue({ challengeId: 'c', options: {} }),
        finishLogin: jest.fn().mockResolvedValue({ accessToken: 'a', refreshToken: 'r' }),
        startRegistration: jest.fn(),
        finishRegistration: jest.fn().mockResolvedValue({ id: 'p1' }),
    };
    const authService = { passkeysEnforcedFor: jest.fn().mockResolvedValue(false), verifyStepUpTotp: jest.fn() };
    const CID = 'a'.repeat(64);

    beforeAll(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [
                ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }),
                ThrottlerModule.forRoot([{ ttl: 60_000, limit: 1000 }]),
            ],
            controllers: [PasskeysController],
            providers: [
                { provide: PasskeysService, useValue: passkeys },
                { provide: AuthService, useValue: authService },
            ],
        }).compile();
        app = moduleRef.createNestApplication();
        // Same pipe as production (see app.setup.ts).
        app.useGlobalPipes(
            new ValidationPipe({
                whitelist: true,
                forbidNonWhitelisted: true,
                transform: true,
                transformOptions: { enableImplicitConversion: true },
            }),
        );
        await app.init();
    });
    afterAll(async () => app.close());
    beforeEach(() => jest.clearAllMocks());

    it('POST login/options : 200 sans corps', async () => {
        await request(app.getHttpServer()).post('/auth/passkeys/login/options').expect(200);
        expect(passkeys.startLogin).toHaveBeenCalledTimes(1);
    });

    it.each([
        ['challengeId absent', { response: {} }],
        ['challengeId mal formé', { challengeId: 'nope', response: {} }],
        ['response absente', { challengeId: CID }],
        ['response de mauvais type', { challengeId: CID, response: 'x' }],
        ['champ inconnu (forbidNonWhitelisted)', { challengeId: CID, response: {}, isAdmin: true }],
    ])('POST login/verify : 400 si %s', async (_label, body) => {
        await request(app.getHttpServer()).post('/auth/passkeys/login/verify').send(body).expect(400);
        expect(passkeys.finishLogin).not.toHaveBeenCalled();
    });

    it('POST login/verify : transmet un corps valide au service', async () => {
        const body = { challengeId: CID, response: { id: 'x', response: {} } };
        const res = await request(app.getHttpServer()).post('/auth/passkeys/login/verify').send(body).expect(200);
        expect(res.body).toEqual({ accessToken: 'a', refreshToken: 'r' });
        expect(passkeys.finishLogin).toHaveBeenCalledWith(body, expect.any(Object));
    });

    it("POST register/options : refusé (401) sans utilisateur authentifié - le step-up s'applique", async () => {
        await request(app.getHttpServer()).post('/auth/passkeys/register/options').expect(401);
        expect(passkeys.startRegistration).not.toHaveBeenCalled();
    });

    it('POST register/verify : le nom est obligatoire et limité à 64 caractères', async () => {
        const base = { challengeId: CID, response: {} };
        await request(app.getHttpServer())
            .post('/auth/passkeys/register/verify')
            .send({ ...base })
            .expect(400);
        await request(app.getHttpServer())
            .post('/auth/passkeys/register/verify')
            .send({ ...base, name: 'x'.repeat(65) })
            .expect(400);
        await request(app.getHttpServer())
            .post('/auth/passkeys/register/verify')
            .send({ ...base, name: '   ' })
            .expect(400);
    });
});
