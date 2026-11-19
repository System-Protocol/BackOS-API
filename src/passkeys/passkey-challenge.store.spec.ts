import { ServiceUnavailableException } from '@nestjs/common';
import Redis from 'ioredis';
import { PasskeyChallengeStore, PasskeyRedisLike } from './passkey-challenge.store';

class MemRedis implements PasskeyRedisLike {
    d = new Map<string, { v: string; ttl: number }>();
    async set(k: string, v: string, _m: 'EX', ttl: number) {
        this.d.set(k, { v, ttl });
    }
    async getdel(k: string) {
        const e = this.d.get(k);
        this.d.delete(k);
        return e?.v ?? null;
    }
    async quit() {}
}

describe('PasskeyChallengeStore', () => {
    it('stocke avec un TTL et un identifiant aléatoire de 256 bits', async () => {
        const redis = new MemRedis();
        const store = new PasskeyChallengeStore(redis);
        const id = await store.put('auth', { challenge: 'c' }, 300);
        expect(id).toMatch(/^[a-f0-9]{64}$/);
        expect([...redis.d.values()][0].ttl).toBe(300);
        expect(await store.put('auth', {}, 300)).not.toBe(id);
    });

    it('lit une seule fois', async () => {
        const store = new PasskeyChallengeStore(new MemRedis());
        const id = await store.put('reg', { challenge: 'c', userId: 'u' }, 300);
        expect(await store.take('reg', id)).toEqual({ challenge: 'c', userId: 'u' });
        expect(await store.take('reg', id)).toBeNull();
    });

    it("les usages sont cloisonnés : un défi 'auth' est introuvable comme 'stepup'", async () => {
        const store = new PasskeyChallengeStore(new MemRedis());
        const id = await store.put('auth', { challenge: 'c' }, 300);
        expect(await store.take('stepup', id)).toBeNull();
        expect(await store.take('auth', id)).not.toBeNull(); // et il n'a pas été consommé par l'erreur
    });

    it('ignore les identifiants mal formés sans interroger Redis', async () => {
        const redis = new MemRedis();
        const spy = jest.spyOn(redis, 'getdel');
        const store = new PasskeyChallengeStore(redis);
        for (const bad of ['', 'abc', 'Z'.repeat(64), '../..', 'a'.repeat(63)])
            expect(await store.take('auth', bad)).toBeNull();
        expect(spy).not.toHaveBeenCalled();
    });

    it('échoue FERMÉ (503) quand Redis est indisponible', async () => {
        const broken: PasskeyRedisLike = {
            set: async () => {
                throw new Error('down');
            },
            getdel: async () => {
                throw new Error('down');
            },
            quit: async () => undefined,
        };
        const store = new PasskeyChallengeStore(broken);
        await expect(store.put('auth', {}, 300)).rejects.toThrow(ServiceUnavailableException);
        await expect(store.take('auth', 'a'.repeat(64))).rejects.toThrow(ServiceUnavailableException);
    });

    it('un contenu corrompu est traité comme absent', async () => {
        const redis = new MemRedis();
        redis.d.set('backos:webauthn:auth:' + 'a'.repeat(64), { v: '{not json', ttl: 1 });
        expect(await new PasskeyChallengeStore(redis).take('auth', 'a'.repeat(64))).toBeNull();
    });
});

// Live Redis: GETDEL must make "use once" hold even under concurrency. Skipped without a server.
const port = process.env.THROTTLE_TEST_REDIS_PORT;
(port ? describe : describe.skip)('PasskeyChallengeStore (live Redis)', () => {
    it('20 lectures simultanées du même défi : exactement UNE réussit', async () => {
        const redis = new Redis({
            host: '127.0.0.1',
            port: Number(port),
            password: process.env.THROTTLE_TEST_REDIS_PASSWORD,
        });
        const store = new PasskeyChallengeStore(redis);
        const id = await store.put('reg', { challenge: 'c', userId: 'u' }, 30);
        const results = await Promise.all(Array.from({ length: 20 }, () => store.take('reg', id)));
        expect(results.filter((r) => r !== null)).toHaveLength(1);
        await store.onModuleDestroy();
    });
});
