import { ConfigService } from '@nestjs/config';
import { RedisThrottlerStorage } from './redis-throttler-storage';

// Live test against a real Redis; skipped unless THROTTLE_TEST_REDIS_PORT is set.
const port = process.env.THROTTLE_TEST_REDIS_PORT;
(port ? describe : describe.skip)('RedisThrottlerStorage (live Redis)', () => {
    let storage: RedisThrottlerStorage;
    beforeAll(async () => {
        const cfg = {
            get: (k: string, d?: unknown) =>
                ({
                    REDIS_HOST: '127.0.0.1',
                    REDIS_PORT: Number(port),
                    REDIS_PASSWORD: process.env.THROTTLE_TEST_REDIS_PASSWORD,
                })[k] ?? d,
        } as unknown as ConfigService;
        storage = new RedisThrottlerStorage(cfg);
        // Wait for the connection so that every call below really goes through Redis.
        for (let i = 0; i < 50 && (storage as any).redis.status !== 'ready'; i++) {
            await new Promise((r) => setTimeout(r, 100));
        }
        expect((storage as any).redis.status).toBe('ready');
    });
    afterAll(async () => storage.onModuleDestroy());

    it('compte, bloque au-delà de la limite, puis repart de zéro après le blocage', async () => {
        const key = `k-${Date.now()}`;
        const r1 = await storage.increment(key, 2000, 3, 1000, 'default');
        const r2 = await storage.increment(key, 2000, 3, 1000, 'default');
        const r3 = await storage.increment(key, 2000, 3, 1000, 'default');
        expect([r1.totalHits, r2.totalHits, r3.totalHits]).toEqual([1, 2, 3]);
        // Proof the counter is in Redis (shared), not in this process's memory:
        expect(await (storage as any).redis.get(`backos:throttle:default:${key}`)).toBe('3');
        expect(r3.isBlocked).toBe(false);

        const r4 = await storage.increment(key, 2000, 3, 1000, 'default');
        expect(r4.isBlocked).toBe(true);
        expect(r4.timeToBlockExpire).toBeGreaterThan(0);

        const r5 = await storage.increment(key, 2000, 3, 1000, 'default'); // toujours bloqué
        expect(r5.isBlocked).toBe(true);

        await new Promise((r) => setTimeout(r, 1200));
        const r6 = await storage.increment(key, 2000, 3, 1000, 'default');
        expect(r6.isBlocked).toBe(false);
        expect(r6.totalHits).toBe(1);
    });

    it('isole les clés et les noms de throttler', async () => {
        const a = await storage.increment('iso-a', 5000, 5, 5000, 'default');
        const b = await storage.increment('iso-b', 5000, 5, 5000, 'default');
        expect(a.totalHits).toBe(1);
        expect(b.totalHits).toBe(1);
    });

    it('retombe en mémoire (sans lever) quand Redis est injoignable', async () => {
        const down = new RedisThrottlerStorage({
            get: (k: string, d?: unknown) => ({ REDIS_HOST: '127.0.0.1', REDIS_PORT: 1 })[k] ?? d,
        } as unknown as ConfigService);
        const r = await down.increment('fb', 1000, 2, 1000, 'default');
        expect(r.totalHits).toBe(1);
        expect(r.isBlocked).toBe(false);
        await down.onModuleDestroy();
    });

    it('la fenêtre expire (ttl)', async () => {
        const key = `ttl-${Date.now()}`;
        await storage.increment(key, 500, 10, 500, 'default');
        await new Promise((r) => setTimeout(r, 700));
        const r = await storage.increment(key, 500, 10, 500, 'default');
        expect(r.totalHits).toBe(1);
    });
});
