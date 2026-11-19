import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ThrottlerStorage, ThrottlerStorageService } from '@nestjs/throttler';
import Redis from 'ioredis';

type ThrottlerStorageRecord = Awaited<ReturnType<ThrottlerStorage['increment']>>;

/**
 * Atomic fixed-window counter with a block period, mirroring the semantics of Nest's in-memory
 * `ThrottlerStorageService` (hits are not counted while a key is blocked; the counter restarts once
 * the block has expired).
 *
 * KEYS[1] = hit counter, KEYS[2] = block marker
 * ARGV[1] = ttl (ms), ARGV[2] = limit, ARGV[3] = block duration (ms)
 * Returns { totalHits, timeToExpireMs, isBlocked (0|1), timeToBlockExpireMs }
 */
export const THROTTLE_LUA = `
local blockTtl = redis.call('PTTL', KEYS[2])
if blockTtl > 0 then
  local ttl = redis.call('PTTL', KEYS[1])
  if ttl < 0 then ttl = 0 end
  return { tonumber(ARGV[2]) + 1, ttl, 1, blockTtl }
end
local hits = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if hits == 1 or ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
if hits > tonumber(ARGV[2]) then
  local blockMs = tonumber(ARGV[3])
  if blockMs <= 0 then blockMs = tonumber(ARGV[1]) end
  redis.call('SET', KEYS[2], '1', 'PX', blockMs)
  redis.call('DEL', KEYS[1])
  return { hits, ttl, 1, blockMs }
end
return { hits, ttl, 0, 0 }
`;

/**
 * SECURITY (step 2): shared, persistent storage for `ThrottlerGuard`.
 *
 * The default storage lives in the memory of one Node process, so (1) every restart or deploy resets
 * every attacker's counter, and (2) with N replicas the effective budget is N times the configured
 * one. Rate limits on /auth/login, recovery, MFA and invitations are a security control: they now live
 * in Redis (already required by BullMQ).
 *
 * Availability over strictness: if Redis is unreachable the storage degrades to the in-process one
 * (and logs it, at most once a minute) rather than turning a Redis outage into a full API outage.
 */
@Injectable()
export class RedisThrottlerStorage implements ThrottlerStorage, OnModuleDestroy {
    private readonly logger = new Logger('ThrottlerStorage');
    private readonly fallback = new ThrottlerStorageService();
    private readonly redis: Redis | null;
    private lastErrorLogAt = 0;

    constructor(configService: ConfigService) {
        const host = configService.get<string>('REDIS_HOST');
        if (!host) {
            this.redis = null;
            this.logger.warn('REDIS_HOST is not set: rate limiting falls back to in-memory (per-process) counters.');
            return;
        }

        const password = configService.get<string>('REDIS_PASSWORD') || undefined;
        const username = configService.get<string>('REDIS_USERNAME') || undefined;
        const tls = String(configService.get<string | boolean>('REDIS_TLS', false)) === 'true';

        this.redis = new Redis({
            host,
            port: Number(configService.get<number>('REDIS_PORT', 6379)),
            ...(password ? { password } : {}),
            ...(username ? { username } : {}),
            ...(tls ? { tls: {} } : {}),
            // Fail fast: a slow Redis must never stall login requests.
            enableOfflineQueue: false,
            maxRetriesPerRequest: 1,
            connectTimeout: 2_000,
            commandTimeout: 1_000,
        });
        this.redis.on('error', (error) => this.logRedisProblem(error));
    }

    async increment(
        key: string,
        ttl: number,
        limit: number,
        blockDuration: number,
        throttlerName: string,
    ): Promise<ThrottlerStorageRecord> {
        // Not connected yet (boot) or reconnecting after an outage: use the in-process counters for
        // that request instead of failing it. `enableOfflineQueue` is off on purpose (no stalled logins).
        if (!this.redis || this.redis.status !== 'ready') {
            return this.fallback.increment(key, ttl, limit, blockDuration, throttlerName);
        }

        const base = `backos:throttle:${throttlerName}:${key}`;
        try {
            const result = (await this.redis.eval(
                THROTTLE_LUA,
                2,
                base,
                `${base}:blocked`,
                String(ttl),
                String(limit),
                String(blockDuration),
            )) as [number, number, number, number];

            return {
                totalHits: Number(result[0]),
                timeToExpire: Math.ceil(Number(result[1]) / 1000),
                isBlocked: Number(result[2]) === 1,
                timeToBlockExpire: Math.ceil(Number(result[3]) / 1000),
            };
        } catch (error) {
            this.logRedisProblem(error);
            return this.fallback.increment(key, ttl, limit, blockDuration, throttlerName);
        }
    }

    async onModuleDestroy(): Promise<void> {
        this.fallback.onApplicationShutdown();
        if (this.redis) {
            await this.redis.quit().catch(() => this.redis?.disconnect());
        }
    }

    private logRedisProblem(error: unknown): void {
        const now = Date.now();
        if (now - this.lastErrorLogAt < 60_000) return;
        this.lastErrorLogAt = now;
        this.logger.error(
            `Redis rate-limit storage unavailable, using in-memory counters: ${error instanceof Error ? error.message : String(error)}`,
        );
    }
}
