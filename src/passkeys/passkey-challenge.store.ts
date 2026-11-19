import { Inject, Injectable, OnModuleDestroy, ServiceUnavailableException } from '@nestjs/common';
import { randomBytes } from 'crypto';

/** Injection token of the Redis client used by the passkey store. */
export const PASSKEY_REDIS = Symbol('PASSKEY_REDIS');

/** The tiny part of the ioredis API this store needs (lets tests inject an in-memory fake). */
export interface PasskeyRedisLike {
    set(key: string, value: string, mode: 'EX', seconds: number): Promise<unknown>;
    getdel(key: string): Promise<string | null>;
    quit(): Promise<unknown>;
}

export type PasskeyStoreKind = 'reg' | 'auth' | 'stepup' | 'su';

/**
 * Short-lived, SINGLE-USE storage for WebAuthn challenges and step-up tokens.
 *
 * - `take()` reads and deletes in one atomic Redis command (GETDEL): a challenge can never be used
 *   twice, even by two simultaneous requests. It is consumed BEFORE the signature is verified, so a
 *   failed attempt cannot be retried against the same challenge.
 * - TTLs are short (5 min for challenges, 60 s for step-up tokens).
 * - Fail closed: if Redis is unreachable the operation fails with 503. (Unlike rate limiting, falling
 *   back to process memory here would be wrong with several instances: the challenge issued by one
 *   instance would be unknown to the other.)
 */
@Injectable()
export class PasskeyChallengeStore implements OnModuleDestroy {
    constructor(@Inject(PASSKEY_REDIS) private readonly redis: PasskeyRedisLike) {}

    private key(kind: PasskeyStoreKind, id: string): string {
        return `backos:webauthn:${kind}:${id}`;
    }

    /** Stores `payload` and returns its id (random 256-bit hex unless an id is imposed). */
    async put(kind: PasskeyStoreKind, payload: object, ttlSeconds: number, id?: string): Promise<string> {
        const finalId = id ?? randomBytes(32).toString('hex');
        try {
            await this.redis.set(this.key(kind, finalId), JSON.stringify(payload), 'EX', ttlSeconds);
        } catch {
            throw new ServiceUnavailableException('Passkey service temporarily unavailable.');
        }
        return finalId;
    }

    /** Atomically reads AND deletes the entry. Returns null when absent, expired or already used. */
    async take<T extends object>(kind: PasskeyStoreKind, id: string): Promise<T | null> {
        if (!/^[a-f0-9]{64}$/.test(id)) return null;
        let raw: string | null;
        try {
            raw = await this.redis.getdel(this.key(kind, id));
        } catch {
            throw new ServiceUnavailableException('Passkey service temporarily unavailable.');
        }
        if (!raw) return null;
        try {
            return JSON.parse(raw) as T;
        } catch {
            return null;
        }
    }

    async onModuleDestroy(): Promise<void> {
        await this.redis.quit().catch(() => undefined);
    }
}
