import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { AuthModule } from '../auth/auth.module';
import { PASSKEY_REDIS, PasskeyChallengeStore } from './passkey-challenge.store';
import { PasskeysAdminController } from './passkeys-admin.controller';
import { PasskeysController } from './passkeys.controller';
import { PasskeysService } from './passkeys.service';

@Module({
    imports: [AuthModule],
    controllers: [PasskeysController, PasskeysAdminController],
    providers: [
        PasskeysService,
        PasskeyChallengeStore,
        {
            provide: PASSKEY_REDIS,
            inject: [ConfigService],
            useFactory: (config: ConfigService) =>
                new Redis({
                    host: config.get<string>('REDIS_HOST', '127.0.0.1'),
                    port: Number(config.get('REDIS_PORT', 6379)),
                    password: config.get<string>('REDIS_PASSWORD') || undefined,
                    username: config.get<string>('REDIS_USERNAME') || undefined,
                    ...(String(config.get('REDIS_TLS', false)) === 'true' ? { tls: {} } : {}),
                    maxRetriesPerRequest: 2,
                    connectTimeout: 3_000,
                    commandTimeout: 2_000,
                }),
        },
    ],
    exports: [PasskeysService],
})
export class PasskeysModule {}
