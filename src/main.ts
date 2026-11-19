import { NestFactory } from '@nestjs/core';
import { Logger, ConsoleLogger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import { configureApp } from './app.setup';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { certificateDaysLeft, loadHttpsOptions, tlsFilesFromEnv, watchTlsFiles } from './config/tls';

async function bootstrap() {
    // OPS-007: LOG_FORMAT=json switches to structured JSON logs (one object per line), easier to
    // ship to a log pipeline; the default human-readable format is kept for development.
    // LAN stack: the API serves HTTPS itself when TLS_KEY_FILE / TLS_CERT_FILE are set (see docker-compose.lan.yml).
    const tlsFiles = tlsFilesFromEnv();
    const httpsOptions = tlsFiles ? loadHttpsOptions(tlsFiles) : undefined;

    const app = await NestFactory.create(AppModule, {
        logger: process.env.LOG_FORMAT === 'json' ? new ConsoleLogger({ json: true }) : undefined,
        httpsOptions,
    });

    // Without this, a SIGTERM (deploy, `docker stop`, `pm2 reload`, ...) kills the process
    // immediately - Nest's `onModuleDestroy`/`beforeApplicationShutdown` hooks never run, which
    // means the BullMQ Worker inside GenerationProcessor never gets a chance to close cleanly.
    // This doesn't make a mid-generation restart free (a build in progress still gets cut off),
    // but it's what lets BullMQ release its job lock immediately instead of leaving it to expire
    // via `lockDuration`, and it's a prerequisite for `GenerationProcessor`'s own reconciliation
    // logic (`onApplicationBootstrap` / the `failed` WorkerEvent) to be reliably reached on the
    // next boot rather than racing an unclean kill.
    app.enableShutdownHooks();

    const configService = app.get(ConfigService);

    configureApp(app);

    const port = configService.get<number>('PORT', 4803);
    const isProduction = configService.get<string>('NODE_ENV') === 'production';

    // SECURITY: the interactive OpenAPI explorer documents every route and DTO shape on this
    // API. That is valuable in development but is unnecessary reconnaissance information to
    // hand to an unauthenticated caller in production, so it is only mounted outside of
    // `production`.
    if (!isProduction) {
        const swaggerConfig = new DocumentBuilder()
            .setTitle('BPG Core API')
            .setDescription('API du générateur BPG (Backend Platform Generator)')
            .setVersion('0.1.0')
            .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }, 'access-token')
            .build();

        const swaggerDocument = SwaggerModule.createDocument(app, swaggerConfig);
        SwaggerModule.setup('api/docs', app, swaggerDocument);
    }

    await app.listen(port);

    if (tlsFiles && httpsOptions) {
        const daysLeft = Math.floor(certificateDaysLeft(httpsOptions.cert));
        if (daysLeft < 30) {
            Logger.warn(
                `The TLS certificate expires in ${daysLeft} days: restart the stack so it is renewed.`,
                'Bootstrap',
            );
        }
        // A renewed certificate (written by tls-init) is picked up without a restart.
        watchTlsFiles(app.getHttpServer(), tlsFiles);
    }

    Logger.log(`back-os Backend listening on ${tlsFiles ? 'https' : 'http'}://:${port}`, 'Bootstrap');
}

void bootstrap();
