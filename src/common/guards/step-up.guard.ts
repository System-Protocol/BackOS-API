import { CanActivate, ExecutionContext, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ModuleRef } from '@nestjs/core';
import type { Request } from 'express';
import { AuthService } from '../../auth/auth.service';
import { PasskeysService } from '../../passkeys/passkeys.service';

/** HTTP header carrying the current authenticator (TOTP) code for a step-up protected route. */
export const STEP_UP_HEADER = 'x-totp-code';

/** HTTP header carrying the single-use token obtained from a passkey step-up (`POST /auth/passkeys/step-up/*`). */
export const STEP_UP_TOKEN_HEADER = 'x-step-up-token';

/**
 * Step-up re-authentication gate (see `@RequireStepUp()`).
 *
 * WHY: a stolen or hijacked access token (valid up to 15 minutes) used to be enough to download a full
 * database dump, hand out permissions or delete a platform. For these routes the caller must now also
 * prove, with a fresh TOTP code, that the person holding the device is the one making the request.
 *
 * It runs AFTER the global guards (JWT authentication, then permissions), so `request.user` is set and
 * the caller is already known to hold the permission. Failed codes count toward the account lockout
 * (see `AuthService.verifyStepUpTotp`), and an already-used TOTP time step is refused (anti-replay).
 *
 * `AuthService` is resolved lazily through `ModuleRef` (non-strict) so a controller in any module can
 * use the decorator without having to import `AuthModule`.
 */
@Injectable()
export class StepUpGuard implements CanActivate {
    private readonly logger = new Logger(StepUpGuard.name);
    private warnedDisabled = false;

    constructor(
        private readonly moduleRef: ModuleRef,
        private readonly configService: ConfigService,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        // Rollout switch: lets the back end ship before the front end sends the header. Keep it on.
        if (String(this.configService.get('STEP_UP_REQUIRED', true)) === 'false') {
            if (!this.warnedDisabled) {
                this.warnedDisabled = true;
                this.logger.warn('STEP_UP_REQUIRED=false: step-up re-authentication is DISABLED. Re-enable it.');
            }
            return true;
        }

        const request = context.switchToHttp().getRequest<Request & { user?: { userId?: string; scope?: string } }>();
        const userId = request.user?.userId;
        if (!userId) {
            throw new UnauthorizedException('Re-authentication failed.');
        }

        // A recovery session (account with passkeys, signed in with a recovery code) already proved
        // itself with that code, and `JwtAuthGuard` only lets it reach `@AllowRecoveryScope()` routes.
        if (request.user?.scope === 'recovery') {
            return true;
        }

        const authService = this.moduleRef.get(AuthService, { strict: false });

        // 1) Passkey step-up: a single-use token, valid for 60 seconds, bound to this user.
        const tokenHeader = request.headers[STEP_UP_TOKEN_HEADER];
        if (typeof tokenHeader === 'string' && tokenHeader.length > 0) {
            const passkeys = this.moduleRef.get(PasskeysService, { strict: false });
            if (await passkeys.consumeStepUpToken(userId, tokenHeader.trim())) {
                return true;
            }
            throw new UnauthorizedException({
                statusCode: 401,
                message: 'Step-up token invalid, expired or already used. Confirm with your passkey again.',
                error: 'StepUpPasskeyRequired',
            });
        }

        // 2) No downgrade: an account that owns a passkey cannot step up with a TOTP code.
        if (await authService.passkeysEnforcedFor(userId)) {
            throw new UnauthorizedException({
                statusCode: 401,
                message:
                    'Step-up required: confirm with your passkey (POST /auth/passkeys/step-up/options then /verify) and send the returned token in the X-Step-Up-Token header.',
                error: 'StepUpPasskeyRequired',
            });
        }

        // 3) Accounts without a passkey: fresh TOTP code, as before.
        const header = request.headers[STEP_UP_HEADER];
        const code = typeof header === 'string' ? header.replace(/\s+/g, '') : '';
        if (!/^\d{6,8}$/.test(code)) {
            // A dedicated `error` value lets the front end open its "enter your authenticator code" dialog.
            throw new UnauthorizedException({
                statusCode: 401,
                message: 'Step-up required: send your current authenticator code in the X-TOTP-Code header.',
                error: 'StepUpRequired',
            });
        }

        await authService.verifyStepUpTotp(userId, code, {
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'],
        });
        return true;
    }
}
