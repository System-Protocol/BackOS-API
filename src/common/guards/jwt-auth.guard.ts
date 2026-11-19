import { ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Reflector } from '@nestjs/core';
import { ALLOW_RECOVERY_SCOPE_KEY } from '../decorators/allow-recovery-scope.decorator';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

/**
 * Global authentication guard extending Passport's built-in JWT guard.
 * Intercepts incoming requests to verify JWT credentials unless explicitly marked as public.
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
    /**
     * @param reflector - Helper service used to retrieve custom metadata attached to route handlers or controllers.
     */
    constructor(private readonly reflector: Reflector) {
        super();
    }

    /**
     * Determines whether the current request is allowed to proceed.
     * * @param context - Execution details regarding the current pipeline and endpoint handler.
     * @returns `true` if public or successfully authenticated; otherwise delegates to `AuthGuard('jwt')`.
     */
    canActivate(context: ExecutionContext) {
        // Checks for the `@Public()` decorator metadata on either the handler (method) or class (controller).
        // Method-level metadata overrides class-level metadata if present.
        const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        // Opt-out mechanism: Allows immediate access without validating JWT signatures for public routes.
        if (isPublic) return true;

        // Delegates authentication to Passport's default 'jwt' strategy pipeline for protected routes.
        return super.canActivate(context);
    }

    /**
     * SECURITY (step 3): a token with `scope: 'recovery'` (issued after a recovery-code login on an
     * account that owns passkeys) is only valid on routes explicitly marked `@AllowRecoveryScope()`.
     * This is an allow-list, so every route added in the future is closed to it by default.
     */
    handleRequest<TUser = any>(err: any, user: any, info: any, context: ExecutionContext, status?: any): TUser {
        const authenticated = super.handleRequest(err, user, info, context, status);
        if (authenticated?.scope === 'recovery') {
            const allowed = this.reflector.getAllAndOverride<boolean>(ALLOW_RECOVERY_SCOPE_KEY, [
                context.getHandler(),
                context.getClass(),
            ]);
            if (!allowed) {
                throw new ForbiddenException('Recovery session: register a new passkey first.');
            }
        }
        return authenticated as TUser;
    }
}
