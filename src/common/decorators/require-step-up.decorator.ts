import { applyDecorators, UseGuards } from '@nestjs/common';
import { ApiHeader } from '@nestjs/swagger';
import { StepUpGuard } from '../guards/step-up.guard';

/**
 * Requires a fresh TOTP code (header `X-TOTP-Code`) on top of the usual JWT + permission checks.
 * Use it on routes that destroy data, export data, or change who is allowed to do what.
 *
 * @example
 * @RequirePermissions(PERMISSIONS.BACKUP_MANAGE)
 * @RequireStepUp()
 * @Get('download')
 */
export function RequireStepUp(): MethodDecorator & ClassDecorator {
    return applyDecorators(
        UseGuards(StepUpGuard),
        ApiHeader({
            name: 'X-TOTP-Code',
            required: false,
            description:
                'Accounts WITHOUT a passkey: current authenticator (TOTP) code. Step-up re-authentication for this sensitive action.',
        }),
        ApiHeader({
            name: 'X-Step-Up-Token',
            required: false,
            description:
                'Accounts WITH a passkey: single-use token (valid 60 s) returned by POST /auth/passkeys/step-up/verify. Replaces X-TOTP-Code, which such accounts can no longer use.',
        }),
    );
}
