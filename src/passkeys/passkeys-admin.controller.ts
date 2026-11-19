import { Controller, Delete, Param, ParseUUIDPipe, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { PERMISSIONS } from '../common/constants/permissions.constant';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { RequirePermissions } from '../common/decorators/require-permissions.decorator';
import { RequireStepUp } from '../common/decorators/require-step-up.decorator';
import { PasskeysService } from './passkeys.service';

@ApiTags('Passkeys')
@ApiBearerAuth()
@Controller('users')
export class PasskeysAdminController {
    constructor(private readonly passkeys: PasskeysService) {}

    /**
     * Lost-device recovery: revokes every passkey of a more junior user and ends their sessions. The
     * user can then sign in with TOTP again and enrol new passkeys. Hierarchy rule + step-up apply.
     */
    @RequirePermissions(PERMISSIONS.USERS_MANAGE_ROLES)
    @RequireStepUp()
    @Delete(':id/passkeys')
    @ApiOperation({ summary: "Reset (revoke) all of a user's passkeys" })
    resetPasskeys(@CurrentUser('userId') actorId: string, @Param('id', ParseUUIDPipe) id: string, @Req() req: Request) {
        return this.passkeys.adminResetAll(actorId, id, { ipAddress: req.ip, userAgent: req.headers['user-agent'] });
    }
}
