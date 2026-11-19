import {
    Body,
    Controller,
    Delete,
    Get,
    HttpCode,
    HttpStatus,
    Param,
    ParseUUIDPipe,
    Post,
    Req,
    UseGuards,
} from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { AllowRecoveryScope } from '../common/decorators/allow-recovery-scope.decorator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Public } from '../common/decorators/public.decorator';
import { RequireStepUp } from '../common/decorators/require-step-up.decorator';
import { PasskeyAssertionDto, PasskeyRegistrationDto } from './dto/passkey.dto';
import { PasskeysService } from './passkeys.service';

function extractContext(req: Request) {
    return { ipAddress: req.ip, userAgent: req.headers['user-agent'] };
}

/** A ceremony is cheap to start and expensive to guess: a tight, route-specific budget on every entry point. */
const CEREMONY_THROTTLE = { default: { limit: 8, ttl: 60_000 } };

/**
 * Passkey (WebAuthn) endpoints. See `PasskeysService` for the security policy.
 *
 * Front-end contract: every `.../options` response is `{ challengeId, options }` where `options` is the
 * exact JSON to hand to `navigator.credentials.create/get` (via `PublicKeyCredential.parse*FromJSON`);
 * the `.../verify` call sends back `{ challengeId, response }` (the credential's `toJSON()`).
 */
@Throttle({ default: { limit: 20, ttl: 60_000 } })
@UseGuards(ThrottlerGuard)
@ApiTags('Passkeys')
@ApiBearerAuth()
@Controller('auth/passkeys')
export class PasskeysController {
    constructor(private readonly passkeys: PasskeysService) {}

    // ---- Login (public, usernameless) -------------------------------------------------------------

    @Public()
    @Throttle(CEREMONY_THROTTLE)
    @Post('login/options')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Start a passkey login (no identifier needed)' })
    loginOptions() {
        return this.passkeys.startLogin();
    }

    @Public()
    @Throttle(CEREMONY_THROTTLE)
    @Post('login/verify')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Finish a passkey login and receive the session tokens' })
    @ApiOkResponse({ description: '{ accessToken, refreshToken }' })
    loginVerify(@Body() dto: PasskeyAssertionDto, @Req() req: Request) {
        return this.passkeys.finishLogin(
            { challengeId: dto.challengeId, response: dto.response as any },
            extractContext(req),
        );
    }

    // ---- Registration (authenticated + step-up) ---------------------------------------------------

    @AllowRecoveryScope()
    @RequireStepUp()
    @Throttle(CEREMONY_THROTTLE)
    @Post('register/options')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Start registering a passkey (requires step-up)' })
    registerOptions(@CurrentUser('userId') userId: string) {
        return this.passkeys.startRegistration(userId);
    }

    @AllowRecoveryScope()
    @Throttle(CEREMONY_THROTTLE)
    @Post('register/verify')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Finish registering a passkey' })
    registerVerify(@CurrentUser('userId') userId: string, @Body() dto: PasskeyRegistrationDto, @Req() req: Request) {
        return this.passkeys.finishRegistration(
            userId,
            { challengeId: dto.challengeId, response: dto.response as any, name: dto.name },
            extractContext(req),
        );
    }

    // ---- Step-up: passkey assertion -> one-shot token ---------------------------------------------

    @Throttle(CEREMONY_THROTTLE)
    @Post('step-up/options')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Start a passkey step-up re-authentication' })
    stepUpOptions(@CurrentUser('userId') userId: string) {
        return this.passkeys.startStepUp(userId);
    }

    @Throttle(CEREMONY_THROTTLE)
    @Post('step-up/verify')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Finish the step-up: returns a single-use token valid 60 s (header X-Step-Up-Token)' })
    stepUpVerify(@CurrentUser('userId') userId: string, @Body() dto: PasskeyAssertionDto, @Req() req: Request) {
        return this.passkeys.finishStepUp(
            userId,
            { challengeId: dto.challengeId, response: dto.response as any },
            extractContext(req),
        );
    }

    // ---- Management -------------------------------------------------------------------------------

    @AllowRecoveryScope()
    @Get()
    @ApiOperation({ summary: 'List my passkeys' })
    list(@CurrentUser('userId') userId: string) {
        return this.passkeys.list(userId);
    }

    @AllowRecoveryScope()
    @RequireStepUp()
    @Delete(':id')
    @ApiOperation({ summary: 'Revoke one of my passkeys (never the last one)' })
    revoke(@CurrentUser('userId') userId: string, @Param('id', ParseUUIDPipe) id: string, @Req() req: Request) {
        return this.passkeys.revoke(userId, id, extractContext(req));
    }
}
