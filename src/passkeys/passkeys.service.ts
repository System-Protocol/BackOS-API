import {
    BadRequestException,
    ConflictException,
    ForbiddenException,
    Injectable,
    NotFoundException,
    ServiceUnavailableException,
    UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { createHash, randomBytes } from 'crypto';
import { UserStatus } from '@prismamodels/enums';
import { AuditContext, AuditLogService } from '../audit/audit-log.service';
import { AuthService } from '../auth/auth.service';
import { AUDIT_ACTIONS } from '../common/constants/audit-actions';
import { AUDIT_TARGETS } from '../common/constants/audit-target.constant';
import { RoleHierarchyService } from '../common/services/role-hierarchy.service';
import { PrismaService } from '../prisma/prisma.service';
import { PasskeyChallengeStore } from './passkey-challenge.store';

const CHALLENGE_TTL_SECONDS = 300;
const STEP_UP_TOKEN_TTL_SECONDS = 60;
const CEREMONY_TIMEOUT_MS = 120_000;
const ALLOWED_TRANSPORTS = new Set(['usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card']);

interface ChallengeEntry {
    challenge: string;
    userId?: string;
}

/**
 * Passkey (WebAuthn) authentication: registration, passwordless login, step-up re-authentication,
 * revocation. The cryptography is delegated to @simplewebauthn/server; this class owns the POLICY:
 *
 *  - user verification (PIN / biometric on the device) is REQUIRED on every ceremony;
 *  - credentials are discoverable (usernameless login: no identifier is sent, so nothing to enumerate);
 *  - RP ID and origins are pinned by configuration, never taken from the request;
 *  - every challenge is single-use, short-lived, and bound to its purpose (and to the user when known);
 *  - a signature counter that goes backwards revokes the passkey (cloned authenticator);
 *  - the last passkey of an account cannot be self-revoked (that would be a silent downgrade to TOTP).
 */
@Injectable()
export class PasskeysService {
    constructor(
        private readonly prisma: PrismaService,
        private readonly configService: ConfigService,
        private readonly store: PasskeyChallengeStore,
        private readonly authService: AuthService,
        private readonly roleHierarchy: RoleHierarchyService,
        private readonly auditLog: AuditLogService,
    ) {}

    // ---------------------------------------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------------------------------------

    private settings() {
        const rpID = String(this.configService.get<string>('WEBAUTHN_RP_ID') ?? '').trim();
        const origins = String(this.configService.get<string>('WEBAUTHN_ORIGINS') ?? '')
            .split(',')
            .map((o) => o.trim())
            .filter(Boolean);
        if (!rpID || origins.length === 0) {
            throw new ServiceUnavailableException('Passkeys are not configured on this server.');
        }
        return {
            rpID,
            origins,
            rpName: String(this.configService.get<string>('WEBAUTHN_RP_NAME') ?? 'BACKOS Control'),
            requireDeviceBound: String(this.configService.get('PASSKEY_REQUIRE_DEVICE_BOUND', false)) === 'true',
            max: Number(this.configService.get('PASSKEY_MAX_PER_USER', 10)),
        };
    }

    // ---------------------------------------------------------------------------------------------
    // Registration (authenticated)
    // ---------------------------------------------------------------------------------------------

    async startRegistration(userId: string) {
        const s = this.settings();
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            select: { id: true, workEmail: true, firstName: true, lastName: true, status: true },
        });
        if (!user || user.status !== UserStatus.ACTIVE) throw new UnauthorizedException('Session no longer valid.');

        const existing = await this.prisma.userPasskey.findMany({
            where: { userId, revokedAt: null },
            select: { credentialId: true, transports: true },
        });
        if (existing.length >= s.max) {
            throw new BadRequestException(`You already have the maximum number of passkeys (${s.max}).`);
        }

        const options = await generateRegistrationOptions({
            rpName: s.rpName,
            rpID: s.rpID,
            userName: user.workEmail,
            userDisplayName: `${user.firstName} ${user.lastName}`.trim(),
            userID: new TextEncoder().encode(user.id),
            attestationType: 'none',
            timeout: CEREMONY_TIMEOUT_MS,
            // Never let the same authenticator register twice.
            excludeCredentials: existing.map((p) => ({ id: p.credentialId, transports: p.transports })),
            authenticatorSelection: {
                residentKey: 'required', // discoverable credential = usernameless login
                requireResidentKey: true,
                userVerification: 'required',
            },
        });

        const challengeId = await this.store.put(
            'reg',
            { challenge: options.challenge, userId },
            CHALLENGE_TTL_SECONDS,
        );
        return { challengeId, options };
    }

    async finishRegistration(
        userId: string,
        input: { challengeId: string; response: RegistrationResponseJSON; name: string },
        context: AuditContext,
    ) {
        const s = this.settings();
        // Consumed first: whatever happens next, this challenge can never be replayed.
        const entry = await this.store.take<ChallengeEntry>('reg', input.challengeId);
        if (!entry || entry.userId !== userId) throw new BadRequestException('Invalid or expired challenge.');

        let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
        try {
            verification = await verifyRegistrationResponse({
                response: input.response,
                expectedChallenge: entry.challenge,
                expectedOrigin: s.origins,
                expectedRPID: s.rpID,
                requireUserVerification: true,
            });
        } catch {
            throw new BadRequestException('The passkey could not be verified.');
        }
        if (!verification.verified) throw new BadRequestException('The passkey could not be verified.');

        const { credential, credentialDeviceType, credentialBackedUp, aaguid } = verification.registrationInfo;
        if (s.requireDeviceBound && credentialDeviceType !== 'singleDevice') {
            throw new BadRequestException(
                'Only hardware-bound passkeys are accepted on this server (no synced passkeys).',
            );
        }

        const transports = (input.response.response.transports ?? []).filter((t) => ALLOWED_TRANSPORTS.has(t));
        const name = this.cleanName(input.name);

        let created;
        try {
            created = await this.prisma.userPasskey.create({
                data: {
                    userId,
                    credentialId: credential.id,
                    publicKey: Buffer.from(credential.publicKey),
                    counter: BigInt(credential.counter),
                    transports,
                    deviceType: credentialDeviceType,
                    backedUp: credentialBackedUp,
                    aaguid,
                    name,
                },
            });
        } catch (error) {
            if ((error as { code?: string }).code === 'P2002') {
                throw new ConflictException('This passkey is already registered.');
            }
            throw error;
        }

        await this.auditLog.log({
            action: AUDIT_ACTIONS.PASSKEY_REGISTERED,
            actorId: userId,
            targetType: AUDIT_TARGETS.PASSKEY,
            targetId: created.id,
            metadata: { name, deviceType: credentialDeviceType, backedUp: credentialBackedUp, aaguid },
            context,
        });
        return this.summary(created);
    }

    // ---------------------------------------------------------------------------------------------
    // Login (public, usernameless)
    // ---------------------------------------------------------------------------------------------

    async startLogin() {
        const s = this.settings();
        const options = await generateAuthenticationOptions({
            rpID: s.rpID,
            userVerification: 'required',
            timeout: CEREMONY_TIMEOUT_MS,
        });
        const challengeId = await this.store.put('auth', { challenge: options.challenge }, CHALLENGE_TTL_SECONDS);
        return { challengeId, options };
    }

    async finishLogin(input: { challengeId: string; response: AuthenticationResponseJSON }, context: AuditContext) {
        const entry = await this.store.take<ChallengeEntry>('auth', input.challengeId);
        if (!entry) throw new UnauthorizedException('Invalid credentials.');

        const credentialId = typeof input.response?.id === 'string' ? input.response.id : '';
        const passkey =
            credentialId.length > 0 && credentialId.length <= 1024
                ? await this.prisma.userPasskey.findUnique({
                      where: { credentialId },
                      include: { user: { select: { id: true, status: true } } },
                  })
                : null;
        if (!passkey || passkey.revokedAt || passkey.user.status !== UserStatus.ACTIVE) {
            await this.auditLog.log({
                action: AUDIT_ACTIONS.PASSKEY_LOGIN_FAILED,
                metadata: { reason: 'unknown-credential' },
                context,
            });
            throw new UnauthorizedException('Invalid credentials.');
        }

        // The discoverable credential carries the user handle: it must be the owner of the passkey.
        const expectedHandle = Buffer.from(passkey.userId).toString('base64url');
        const handle = input.response.response?.userHandle;
        if (handle !== undefined && handle !== expectedHandle) {
            await this.failLogin(passkey.userId, 'user-handle-mismatch', context);
        }

        const newCounter = await this.verifyAssertion(
            passkey,
            input.response,
            entry.challenge,
            passkey.userId,
            context,
        );
        await this.advanceCounter(passkey, newCounter, context);
        return this.authService.completePasskeyLogin(passkey.userId, context);
    }

    // ---------------------------------------------------------------------------------------------
    // Step-up (authenticated): a passkey assertion exchanged for a one-shot, 60-second token
    // ---------------------------------------------------------------------------------------------

    async startStepUp(userId: string) {
        const s = this.settings();
        const passkeys = await this.prisma.userPasskey.findMany({
            where: { userId, revokedAt: null },
            select: { credentialId: true, transports: true },
        });
        if (passkeys.length === 0) throw new BadRequestException('This account has no passkey.');

        const options = await generateAuthenticationOptions({
            rpID: s.rpID,
            userVerification: 'required',
            timeout: CEREMONY_TIMEOUT_MS,
            allowCredentials: passkeys.map((p) => ({ id: p.credentialId, transports: p.transports })),
        });
        const challengeId = await this.store.put(
            'stepup',
            { challenge: options.challenge, userId },
            CHALLENGE_TTL_SECONDS,
        );
        return { challengeId, options };
    }

    async finishStepUp(
        userId: string,
        input: { challengeId: string; response: AuthenticationResponseJSON },
        context: AuditContext,
    ) {
        const entry = await this.store.take<ChallengeEntry>('stepup', input.challengeId);
        if (!entry || entry.userId !== userId) throw new UnauthorizedException('Re-authentication failed.');

        const credentialId = typeof input.response?.id === 'string' ? input.response.id : '';
        const passkey = credentialId
            ? await this.prisma.userPasskey.findFirst({ where: { credentialId, userId, revokedAt: null } })
            : null;
        if (!passkey) throw new UnauthorizedException('Re-authentication failed.');

        const newCounter = await this.verifyAssertion(
            passkey,
            input.response,
            entry.challenge,
            userId,
            context,
            'step-up',
        );
        await this.advanceCounter(passkey, newCounter, context);

        const token = randomBytes(32).toString('base64url');
        await this.store.put('su', { userId }, STEP_UP_TOKEN_TTL_SECONDS, this.hashToken(token));
        await this.auditLog.log({
            action: AUDIT_ACTIONS.PASSKEY_STEP_UP,
            actorId: userId,
            targetType: AUDIT_TARGETS.PASSKEY,
            targetId: passkey.id,
            context,
        });
        return { stepUpToken: token, expiresInSeconds: STEP_UP_TOKEN_TTL_SECONDS };
    }

    /** Consumes a step-up token (single use). Used by `StepUpGuard`. */
    async consumeStepUpToken(userId: string, token: string): Promise<boolean> {
        if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return false;
        const entry = await this.store.take<{ userId: string }>('su', this.hashToken(token));
        return !!entry && entry.userId === userId;
    }

    // ---------------------------------------------------------------------------------------------
    // Management
    // ---------------------------------------------------------------------------------------------

    async list(userId: string) {
        const rows = await this.prisma.userPasskey.findMany({
            where: { userId, revokedAt: null },
            orderBy: { createdAt: 'asc' },
        });
        return {
            passkeys: rows.map((r) => this.summary(r)),
            // One passkey is the minimum; two (ideally one hardware key) means a lost device is not a lockout.
            recommendedMinimumReached: rows.length >= 2,
        };
    }

    /** Self-service revocation. The last passkey cannot be removed (that would silently downgrade to TOTP). */
    async revoke(userId: string, passkeyId: string, context: AuditContext) {
        const target = await this.prisma.userPasskey.findFirst({ where: { id: passkeyId, userId, revokedAt: null } });
        if (!target) throw new NotFoundException('Passkey not found.');

        const active = await this.prisma.userPasskey.count({ where: { userId, revokedAt: null } });
        if (active <= 1) {
            throw new BadRequestException(
                'You cannot remove your last passkey. Register another one first, or ask an administrator to reset your passkeys.',
            );
        }

        await this.prisma.userPasskey.update({
            where: { id: target.id },
            data: { revokedAt: new Date(), revokedReason: 'user-revoked' },
        });
        // A revoked passkey usually means a lost or compromised device: end every session now.
        await this.authService.revokeAllRefreshTokens(userId);
        await this.auditLog.log({
            action: AUDIT_ACTIONS.PASSKEY_REVOKED,
            actorId: userId,
            targetType: AUDIT_TARGETS.PASSKEY,
            targetId: target.id,
            metadata: { name: target.name, reason: 'user-revoked' },
            context,
        });
        return { revoked: true };
    }

    /** Administrator recovery: revokes ALL passkeys of a (more junior) user, who then re-enrols. */
    async adminResetAll(actorId: string, targetUserId: string, context: AuditContext) {
        if (actorId === targetUserId) {
            throw new ForbiddenException('Use your own passkey management to change your passkeys.');
        }
        await this.roleHierarchy.assertSeniorToTarget(actorId, targetUserId, 'reset the passkeys of');

        const result = await this.prisma.userPasskey.updateMany({
            where: { userId: targetUserId, revokedAt: null },
            data: { revokedAt: new Date(), revokedReason: 'admin-reset' },
        });
        await this.authService.revokeAllRefreshTokens(targetUserId);
        await this.auditLog.log({
            action: AUDIT_ACTIONS.PASSKEYS_RESET_BY_ADMIN,
            actorId,
            targetType: AUDIT_TARGETS.USER,
            targetId: targetUserId,
            metadata: { revokedCount: result.count },
            context,
        });
        return { revoked: result.count };
    }

    // ---------------------------------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------------------------------

    /** Verifies an assertion; ANY failure is audited and reported with one generic message. */
    private async verifyAssertion(
        passkey: { credentialId: string; publicKey: Uint8Array; transports: string[] },
        response: AuthenticationResponseJSON,
        challenge: string,
        userId: string,
        context: AuditContext,
        purpose: 'login' | 'step-up' = 'login',
    ): Promise<number> {
        const s = this.settings();
        try {
            const result = await verifyAuthenticationResponse({
                response,
                expectedChallenge: challenge,
                expectedOrigin: s.origins,
                expectedRPID: s.rpID,
                requireUserVerification: true,
                // Counter 0 on purpose: the clone check is done by `advanceCounter` (atomic, audited).
                credential: {
                    id: passkey.credentialId,
                    publicKey: new Uint8Array(passkey.publicKey),
                    counter: 0,
                    transports: passkey.transports,
                },
            });
            if (!result.verified) throw new Error('not verified');
            return result.authenticationInfo.newCounter;
        } catch {
            return this.failLogin(userId, 'invalid-assertion', context, purpose);
        }
    }

    private async failLogin(userId: string, reason: string, context: AuditContext, purpose = 'login'): Promise<never> {
        await this.auditLog.log({
            action: AUDIT_ACTIONS.PASSKEY_LOGIN_FAILED,
            actorId: userId,
            targetType: AUDIT_TARGETS.USER,
            targetId: userId,
            metadata: { reason, purpose },
            context,
        });
        throw new UnauthorizedException(purpose === 'step-up' ? 'Re-authentication failed.' : 'Invalid credentials.');
    }

    /**
     * Moves the stored signature counter forward, atomically. A counter that does not increase
     * (when either side is non-zero) means the credential was cloned: the passkey is revoked.
     * Authenticators that always report 0 (most synced passkeys) are not affected.
     */
    private async advanceCounter(
        passkey: { id: string; userId: string; counter: bigint; name: string },
        newCounter: number,
        context: AuditContext,
    ) {
        const next = BigInt(newCounter);
        if (next === 0n && passkey.counter === 0n) {
            await this.prisma.userPasskey.update({ where: { id: passkey.id }, data: { lastUsedAt: new Date() } });
            return;
        }
        const moved = await this.prisma.userPasskey.updateMany({
            where: { id: passkey.id, revokedAt: null, counter: { lt: next } },
            data: { counter: next, lastUsedAt: new Date() },
        });
        if (moved.count === 1) return;

        await this.prisma.userPasskey.updateMany({
            where: { id: passkey.id, revokedAt: null },
            data: { revokedAt: new Date(), revokedReason: 'clone-suspected' },
        });
        await this.authService.revokeAllRefreshTokens(passkey.userId);
        await this.auditLog.log({
            action: AUDIT_ACTIONS.PASSKEY_CLONE_SUSPECTED,
            actorId: passkey.userId,
            targetType: AUDIT_TARGETS.PASSKEY,
            targetId: passkey.id,
            metadata: {
                name: passkey.name,
                storedCounter: passkey.counter.toString(),
                receivedCounter: next.toString(),
            },
            context,
        });
        throw new UnauthorizedException('Invalid credentials.');
    }

    private hashToken(token: string): string {
        return createHash('sha256').update(token).digest('hex');
    }

    /** Display name only: trimmed, control characters removed (the front end must still escape it). */
    private cleanName(raw: string): string {
        const cleaned = String(raw ?? '')
            // eslint-disable-next-line no-control-regex
            .replace(/[\u0000-\u001f\u007f]/g, '')
            .trim()
            .slice(0, 64);
        return cleaned || 'Passkey';
    }

    private summary(p: {
        id: string;
        name: string;
        deviceType: string;
        backedUp: boolean;
        transports: string[];
        createdAt: Date;
        lastUsedAt: Date | null;
    }) {
        return {
            id: p.id,
            name: p.name,
            deviceType: p.deviceType,
            backedUp: p.backedUp,
            transports: p.transports,
            createdAt: p.createdAt,
            lastUsedAt: p.lastUsedAt,
        };
    }
}
