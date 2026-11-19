import { ExecutionContext, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';

describe('JwtAuthGuard - recovery sessions (step 3)', () => {
    const ctx = { getHandler: () => 'handler', getClass: () => 'class' } as unknown as ExecutionContext;
    const make = (allowed: boolean | undefined) =>
        new JwtAuthGuard({ getAllAndOverride: jest.fn(() => allowed) } as any);

    it('une session normale passe partout', () => {
        const user = { userId: 'u1', permissions: ['x'] };
        expect(make(undefined).handleRequest(null, user, null, ctx)).toBe(user);
    });

    it('une session de récupération est REFUSÉE sur une route non marquée @AllowRecoveryScope()', () => {
        const user = { userId: 'u1', permissions: [], scope: 'recovery' };
        expect(() => make(undefined).handleRequest(null, user, null, ctx)).toThrow(ForbiddenException);
        expect(() => make(false).handleRequest(null, user, null, ctx)).toThrow(ForbiddenException);
    });

    it('une session de récupération passe sur une route marquée @AllowRecoveryScope()', () => {
        const user = { userId: 'u1', permissions: [], scope: 'recovery' };
        expect(make(true).handleRequest(null, user, null, ctx)).toBe(user);
    });

    it('un jeton invalide reste une 401', () => {
        expect(() => make(true).handleRequest(null, false, new Error('bad'), ctx)).toThrow(UnauthorizedException);
    });
});
