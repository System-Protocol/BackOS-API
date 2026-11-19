/**
 * SECURITY (step 2 - JWT pinning): the access-token verification parameters, shared by the signer
 * (`AuthModule`) and the verifier (`JwtStrategy`) so they can never drift apart.
 *
 * - `algorithm`: only HS256 is accepted. Without an explicit allow-list, the verifier trusts
 *   whichever algorithm the (attacker-controlled) token header announces.
 * - `issuer` / `audience`: a token signed by another service that happens to share the secret
 *   (or a token minted for another purpose) is rejected.
 *
 * Deploying this invalidates the access tokens already issued (<= JWT_ACCESS_EXPIRES_IN, 15 min by
 * default); refresh tokens are unaffected, so clients silently re-authenticate through /auth/refresh.
 */
export const JWT_ALGORITHM = 'HS256' as const;
export const JWT_ISSUER = 'backos-api';
export const JWT_AUDIENCE = 'backos-access';
