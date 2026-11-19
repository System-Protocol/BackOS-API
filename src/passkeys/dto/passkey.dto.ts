import { Transform } from 'class-transformer';
import { IsObject, IsString, Length, Matches } from 'class-validator';

const CHALLENGE_ID = /^[a-f0-9]{64}$/;

/** Body of `POST /auth/passkeys/login/verify` and `.../step-up/verify`. */
export class PasskeyAssertionDto {
    /** Id returned by the matching `.../options` call. */
    @IsString()
    @Matches(CHALLENGE_ID)
    challengeId!: string;

    /** The `AuthenticationResponseJSON` produced by the browser / OS. Deeply validated by the WebAuthn library. */
    @IsObject()
    response!: Record<string, any>;
}

/** Body of `POST /auth/passkeys/register/verify`. */
export class PasskeyRegistrationDto {
    @IsString()
    @Matches(CHALLENGE_ID)
    challengeId!: string;

    /** The `RegistrationResponseJSON` produced by the browser / OS. */
    @IsObject()
    response!: Record<string, any>;

    /** Display name chosen by the user, e.g. "YubiKey bureau". */
    @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
    @IsString()
    @Length(1, 64)
    name!: string;
}
