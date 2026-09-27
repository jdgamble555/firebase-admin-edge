import { FirebaseEdgeError } from './errors.js';
import type { FirebaseIdpSignInResponse } from './firebase-types.js';

export const FIREBASE_PROVIDER_IDS = {
    google: 'google.com',
    facebook: 'facebook.com',
    apple: 'apple.com',
    twitter: 'twitter.com',
    github: 'github.com',
    microsoft: 'microsoft.com',
    yahoo: 'yahoo.com',
    playgames: 'playgames.google.com'
} as const;

export type ProviderCredential = {
    idToken?: string;
    accessToken?: string;
    rawNonce?: string;
    secret?: string;
    serverAuthCode?: string;
};

export type ProviderAuthorizationOptions = {
    addScopes?: string[];
    customParameters?: Record<string, string>;
};

export type ProviderCallback = { requestUri: string } & (
    | {
          sessionId: string;
          postBody?: string;
          pendingToken?: never;
      }
    | {
          pendingToken: string;
          sessionId?: never;
          postBody?: never;
      }
);

/** Resolve a provider slug or a configured Firebase provider ID. */
export function resolveProviderId(provider: string): string {
    if (Object.hasOwn(FIREBASE_PROVIDER_IDS, provider))
        return FIREBASE_PROVIDER_IDS[
            provider as keyof typeof FIREBASE_PROVIDER_IDS
        ];
    if (
        (Object.values(FIREBASE_PROVIDER_IDS) as readonly string[]).includes(
            provider
        ) ||
        /^(oidc|saml)\..+/.test(provider)
    )
        return provider;
    throw new FirebaseEdgeError({
        code: 'auth/invalid-provider-id',
        message: 'Unsupported Firebase provider.'
    });
}

/** Serialize credentials for Firebase's signInWithIdp endpoint. @internal */
export function providerCredentialBody(
    token: string | ProviderCredential,
    provider: string
): string {
    const providerId = resolveProviderId(provider);
    const credential =
        typeof token === 'string'
            ? providerId === 'github.com' || providerId === 'facebook.com'
                ? { accessToken: token }
                : providerId === 'playgames.google.com'
                  ? { serverAuthCode: token }
                  : { idToken: token }
            : token;
    if (
        !credential ||
        ![
            credential.idToken,
            credential.accessToken,
            credential.serverAuthCode
        ].some((value) => typeof value === 'string' && value.trim().length > 0)
    )
        throw new FirebaseEdgeError({
            code: 'auth/invalid-credential',
            message: 'A provider credential is required.'
        });
    if (
        ['microsoft.com', 'yahoo.com'].includes(providerId) &&
        credential.accessToken &&
        !credential.idToken
    )
        throw new FirebaseEdgeError({
            code: 'auth/invalid-credential',
            message:
                'Use a Firebase-managed authorization flow for this provider.'
        });
    if (providerId.startsWith('saml.'))
        throw new FirebaseEdgeError({
            code: 'auth/invalid-credential',
            message: 'SAML requires an authorization callback.'
        });
    if (
        providerId === 'twitter.com' &&
        (!credential.accessToken || !credential.secret)
    )
        throw new FirebaseEdgeError({
            code: 'auth/invalid-credential',
            message: 'Twitter requires an access token and token secret.'
        });
    if (providerId === 'playgames.google.com' && !credential.serverAuthCode)
        throw new FirebaseEdgeError({
            code: 'auth/invalid-credential',
            message: 'Play Games requires a server authorization code.'
        });
    const body = new URLSearchParams();
    const fields = {
        idToken: 'id_token',
        accessToken: 'access_token',
        rawNonce: 'nonce',
        secret: 'oauth_token_secret',
        serverAuthCode: 'code'
    } as const;
    for (const [key, field] of Object.entries(fields)) {
        const value = credential[key as keyof ProviderCredential];
        if (value === undefined) continue;
        if (typeof value !== 'string' || !value.trim())
            throw new FirebaseEdgeError({
                code: 'auth/invalid-credential',
                message: 'Credential fields must be nonempty strings.'
            });
        body.set(field, value);
    }
    body.set('providerId', providerId);
    return body.toString();
}

/** Recover and validate the provider credential returned by Firebase. @internal */
export function providerCredentialFromResponse(
    response: FirebaseIdpSignInResponse
) {
    if (!response.providerId)
        throw new FirebaseEdgeError({
            code: 'auth/invalid-credential',
            message:
                'Firebase did not identify the provider for account linking.'
        });
    const providerId = resolveProviderId(response.providerId);
    const credential: ProviderCredential = {
        idToken: response.oauthIdToken,
        accessToken: response.oauthAccessToken,
        secret: response.oauthTokenSecret,
        rawNonce: response.nonce
    };
    // Reuse provider-specific validation, including Twitter's token secret.
    providerCredentialBody(credential, providerId);
    return { providerId, credential };
}
