import { describe, expect, it } from 'vitest';
import {
    FIREBASE_PROVIDER_IDS,
    providerCredentialBody,
    providerCredentialFromResponse,
    resolveProviderId
} from './provider-credential.js';

describe('provider credentials returned by Firebase', () => {
    it.each([
        { providerId: 'github.com', oauthAccessToken: 'github-token' },
        { providerId: 'facebook.com', oauthAccessToken: 'facebook-token' },
        {
            providerId: 'facebook.com',
            oauthIdToken: 'limited-login-id',
            nonce: 'facebook-nonce'
        },
        {
            providerId: 'apple.com',
            oauthIdToken: 'apple-id',
            nonce: 'apple-nonce'
        },
        {
            providerId: 'microsoft.com',
            oauthIdToken: 'microsoft-id',
            oauthAccessToken: 'access',
            nonce: 'microsoft-nonce'
        },
        {
            providerId: 'yahoo.com',
            oauthIdToken: 'yahoo-id',
            nonce: 'yahoo-nonce'
        },
        {
            providerId: 'google.com',
            oauthIdToken: 'google-id',
            oauthAccessToken: 'google-access'
        },
        {
            providerId: 'twitter.com',
            oauthAccessToken: 'twitter-token',
            oauthTokenSecret: 'twitter-secret'
        },
        { providerId: 'oidc.company', oauthIdToken: 'oidc-id' }
    ])(
        'maps $providerId credentials without using the Firebase ID token',
        (response) => {
            const input = Object.freeze({
                ...response,
                idToken: 'firebase-id'
            });
            const result = providerCredentialFromResponse(input);
            expect(result).toEqual({
                providerId: response.providerId,
                credential: {
                    idToken:
                        'oauthIdToken' in response
                            ? response.oauthIdToken
                            : undefined,
                    accessToken:
                        'oauthAccessToken' in response
                            ? response.oauthAccessToken
                            : undefined,
                    secret:
                        'oauthTokenSecret' in response
                            ? response.oauthTokenSecret
                            : undefined,
                    rawNonce: 'nonce' in response ? response.nonce : undefined
                }
            });
        }
    );

    it.each([
        {},
        { oauthAccessToken: 'no-provider' },
        { providerId: 'unknown', oauthAccessToken: 'token' },
        {
            providerId: 'github.com',
            idToken: 'firebase-id-is-not-an-oauth-token'
        },
        { providerId: 'github.com', oauthAccessToken: ' ' },
        { providerId: 'twitter.com', oauthAccessToken: 'missing-secret' },
        { providerId: 'saml.company', oauthIdToken: 'unsupported' },
        { providerId: 'microsoft.com', oauthAccessToken: 'access-only' },
        { providerId: 'yahoo.com', oauthAccessToken: 'access-only' },
        { providerId: 'apple.com', oauthIdToken: 'id', nonce: '' }
    ])('rejects missing or unsupported credentials: %j', (response) => {
        expect(() => providerCredentialFromResponse(response)).toThrow();
    });
});

describe('provider credentials', () => {
    it.each(Object.entries(FIREBASE_PROVIDER_IDS))(
        'resolves %s and its ID',
        (slug, id) => {
            expect(resolveProviderId(slug)).toBe(id);
            expect(resolveProviderId(id)).toBe(id);
        }
    );
    it.each(['oidc.company', 'saml.company'])('accepts configured %s', (id) => {
        expect(resolveProviderId(id)).toBe(id);
    });
    it.each(['', 'unknown', 'toString', '__proto__', 'oidc.', 'saml.'])(
        'rejects %s',
        (id) => {
            expect(() => resolveProviderId(id)).toThrow('Unsupported');
        }
    );
    it.each([
        ['google', 'id_token'],
        ['github', 'access_token'],
        ['facebook', 'access_token'],
        ['apple', 'id_token'],
        ['yahoo', 'id_token'],
        ['microsoft', 'id_token'],
        ['oidc.company', 'id_token'],
        ['playgames', 'code']
    ])('encodes a %s string credential', (provider, field) => {
        const body = new URLSearchParams(
            providerCredentialBody('a&b=+ token', provider!)
        );
        expect(body.get(field!)).toBe('a&b=+ token');
        expect(body.get('providerId')).toBe(resolveProviderId(provider!));
    });
    it('preserves Twitter secrets and Apple nonces', () => {
        const twitter = new URLSearchParams(
            providerCredentialBody(
                { accessToken: 'token', secret: 'secret&+' },
                'twitter'
            )
        );
        expect(twitter.get('oauth_token_secret')).toBe('secret&+');
        const apple = new URLSearchParams(
            providerCredentialBody(
                { idToken: 'id', rawNonce: 'nonce' },
                'apple'
            )
        );
        expect(apple.get('nonce')).toBe('nonce');
    });
    it.each([
        ['google', ''],
        ['google', '  '],
        ['apple', {}],
        ['twitter', { accessToken: 'token' }],
        ['twitter', 'token'],
        ['playgames', { idToken: 'id' }],
        ['saml.company', 'assertion'],
        ['microsoft', { accessToken: 'token' }],
        ['yahoo', { accessToken: 'token' }],
        ['apple', { idToken: 'id', rawNonce: '' }]
    ] as const)('rejects invalid %s credentials', (provider, credential) => {
        expect(() => providerCredentialBody(credential, provider)).toThrow();
    });
});
