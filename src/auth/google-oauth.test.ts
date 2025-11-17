import { describe, expect, it, beforeEach, vi } from 'vitest';
import {
    createGoogleOAuthLoginUrl,
    exchangeCodeForGoogleIdToken,
    getToken
} from './google-oauth.js';

const restFetchMock = vi.hoisted(() => vi.fn());
const signJWTMock = vi.hoisted(() => vi.fn());

vi.mock('../rest-fetch.js', () => ({
    restFetch: restFetchMock
}));
vi.mock('./firebase-jwt.js', () => ({
    signJWT: signJWTMock
}));

beforeEach(() => {
    restFetchMock.mockReset();
    signJWTMock.mockReset();
});

describe('createGoogleOAuthLoginUrl', () => {
    it('builds expected consent screen URL', () => {
        const url = createGoogleOAuthLoginUrl(
            'https://example.com/callback',
            '/next/path',
            'client-123'
        );
        const parsed = new URL(url);

        expect(parsed.origin + parsed.pathname).toBe(
            'https://accounts.google.com/o/oauth2/v2/auth'
        );
        expect(parsed.searchParams.get('client_id')).toBe('client-123');
        expect(parsed.searchParams.get('redirect_uri')).toBe(
            'https://example.com/callback'
        );
        expect(parsed.searchParams.get('response_type')).toBe('code');
        expect(parsed.searchParams.get('scope')).toBe('openid email profile');
        expect(parsed.searchParams.get('access_type')).toBe('offline');
        expect(parsed.searchParams.get('prompt')).toBe('consent');
        expect(JSON.parse(parsed.searchParams.get('state') ?? '')).toEqual({
            next: '/next/path',
            provider: 'google'
        });
    });
});

describe('exchangeCodeForGoogleIdToken', () => {
    const payload = {
        code: 'auth-code',
        redirect_uri: 'https://example.com/callback',
        client_id: 'client-123',
        client_secret: 'secret-xyz'
    };

    it('returns token data when REST call succeeds', async () => {
        const expectedData = { id_token: 'id', access_token: 'access' };
        restFetchMock.mockResolvedValue({ data: expectedData, error: null });

        const result = await exchangeCodeForGoogleIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(restFetchMock).toHaveBeenCalledWith(
            'https://oauth2.googleapis.com/token',
            expect.objectContaining({
                body: expect.objectContaining(payload),
                form: true
            })
        );
        expect(result).toEqual({ data: expectedData, error: null });
    });

    it('returns upstream error when REST call fails', async () => {
        const apiError = { code: 400, message: 'invalid_grant' };
        restFetchMock.mockResolvedValue({
            data: null,
            error: { error: apiError }
        });

        const result = await exchangeCodeForGoogleIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(result).toEqual({
            data: null,
            error: new Error(
                'Failed to exchange code for ID token: invalid_grant'
            )
        });
    });
});

describe('getToken', () => {
    const serviceAccount = {
        client_email: 'test@project.iam.gserviceaccount.com',
        private_key:
            '-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n',
        token_uri: 'https://oauth2.googleapis.com/token'
    } as any;

    it('requests new token with signed JWT', async () => {
        const fakeFetch = vi.fn();
        const tokenData = { access_token: 'ya29', expires_in: 3600 };
        signJWTMock.mockResolvedValue({ data: 'signed-jwt', error: null });
        restFetchMock.mockResolvedValue({ data: tokenData, error: null });

        const result = await getToken(serviceAccount, fakeFetch);

        expect(signJWTMock).toHaveBeenCalledWith(serviceAccount);
        expect(restFetchMock).toHaveBeenCalledWith(
            'https://oauth2.googleapis.com/token',
            expect.objectContaining({
                global: { fetch: fakeFetch },
                body: {
                    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                    assertion: 'signed-jwt'
                },
                headers: expect.objectContaining({
                    'Cache-Control': 'no-cache',
                    Host: 'oauth2.googleapis.com'
                }),
                form: true
            })
        );
        expect(result).toEqual({ data: tokenData, error: null });
    });

    it('short-circuits when signJWT returns error', async () => {
        const jwtError = { code: 401, message: 'bad cert', errors: [] };
        signJWTMock.mockResolvedValue({ data: null, error: jwtError });

        const result = await getToken(serviceAccount);

        expect(restFetchMock).not.toHaveBeenCalled();
        expect(result).toEqual({
            data: null,
            error: new Error('Failed to sign JWT: bad cert')
        });
    });

    it('reports missing JWT data', async () => {
        signJWTMock.mockResolvedValue({ data: null, error: null });

        const result = await getToken(serviceAccount);

        expect(result).toEqual({
            data: null,
            error: new Error('No JWT data returned')
        });
    });

    it('returns REST error payload from Google', async () => {
        const apiError = { code: 503, message: 'unavailable' };
        signJWTMock.mockResolvedValue({ data: 'signed-jwt', error: null });
        restFetchMock.mockResolvedValue({
            data: null,
            error: { error: apiError }
        });

        const result = await getToken(serviceAccount);

        expect(result).toEqual({
            data: null,
            error: new Error('Failed to get token: unavailable')
        });
    });

    it('handles unexpected exceptions', async () => {
        signJWTMock.mockResolvedValue({ data: 'signed-jwt', error: null });
        restFetchMock.mockRejectedValue(new Error('boom'));

        const result = await getToken(serviceAccount);

        expect(result).toEqual({
            data: null,
            error: new Error('Failed to get token: boom')
        });
    });
});
