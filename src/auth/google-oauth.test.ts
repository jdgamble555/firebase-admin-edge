import { describe, expect, it, beforeEach, vi } from 'vitest';
import { exchangeCodeForGoogleIdToken, getToken } from './google-oauth.js';
import type { ServiceAccount } from './firebase-types.js';
import { FirebaseEdgeError } from './errors.js';
import { GoogleErrorInfo } from './auth-error-codes.js';

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

describe('Google OAuth Token Exchange', () => {
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

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/google-invalid-grant');
        expect(result.error?.message).toBe(
            GoogleErrorInfo.GOOGLE_INVALID_GRANT.message
        );
    });

    it('handles invalid client error', async () => {
        const apiError = { code: 401, message: 'invalid_client' };
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

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/google-invalid-client');
        expect(result.error?.message).toBe(
            GoogleErrorInfo.GOOGLE_INVALID_CLIENT.message
        );
    });

    it('handles invalid request error', async () => {
        const apiError = { code: 400, message: 'invalid_request' };
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

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/google-invalid-request');
        expect(result.error?.message).toBe(
            GoogleErrorInfo.GOOGLE_INVALID_REQUEST.message
        );
    });

    it('handles access denied error', async () => {
        const apiError = { code: 403, message: 'access_denied' };
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

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/google-access-denied');
        expect(result.error?.message).toBe(
            GoogleErrorInfo.GOOGLE_ACCESS_DENIED.message
        );
    });

    it('handles unrecognized error with default fallback', async () => {
        const apiError = { code: 500, message: 'unknown_error' };
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

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/google-code-exchange-failed');
        expect(result.error?.message).toBe(
            GoogleErrorInfo.GOOGLE_CODE_EXCHANGE_FAILED.message
        );
    });

    it('includes error context in FirebaseEdgeError', async () => {
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

        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        const firebaseError = result.error as FirebaseEdgeError;
        expect(firebaseError.context).toEqual({
            originalError: 'invalid_grant'
        });
    });
});

describe('getToken', () => {
    const serviceAccount = {
        client_email: 'test@project.iam.gserviceaccount.com',
        private_key:
            '-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n',
        token_uri: 'https://oauth2.googleapis.com/token'
    } as ServiceAccount;

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
        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/jwt-sign-failed');
        expect(result.error?.message).toBe(
            GoogleErrorInfo.JWT_SIGN_FAILED.message
        );
    });

    it('reports missing JWT data', async () => {
        signJWTMock.mockResolvedValue({ data: null, error: null });

        const result = await getToken(serviceAccount);

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/jwt-data-missing');
        expect(result.error?.message).toBe(
            GoogleErrorInfo.JWT_DATA_MISSING.message
        );
    });

    it('returns REST error payload from Google', async () => {
        const apiError = { code: 503, message: 'unavailable' };
        signJWTMock.mockResolvedValue({ data: 'signed-jwt', error: null });
        restFetchMock.mockResolvedValue({
            data: null,
            error: { error: apiError }
        });

        const result = await getToken(serviceAccount);

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/google-temporarily-unavailable');
        expect(result.error?.message).toBe(
            GoogleErrorInfo.GOOGLE_TEMPORARILY_UNAVAILABLE.message
        );
    });

    it('handles unexpected exceptions', async () => {
        signJWTMock.mockResolvedValue({ data: 'signed-jwt', error: null });
        restFetchMock.mockRejectedValue(new Error('boom'));

        const result = await getToken(serviceAccount);

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/google-token-request-failed');
        expect(result.error?.message).toBe(
            GoogleErrorInfo.GOOGLE_TOKEN_REQUEST_FAILED.message
        );
    });

    it('handles server error with appropriate mapping', async () => {
        const apiError = { code: 500, message: 'Internal server error' };
        signJWTMock.mockResolvedValue({ data: 'signed-jwt', error: null });
        restFetchMock.mockResolvedValue({
            data: null,
            error: { error: apiError }
        });

        const result = await getToken(serviceAccount);

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/google-server-error');
        expect(result.error?.message).toBe(
            GoogleErrorInfo.GOOGLE_SERVER_ERROR.message
        );
    });

    it('includes error context in FirebaseEdgeError', async () => {
        const jwtError = { code: 401, message: 'bad cert', errors: [] };
        signJWTMock.mockResolvedValue({ data: null, error: jwtError });

        const result = await getToken(serviceAccount);

        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        const firebaseError = result.error as FirebaseEdgeError;
        expect(firebaseError.context).toEqual({
            originalError: 'bad cert'
        });
        expect(firebaseError.cause).toBeInstanceOf(Error);
    });
});
