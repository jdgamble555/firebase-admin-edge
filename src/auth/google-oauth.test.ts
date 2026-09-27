import { describe, expect, it, beforeEach, vi } from 'vitest';
import { getToken } from './google-oauth.js';
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

describe('getToken', () => {
    const serviceAccount = {
        client_email: 'test@project.iam.gserviceaccount.com',
        private_key:
            '-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n',
        token_uri: 'https://oauth2.googleapis.com/token'
    } as ServiceAccount;

    it('retains the OAuth failure when service account credentials are rejected', async () => {
        signJWTMock.mockResolvedValue({ data: 'signed-jwt', error: null });
        restFetchMock.mockResolvedValue({
            data: null,
            error: {
                error: 'invalid_grant',
                error_description: 'Invalid JWT Signature.'
            }
        });

        const result = await getToken(serviceAccount);

        expect(result.data).toBeNull();
        expect(result.error?.code).toBe('auth/service-account-token-failed');
        expect(result.error?.context).toEqual({
            originalError: 'invalid_grant: Invalid JWT Signature.'
        });
    });

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
