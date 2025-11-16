import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { FirebaseAdminAuth } from './firebase-admin-auth.js';
import type {
    ServiceAccount,
    GoogleTokenResponse,
    UserRecord,
    FirebaseIdTokenPayload
} from './firebase-types.js';
import {
    getAccountInfoByUid,
    createSessionCookie as createSessionCookieEndpoint
} from './firebase-auth-endpoints.js';
import { getToken } from './google-oauth.js';
import {
    signJWTCustomToken,
    verifyJWT,
    verifySessionJWT
} from './firebase-jwt.js';

vi.mock('./firebase-auth-endpoints.js', () => ({
    getAccountInfoByUid: vi.fn(),
    createSessionCookie: vi.fn()
}));

vi.mock('./firebase-jwt.js', () => ({
    signJWTCustomToken: vi.fn(),
    verifyJWT: vi.fn(),
    verifySessionJWT: vi.fn()
}));

vi.mock('./google-oauth.js', () => ({
    getToken: vi.fn()
}));

const mockedGetToken = vi.mocked(getToken);
const mockedGetAccountInfoByUid = vi.mocked(getAccountInfoByUid);
const mockedCreateSessionCookieEndpoint = vi.mocked(
    createSessionCookieEndpoint
);
const mockedVerifyJWT = vi.mocked(verifyJWT);
const mockedVerifySessionJWT = vi.mocked(verifySessionJWT);
const mockedSignJWTCustomToken = vi.mocked(signJWTCustomToken);
const serviceAccountKey: ServiceAccount = {
    type: 'service_account',
    project_id: 'test-project',
    private_key_id: 'test-private-key-id',
    private_key: 'test-private-key',
    client_email: 'test@test-project.iam.gserviceaccount.com',
    client_id: 'test-client-id',
    auth_uri: 'https://accounts.google.com/o/oauth2/auth',
    token_uri: 'https://oauth2.googleapis.com/token',
    auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
    client_x509_cert_url:
        'https://www.googleapis.com/robot/v1/metadata/x509/test%40test-project.iam.gserviceaccount.com'
};

// Proper mock data that matches the expected types
const mockGoogleTokenResponse: GoogleTokenResponse = {
    access_token: 'test-access-token',
    expires_in: 3600,
    scope: 'scope',
    token_type: 'Bearer',
    id_token: 'test-id-token'
};

const mockUserRecord: UserRecord = {
    uid: 'uid-1',
    email: 'test@example.com',
    emailVerified: true,
    disabled: false,
    metadata: {
        creationTime: new Date().toISOString(),
        lastSignInTime: new Date().toISOString()
    },
    providerData: []
};

const mockFirebasePayload: FirebaseIdTokenPayload = {
    iss: 'https://securetoken.google.com/test-project',
    aud: 'test-project',
    auth_time: 1000,
    user_id: 'uid-1',
    sub: 'uid-1',
    iat: 1000,
    exp: 2000,
    email: 'test@example.com',
    email_verified: true,
    firebase: {
        identities: {
            email: ['test@example.com']
        },
        sign_in_provider: 'password'
    }
};

describe('FirebaseAdminAuth', () => {
    let auth: FirebaseAdminAuth;

    beforeEach(() => {
        auth = new FirebaseAdminAuth(serviceAccountKey);
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.resetAllMocks();
    });

    describe('getUser', () => {
        it('returns error when getToken returns an error', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: null,
                error: { code: 401, message: 'unauthorized', errors: [] }
            });

            const result = await auth.getUser('uid-1');

            expect(mockedGetToken).toHaveBeenCalled();
            expect(result.data).toBeNull();
            expect(result.error).toEqual({
                code: 401,
                message: 'unauthorized',
                errors: []
            });
        });

        it('returns error when getToken does not return a token', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: null,
                error: null
            });

            const result = await auth.getUser('uid-1');

            expect(result.data).toBeNull();
            expect(result.error).toEqual({
                code: 500,
                message: 'No token returned',
                errors: []
            });
        });

        it('returns user when everything succeeds', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });

            mockedGetAccountInfoByUid.mockResolvedValueOnce({
                data: mockUserRecord,
                error: null
            });

            const result = await auth.getUser('uid-1');

            expect(mockedGetToken).toHaveBeenCalledWith(
                serviceAccountKey,
                undefined
            );
            expect(mockedGetAccountInfoByUid).toHaveBeenCalledWith(
                'uid-1',
                'test-access-token',
                'test-project',
                undefined
            );
            expect(result.data).toEqual(mockUserRecord);
            expect(result.error).toBeNull();
        });

        it('returns error when getAccountInfoByUid fails', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });

            const error = { code: 404, message: 'not found', errors: [] };
            mockedGetAccountInfoByUid.mockResolvedValueOnce({
                data: null,
                error
            });

            const result = await auth.getUser('uid-1');

            expect(result.data).toBeNull();
            expect(result.error).toEqual(error);
        });
    });

    describe('verifyIdToken', () => {
        it('returns error when verifyJWT fails', async () => {
            mockedVerifyJWT.mockResolvedValueOnce({
                data: null,
                error: new Error('bad token')
            });

            const result = await auth.verifyIdToken('id-token');

            expect(mockedVerifyJWT).toHaveBeenCalledWith(
                'id-token',
                'test-project',
                undefined
            );
            expect(result.data).toBeNull();
            expect(result.error).toEqual(new Error('bad token'));
        });

        it('returns decoded token when not checking revoked', async () => {
            mockedVerifyJWT.mockResolvedValueOnce({
                data: mockFirebasePayload,
                error: null
            });

            const result = await auth.verifyIdToken('id-token', false);

            expect(result.data).toEqual(mockFirebasePayload);
            expect(result.error).toBeNull();
        });

        it('returns error when user lookup fails during revoked check', async () => {
            mockedVerifyJWT.mockResolvedValueOnce({
                data: mockFirebasePayload,
                error: null
            });

            const userError = { code: 500, message: 'fail', errors: [] };
            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });
            mockedGetAccountInfoByUid.mockResolvedValueOnce({
                data: null,
                error: userError
            });

            const result = await auth.verifyIdToken('id-token', true);

            expect(result.data).toBeNull();
            expect(result.error).toEqual(userError);
        });

        it('returns ERR_NO_USER when user is null during revoked check', async () => {
            mockedVerifyJWT.mockResolvedValueOnce({
                data: mockFirebasePayload,
                error: null
            });

            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });
            mockedGetAccountInfoByUid.mockResolvedValueOnce({
                data: null,
                error: null
            });

            const result = await auth.verifyIdToken('id-token', true);

            expect(result.data).toBeNull();
            expect(result.error).toEqual({
                message: 'No user record found!',
                code: 'ERR_NO_USER'
            });
        });

        it('returns ERR_USER_DISABLED when user.disabled is true', async () => {
            mockedVerifyJWT.mockResolvedValueOnce({
                data: mockFirebasePayload,
                error: null
            });

            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });
            mockedGetAccountInfoByUid.mockResolvedValueOnce({
                data: { ...mockUserRecord, disabled: true },
                error: null
            });

            const result = await auth.verifyIdToken('id-token', true);

            expect(result.data).toBeNull();
            expect(result.error).toEqual({
                message: 'User is disabled!',
                code: 'ERR_USER_DISABLED'
            });
        });

        it('returns ERR_TOKEN_REVOKED when auth_time < tokensValidAfterTime', async () => {
            mockedVerifyJWT.mockResolvedValueOnce({
                data: mockFirebasePayload,
                error: null
            });

            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });

            // tokensValidAfterTime far in the future compared to auth_time
            mockedGetAccountInfoByUid.mockResolvedValueOnce({
                data: {
                    ...mockUserRecord,
                    disabled: false,
                    tokensValidAfterTime: new Date(2000000 * 1000).toISOString()
                },
                error: null
            });

            const result = await auth.verifyIdToken('id-token', true);

            expect(result.data).toBeNull();
            expect(result.error).toEqual({
                message: 'Token has been revoked!',
                code: 'ERR_TOKEN_REVOKED'
            });
        });

        it('returns decoded token when not revoked', async () => {
            const mockPayloadWithLaterAuthTime = {
                ...mockFirebasePayload,
                auth_time: 2000
            };
            mockedVerifyJWT.mockResolvedValueOnce({
                data: mockPayloadWithLaterAuthTime,
                error: null
            });

            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });
            mockedGetAccountInfoByUid.mockResolvedValueOnce({
                data: {
                    ...mockUserRecord,
                    disabled: false,
                    tokensValidAfterTime: new Date(1000 * 1000).toISOString()
                },
                error: null
            });

            const result = await auth.verifyIdToken('id-token', true);

            expect(result.data).toEqual(mockPayloadWithLaterAuthTime);
            expect(result.error).toBeNull();
        });
    });

    describe('createSessionCookie', () => {
        it('returns error when getToken fails', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: null,
                error: { code: 401, message: 'unauthorized', errors: [] }
            });

            const result = await auth.createSessionCookie('id-token', {
                expiresIn: 3600
            });

            expect(result.data).toBeNull();
            expect(result.error).toEqual({
                code: 401,
                message: 'unauthorized',
                errors: []
            });
        });

        it('returns error when token is missing', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: null,
                error: null
            });

            const result = await auth.createSessionCookie('id-token', {
                expiresIn: 3600
            });

            expect(result.data).toBeNull();
            expect(result.error).toEqual({
                code: 500,
                message: 'No token returned',
                errors: []
            });
        });

        it('returns error when endpoint returns error', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });

            const endpointError = {
                code: 400,
                message: 'bad request',
                errors: []
            };
            mockedCreateSessionCookieEndpoint.mockResolvedValueOnce({
                data: null,
                error: endpointError
            });

            const result = await auth.createSessionCookie('id-token', {
                expiresIn: 3600
            });

            expect(mockedCreateSessionCookieEndpoint).toHaveBeenCalledWith(
                'id-token',
                'test-access-token',
                'test-project',
                3600,
                undefined
            );
            expect(result.data).toBeNull();
            expect(result.error).toEqual(endpointError);
        });

        it('returns session cookie data on success', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });

            const cookieData = 'cookie-value';
            mockedCreateSessionCookieEndpoint.mockResolvedValueOnce({
                data: cookieData,
                error: null
            });

            const result = await auth.createSessionCookie('id-token', {
                expiresIn: 3600
            });

            expect(result.data).toEqual(cookieData);
            expect(result.error).toBeNull();
        });
    });

    describe('verifySessionCookie', () => {
        it('returns error when verifySessionJWT fails', async () => {
            mockedVerifySessionJWT.mockResolvedValueOnce({
                data: null,
                error: new Error('bad session token')
            });

            const result = await auth.verifySessionCookie('session-cookie');

            expect(result.data).toBeNull();
            expect(result.error).toEqual(new Error('bad session token'));
        });

        it('returns data when not checking revoked', async () => {
            mockedVerifySessionJWT.mockResolvedValueOnce({
                data: mockFirebasePayload,
                error: null
            });

            const result = await auth.verifySessionCookie(
                'session-cookie',
                false
            );

            expect(result.data).toEqual(mockFirebasePayload);
            expect(result.error).toBeNull();
        });

        it('returns error when user lookup fails during revoked check', async () => {
            mockedVerifySessionJWT.mockResolvedValueOnce({
                data: mockFirebasePayload,
                error: null
            });

            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });
            const error = { code: 500, message: 'fail', errors: [] };
            mockedGetAccountInfoByUid.mockResolvedValueOnce({
                data: null,
                error
            });

            const result = await auth.verifySessionCookie(
                'session-cookie',
                true
            );

            expect(result.data).toBeNull();
            expect(result.error).toEqual(error);
        });

        it('returns ERR_NO_USER when user is null during revoked check', async () => {
            mockedVerifySessionJWT.mockResolvedValueOnce({
                data: mockFirebasePayload,
                error: null
            });

            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });
            mockedGetAccountInfoByUid.mockResolvedValueOnce({
                data: null,
                error: null
            });

            const result = await auth.verifySessionCookie(
                'session-cookie',
                true
            );

            expect(result.data).toBeNull();
            expect(result.error).toEqual({
                message: 'No user record found!',
                code: 'ERR_NO_USER'
            });
        });

        it('returns decoded data when revoked check passes', async () => {
            mockedVerifySessionJWT.mockResolvedValueOnce({
                data: mockFirebasePayload,
                error: null
            });

            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });
            mockedGetAccountInfoByUid.mockResolvedValueOnce({
                data: mockUserRecord,
                error: null
            });

            const result = await auth.verifySessionCookie(
                'session-cookie',
                true
            );

            expect(result.data).toEqual(mockFirebasePayload);
            expect(result.error).toBeNull();
        });
    });

    describe('createCustomToken', () => {
        it('returns error when signJWTCustomToken fails', async () => {
            mockedSignJWTCustomToken.mockResolvedValueOnce({
                data: null,
                error: new Error('sign failed')
            });

            const result = await auth.createCustomToken('uid-1');

            expect(mockedSignJWTCustomToken).toHaveBeenCalledWith(
                'uid-1',
                serviceAccountKey,
                {}
            );
            expect(result.data).toBeNull();
            expect(result.error).toEqual(new Error('sign failed'));
        });

        it('returns error when no data is returned', async () => {
            mockedSignJWTCustomToken.mockResolvedValueOnce({
                data: null,
                error: new Error('No custom token returned')
            });

            const result = await auth.createCustomToken('uid-1');

            expect(result.data).toBeNull();
            expect(result.error).toEqual(new Error('No custom token returned'));
        });

        it('returns token when successful', async () => {
            mockedSignJWTCustomToken.mockResolvedValueOnce({
                data: 'custom-token',
                error: null
            });

            const claims = { role: 'admin' };
            const result = await auth.createCustomToken('uid-1', claims);

            expect(mockedSignJWTCustomToken).toHaveBeenCalledWith(
                'uid-1',
                serviceAccountKey,
                claims
            );
            expect(result.data).toBe('custom-token');
            expect(result.error).toBeNull();
        });
    });
});
