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
import {
    FirebaseEdgeError,
    FirebaseAdminAuthErrorInfo,
    FirebaseEndpointErrorInfo,
    JWTErrorInfo
} from './errors.js';

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
    let authWithTenant: FirebaseAdminAuth;

    beforeEach(() => {
        auth = new FirebaseAdminAuth(serviceAccountKey);
        authWithTenant = new FirebaseAdminAuth(
            serviceAccountKey,
            'test-tenant-id'
        );
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.resetAllMocks();
    });

    describe('getUser', () => {
        it('returns error when getToken returns an error', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: null,
                error: new Error('unauthorized')
            });

            const result = await auth.getUser('uid-1');

            expect(mockedGetToken).toHaveBeenCalled();
            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error!.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
                    .code
            );
        });

        it('returns error when getToken does not return a token', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: null,
                error: null
            });

            const result = await auth.getUser('uid-1');

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error!.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED.code
            );
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
                undefined,
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

            const error = new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_USER_NOT_FOUND
            );
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
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect((result.error as FirebaseEdgeError).code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_ID_TOKEN_VERIFY_FAILED.code
            );
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

            const userError = new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_INTERNAL_ERROR
            );
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
            expect(result.error).toEqual(
                new Error(
                    'Failed to get user: Internal error occurred in Firebase service.'
                )
            );
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
            expect(result.error).toEqual(new Error('No user record found!'));
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
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect((result.error as FirebaseEdgeError).code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_DISABLED.code
            );
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
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect((result.error as FirebaseEdgeError).code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_ID_TOKEN_REVOKED.code
            );
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

        it('returns error when token has no decoded payload', async () => {
            mockedVerifyJWT.mockResolvedValueOnce({
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ID_TOKEN
                )
            });

            const result = await auth.verifyIdToken('id-token');

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect((result.error as FirebaseEdgeError).code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_ID_TOKEN_VERIFY_FAILED.code
            );
        });

        it('returns error when tenant ID does not match', async () => {
            const mockPayloadWithDifferentTenant = {
                ...mockFirebasePayload,
                firebase: {
                    ...mockFirebasePayload.firebase,
                    tenant: 'different-tenant-id'
                }
            };

            mockedVerifyJWT.mockResolvedValueOnce({
                data: mockPayloadWithDifferentTenant,
                error: null
            });

            const result = await authWithTenant.verifyIdToken('id-token');

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect((result.error as FirebaseEdgeError).code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_ID_TOKEN_VERIFY_FAILED.code
            );
            expect((result.error as FirebaseEdgeError).cause).toBeInstanceOf(
                Error
            );
            expect(
                ((result.error as FirebaseEdgeError).cause as Error).message
            ).toContain('does not match');
        });

        it('returns success when tenant ID matches', async () => {
            const mockPayloadWithCorrectTenant = {
                ...mockFirebasePayload,
                firebase: {
                    ...mockFirebasePayload.firebase,
                    tenant: 'test-tenant-id'
                }
            };

            mockedVerifyJWT.mockResolvedValueOnce({
                data: mockPayloadWithCorrectTenant,
                error: null
            });

            const result = await authWithTenant.verifyIdToken(
                'id-token',
                false
            );

            expect(result.data).toEqual(mockPayloadWithCorrectTenant);
            expect(result.error).toBeNull();
        });
    });

    describe('createSessionCookie', () => {
        it('returns error when getToken fails', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: null,
                error: new Error('unauthorized')
            });

            const result = await auth.createSessionCookie('id-token', {
                expiresIn: 3600
            });

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error!.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
                    .code
            );
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
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error!.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED.code
            );
        });

        it('returns error when endpoint returns error', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });

            const endpointError = new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ARGUMENT
            );
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
                undefined,
                undefined
            );
            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect((result.error as FirebaseEdgeError).code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_CREATE_FAILED
                    .code
            );
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
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect((result.error as FirebaseEdgeError).code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_VERIFY_FAILED
                    .code
            );
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
            const error = new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_INTERNAL_ERROR
            );
            mockedGetAccountInfoByUid.mockResolvedValueOnce({
                data: null,
                error
            });

            const result = await auth.verifySessionCookie(
                'session-cookie',
                true
            );

            expect(result.data).toBeNull();
            expect(result.error).toEqual(
                new Error(
                    'Failed to get user: Internal error occurred in Firebase service.'
                )
            );
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
            expect(result.error).toEqual(new Error('No user record found!'));
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

        it('returns error when no decoded data returned', async () => {
            mockedVerifySessionJWT.mockResolvedValueOnce({
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseEndpointErrorInfo.ENDPOINT_INVALID_SESSION_COOKIE
                )
            });

            const result = await auth.verifySessionCookie('session-cookie');

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect((result.error as FirebaseEdgeError).code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_VERIFY_FAILED
                    .code
            );
        });

        it('returns error when tenant ID does not match', async () => {
            const mockPayloadWithDifferentTenant = {
                ...mockFirebasePayload,
                firebase: {
                    ...mockFirebasePayload.firebase,
                    tenant: 'wrong-tenant-id'
                }
            };

            mockedVerifySessionJWT.mockResolvedValueOnce({
                data: mockPayloadWithDifferentTenant,
                error: null
            });

            const result =
                await authWithTenant.verifySessionCookie('session-cookie');

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect((result.error as FirebaseEdgeError).code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_VERIFY_FAILED
                    .code
            );
            expect((result.error as FirebaseEdgeError).cause).toBeInstanceOf(
                Error
            );
            expect(
                ((result.error as FirebaseEdgeError).cause as Error).message
            ).toContain('does not match');
        });

        it('returns success when tenant ID matches', async () => {
            const mockPayloadWithCorrectTenant = {
                ...mockFirebasePayload,
                firebase: {
                    ...mockFirebasePayload.firebase,
                    tenant: 'test-tenant-id'
                }
            };

            mockedVerifySessionJWT.mockResolvedValueOnce({
                data: mockPayloadWithCorrectTenant,
                error: null
            });

            const result = await authWithTenant.verifySessionCookie(
                'session-cookie',
                false
            );

            expect(result.data).toEqual(mockPayloadWithCorrectTenant);
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
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect((result.error as FirebaseEdgeError).code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_CUSTOM_TOKEN_CREATE_FAILED.code
            );
        });

        it('returns error when no data is returned', async () => {
            mockedSignJWTCustomToken.mockResolvedValueOnce({
                data: null,
                error: new FirebaseEdgeError(
                    JWTErrorInfo.JWT_UNKNOWN_SIGNING_ERROR
                )
            });

            const result = await auth.createCustomToken('uid-1');

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect((result.error as FirebaseEdgeError).code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_CUSTOM_TOKEN_CREATE_FAILED.code
            );
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

        it('includes tenant_id claim when tenant is specified', async () => {
            mockedSignJWTCustomToken.mockResolvedValueOnce({
                data: 'custom-token-with-tenant',
                error: null
            });

            const claims = { role: 'admin' };
            const result = await authWithTenant.createCustomToken(
                'uid-1',
                claims
            );

            expect(mockedSignJWTCustomToken).toHaveBeenCalledWith(
                'uid-1',
                serviceAccountKey,
                { ...claims, tenant_id: 'test-tenant-id' }
            );
            expect(result.data).toBe('custom-token-with-tenant');
            expect(result.error).toBeNull();
        });

        it('does not add tenant_id when no tenant specified', async () => {
            mockedSignJWTCustomToken.mockResolvedValueOnce({
                data: 'custom-token',
                error: null
            });

            const claims = { role: 'user' };
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
