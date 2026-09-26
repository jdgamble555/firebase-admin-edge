import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { FirebaseAdminAuth } from './firebase-admin-auth.js';
import type {
    ServiceAccount,
    GoogleTokenResponse,
    FirebaseIdTokenPayload,
    UserInfo
} from './firebase-types.js';
import {
    getAccountsInfo,
    createAccountAdmin,
    updateAccountAdmin,
    deleteAccountAdmin,
    downloadAccount,
    getAccountInfo,
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
    getAccountsInfo: vi.fn(),
    createAccountAdmin: vi.fn(),
    updateAccountAdmin: vi.fn(),
    deleteAccountAdmin: vi.fn(),
    downloadAccount: vi.fn(),
    getAccountInfo: vi.fn(),
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
const mockedGetAccountInfo = vi.mocked(getAccountInfo);
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

const mockUserRecord: UserInfo = {
    localId: 'uid-1',
    email: 'test@example.com',
    emailVerified: true,
    disabled: false
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

    describe('getUsers', () => {
        beforeEach(() => {
            mockedGetToken.mockResolvedValue({
                data: mockGoogleTokenResponse,
                error: null
            });
            vi.mocked(getAccountsInfo).mockResolvedValue({
                data: {},
                error: null
            });
        });
        it('returns records and unmatched identifiers using one batch request', async () => {
            const customFetch = vi.fn<typeof fetch>();
            const instance = new FirebaseAdminAuth(
                serviceAccountKey,
                'tenant',
                customFetch
            );
            const ids = [{ uid: 'uid' }, { email: 'missing@example.com' }];
            vi.mocked(getAccountsInfo).mockResolvedValue({
                data: { users: [{ localId: 'uid' }] },
                error: null
            });
            const { data, error } = await instance.getUsers(ids);
            expect(error).toBeNull();
            expect(data?.users[0]?.uid).toBe('uid');
            expect(data?.notFound).toEqual([ids[1]]);
            expect(getAccountsInfo).toHaveBeenCalledExactlyOnceWith(
                { localId: ['uid'], email: ['missing@example.com'] },
                'test-access-token',
                'test-project',
                'tenant',
                customFetch
            );
        });
        it('returns an empty batch without authentication or requests', async () => {
            expect(await auth.getUsers([])).toEqual({
                data: { users: [], notFound: [] },
                error: null
            });
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(getAccountsInfo).not.toHaveBeenCalled();
        });
        it('rejects invalid inputs before authentication', async () => {
            expect((await auth.getUsers([{ uid: '' }])).error).toBeInstanceOf(
                FirebaseEdgeError
            );
            expect(
                (await auth.getUsers(Array(101).fill({ uid: 'uid' }))).error
            ).toBeInstanceOf(FirebaseEdgeError);
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(getAccountsInfo).not.toHaveBeenCalled();
        });
        it('returns all identifiers in notFound when there are no matches', async () => {
            expect(await auth.getUsers([{ uid: 'missing' }])).toEqual({
                data: { users: [], notFound: [{ uid: 'missing' }] },
                error: null
            });
        });
        it('uses cached credentials', async () => {
            const cache = {
                getCache: vi.fn().mockResolvedValue(mockGoogleTokenResponse),
                setCache: vi.fn()
            };
            const instance = new FirebaseAdminAuth(
                serviceAccountKey,
                undefined,
                undefined,
                cache
            );
            expect(
                (await instance.getUsers([{ uid: 'uid' }])).error
            ).toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(getAccountsInfo).toHaveBeenCalledTimes(1);
        });
        it('returns credential failures without a lookup', async () => {
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
            );
            mockedGetToken.mockResolvedValue({ data: null, error });
            expect(await auth.getUsers([{ uid: 'uid' }])).toEqual({
                data: null,
                error
            });
            expect(getAccountsInfo).not.toHaveBeenCalled();
        });
        it('guards against missing access tokens', async () => {
            mockedGetToken.mockResolvedValue({
                data: {} as GoogleTokenResponse,
                error: null
            });
            expect((await auth.getUsers([{ uid: 'uid' }])).error?.code).toBe(
                'auth/admin-no-token-returned'
            );
            expect(getAccountsInfo).not.toHaveBeenCalled();
        });
        it('retains mapped endpoint failures as the cause', async () => {
            const cause = new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_PERMISSION_DENIED
            );
            vi.mocked(getAccountsInfo).mockResolvedValue({
                data: null,
                error: cause
            });
            const result = await auth.getUsers([{ uid: 'uid' }]);
            expect(result.data).toBeNull();
            expect(result.error?.cause).toBe(cause);
        });
        it.each([null, 'not JSON', { users: [{}] }, { users: 'invalid' }])(
            'returns structured errors for malformed responses %j',
            async (data) => {
                vi.mocked(getAccountsInfo).mockResolvedValue({
                    data,
                    error: null
                } as Awaited<ReturnType<typeof getAccountsInfo>>);
                const result = await auth.getUsers([{ uid: 'uid' }]);
                expect(result.data).toBeNull();
                expect(result.error?.code).toBe(
                    'auth/admin-user-lookup-failed'
                );
            }
        );
        it('returns network and token exceptions rather than rejecting', async () => {
            vi.mocked(getAccountsInfo).mockRejectedValue(new Error('offline'));
            expect(
                (await auth.getUsers([{ uid: 'uid' }])).error?.cause
            ).toBeInstanceOf(Error);
            mockedGetToken.mockRejectedValue('token failure');
            expect(
                (await auth.getUsers([{ uid: 'uid' }])).error?.cause
            ).toBeInstanceOf(Error);
        });
    });

    describe('user management', () => {
        beforeEach(() => {
            mockedGetToken.mockResolvedValue({
                data: mockGoogleTokenResponse,
                error: null
            });
            mockedGetAccountInfo.mockResolvedValue({
                data: mockUserRecord,
                error: null
            });
            vi.mocked(createAccountAdmin).mockResolvedValue({
                data: { localId: 'uid-1' },
                error: null
            });
            vi.mocked(updateAccountAdmin).mockResolvedValue({
                data: { localId: 'uid-1' },
                error: null
            });
            vi.mocked(deleteAccountAdmin).mockResolvedValue({ error: null });
        });

        it('creates a user and reads the full record with the same credentials', async () => {
            const customFetch = vi.fn<typeof fetch>();
            const instance = new FirebaseAdminAuth(
                serviceAccountKey,
                'tenant',
                customFetch
            );
            const result = await instance.createUser({
                email: 'test@example.com',
                photoURL: 'https://example.com/photo',
                disabled: false
            });
            expect(result.error).toBeNull();
            expect(result.data?.uid).toBe('uid-1');
            expect(result.data?.toJSON()).toMatchObject({
                uid: 'uid-1',
                email: 'test@example.com'
            });
            expect(createAccountAdmin).toHaveBeenCalledWith(
                'test-project',
                {
                    email: 'test@example.com',
                    photoUrl: 'https://example.com/photo',
                    disabled: false
                },
                'test-access-token',
                customFetch,
                'tenant'
            );
            expect(mockedGetAccountInfo).toHaveBeenCalledWith(
                { uid: 'uid-1' },
                'test-access-token',
                'test-project',
                'tenant',
                customFetch
            );
            expect(mockedGetToken).toHaveBeenCalledTimes(1);
        });

        it('updates through the existing endpoint with translated fields and tenant', async () => {
            const result = await authWithTenant.updateUser('uid-1', {
                displayName: null,
                photoURL: null,
                phoneNumber: null,
                disabled: true
            });
            expect(result.error).toBeNull();
            expect(result.data?.uid).toBe('uid-1');
            expect(updateAccountAdmin).toHaveBeenCalledWith(
                'test-project',
                'uid-1',
                {
                    deleteAttribute: ['DISPLAY_NAME', 'PHOTO_URL'],
                    deleteProvider: ['phone'],
                    disableUser: true
                },
                'test-access-token',
                undefined,
                'test-tenant-id'
            );
            expect(mockedGetAccountInfo).toHaveBeenCalledWith(
                { uid: 'uid-1' },
                'test-access-token',
                'test-project',
                'test-tenant-id',
                undefined
            );
        });

        it('deletes without a follow-up lookup and returns void data', async () => {
            expect(await authWithTenant.deleteUser('uid-1')).toEqual({
                data: undefined,
                error: null
            });
            expect(deleteAccountAdmin).toHaveBeenCalledWith(
                'test-project',
                'uid-1',
                'test-access-token',
                undefined,
                'test-tenant-id'
            );
            expect(mockedGetAccountInfo).not.toHaveBeenCalled();
        });

        it.each(['', 'a'.repeat(129), null])(
            'rejects invalid UID %s before authentication',
            async (uid) => {
                expect(
                    (await auth.updateUser(uid as string, {})).error
                ).toBeInstanceOf(FirebaseEdgeError);
                expect(
                    (await auth.deleteUser(uid as string)).error
                ).toBeInstanceOf(FirebaseEdgeError);
                expect(mockedGetToken).not.toHaveBeenCalled();
            }
        );

        it('rejects invalid create and update properties before authentication', async () => {
            expect(
                (await auth.createUser({ email: 'invalid' })).error
            ).toBeInstanceOf(FirebaseEdgeError);
            expect(
                (await auth.updateUser('uid', { password: 'short' })).error
            ).toBeInstanceOf(FirebaseEdgeError);
            expect(mockedGetToken).not.toHaveBeenCalled();
        });

        const operations = [
            {
                name: 'create',
                run: () => auth.createUser({}),
                endpoint: vi.mocked(createAccountAdmin)
            },
            {
                name: 'update',
                run: () => auth.updateUser('uid-1', {}),
                endpoint: vi.mocked(updateAccountAdmin)
            },
            {
                name: 'delete',
                run: () => auth.deleteUser('uid-1'),
                endpoint: vi.mocked(deleteAccountAdmin)
            }
        ];
        describe.each(operations)('$name errors', ({ name, run, endpoint }) => {
            it('returns credential errors without a write', async () => {
                const error = new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
                );
                mockedGetToken.mockResolvedValue({ data: null, error });
                expect(await run()).toEqual({ data: null, error });
                expect(endpoint).not.toHaveBeenCalled();
            });
            it('guards against missing credentials', async () => {
                mockedGetToken.mockResolvedValue({
                    data: {} as GoogleTokenResponse,
                    error: null
                });
                expect((await run()).error?.code).toBe(
                    'auth/admin-no-token-returned'
                );
                expect(endpoint).not.toHaveBeenCalled();
            });
            it('preserves API errors as the cause without a readback', async () => {
                const cause = new FirebaseEdgeError(
                    FirebaseEndpointErrorInfo.ENDPOINT_USER_NOT_FOUND
                );
                endpoint.mockResolvedValue({ data: null, error: cause });
                const result = await run();
                expect(result.data).toBeNull();
                expect(result.error?.code).toBe(
                    `auth/admin-${name}-user-failed`
                );
                expect(result.error?.cause).toBe(cause);
                expect(mockedGetAccountInfo).not.toHaveBeenCalled();
            });
            it('returns transport exceptions instead of rejecting', async () => {
                const cause = new Error('offline');
                endpoint.mockRejectedValue(cause);
                const result = await run();
                expect(result.data).toBeNull();
                expect(result.error?.cause).toBe(cause);
            });
            it('returns unexpected token exceptions', async () => {
                mockedGetToken.mockRejectedValue('token failure');
                const result = await run();
                expect(result.data).toBeNull();
                expect(result.error?.code).toBe(
                    `auth/admin-${name}-user-failed`
                );
            });
        });

        describe.each(operations.slice(0, 2))(
            '$name readback',
            ({ run, endpoint }) => {
                it('requires a UID in the write response', async () => {
                    endpoint.mockResolvedValue({
                        data: { localId: '' },
                        error: null
                    });
                    expect((await run()).error).toBeInstanceOf(
                        FirebaseEdgeError
                    );
                    expect(mockedGetAccountInfo).not.toHaveBeenCalled();
                });
                it('returns lookup errors', async () => {
                    const error = new FirebaseEdgeError(
                        FirebaseEndpointErrorInfo.ENDPOINT_USER_NOT_FOUND
                    );
                    mockedGetAccountInfo.mockResolvedValue({
                        data: null,
                        error
                    });
                    expect(await run()).toEqual({ data: null, error });
                });
                it('handles a missing user in the lookup response', async () => {
                    mockedGetAccountInfo.mockResolvedValue({
                        data: null,
                        error: null
                    });
                    expect((await run()).error?.code).toBe(
                        'auth/admin-user-record-not-found'
                    );
                });
                it('returns conversion errors rather than rejecting', async () => {
                    mockedGetAccountInfo.mockResolvedValue({
                        data: { localId: 'uid', customAttributes: '{' },
                        error: null
                    });
                    expect((await run()).error).toBeInstanceOf(
                        FirebaseEdgeError
                    );
                });
            }
        );
    });

    describe('listUsers', () => {
        const download = vi.mocked(downloadAccount);

        beforeEach(() => {
            mockedGetToken.mockResolvedValue({
                data: mockGoogleTokenResponse,
                error: null
            });
            download.mockResolvedValue({ data: {}, error: null });
        });

        it('requests the default page and converts the result', async () => {
            download.mockResolvedValue({
                data: { users: [{ localId: 'uid' }], nextPageToken: 'next' },
                error: null
            });
            const { data, error } = await auth.listUsers();
            expect(error).toBeNull();
            expect(data?.pageToken).toBe('next');
            expect(data?.users[0]).toMatchObject({
                uid: 'uid',
                emailVerified: false,
                disabled: false
            });
            expect(download).toHaveBeenCalledExactlyOnceWith(
                'test-access-token',
                'test-project',
                1000,
                undefined,
                undefined,
                undefined
            );
        });

        it('forwards pagination, tenant, and custom fetch to the endpoint', async () => {
            const customFetch = vi.fn<typeof fetch>();
            const instance = new FirebaseAdminAuth(
                serviceAccountKey,
                'tenant',
                customFetch
            );
            expect(await instance.listUsers(25, 'opaque+/=')).toEqual({
                data: { users: [] },
                error: null
            });
            expect(download).toHaveBeenCalledExactlyOnceWith(
                'test-access-token',
                'test-project',
                25,
                'opaque+/=',
                'tenant',
                customFetch
            );
            expect(mockedGetToken).toHaveBeenCalledWith(
                serviceAccountKey,
                customFetch
            );
        });

        it('defaults an undefined page size and omits an absent page token', async () => {
            expect(await auth.listUsers(undefined)).toEqual({
                data: { users: [] },
                error: null
            });
        });

        it('preserves an explicitly returned empty page token', async () => {
            download.mockResolvedValue({
                data: { nextPageToken: '' },
                error: null
            });
            expect(await auth.listUsers()).toEqual({
                data: { users: [], pageToken: '' },
                error: null
            });
        });

        it.each([0, -1, 1001, 1.5, NaN, Infinity, null, '10'])(
            'rejects invalid page size %s before authentication',
            async (size) => {
                const result = await auth.listUsers(size as number);
                expect(result.data).toBeNull();
                expect(result.error?.code).toBe(
                    'auth/admin-api-invalid-argument'
                );
                expect(mockedGetToken).not.toHaveBeenCalled();
                expect(download).not.toHaveBeenCalled();
            }
        );

        it.each(['', null, 123, {}])(
            'rejects invalid page token %s before authentication',
            async (pageToken) => {
                const result = await auth.listUsers(25, pageToken as string);
                expect(result.data).toBeNull();
                expect(result.error?.code).toBe(
                    'auth/admin-invalid-page-token'
                );
                expect(mockedGetToken).not.toHaveBeenCalled();
                expect(download).not.toHaveBeenCalled();
            }
        );

        it('returns authentication errors without calling the endpoint', async () => {
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
            );
            mockedGetToken.mockResolvedValue({ data: null, error });
            expect(await auth.listUsers()).toEqual({ data: null, error });
            expect(download).not.toHaveBeenCalled();
        });

        it('uses cached credentials', async () => {
            const cache = {
                getCache: vi.fn().mockResolvedValue(mockGoogleTokenResponse),
                setCache: vi.fn()
            };
            const instance = new FirebaseAdminAuth(
                serviceAccountKey,
                undefined,
                undefined,
                cache
            );
            expect((await instance.listUsers()).error).toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(cache.getCache).toHaveBeenCalledWith('__cache');
            expect(download).toHaveBeenCalledWith(
                'test-access-token',
                'test-project',
                1000,
                undefined,
                undefined,
                undefined
            );
        });

        it('guards against a missing access token', async () => {
            mockedGetToken.mockResolvedValue({
                data: {} as GoogleTokenResponse,
                error: null
            });
            expect((await auth.listUsers()).error?.code).toBe(
                'auth/admin-no-token-returned'
            );
            expect(download).not.toHaveBeenCalled();
        });

        it('retains a mapped endpoint error as its cause', async () => {
            const cause = new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_PERMISSION_DENIED
            );
            download.mockResolvedValue({ data: null, error: cause });
            const result = await auth.listUsers();
            expect(result.data).toBeNull();
            expect(result.error?.code).toBe('auth/admin-list-users-failed');
            expect(result.error?.cause).toBe(cause);
        });

        it.each([
            null,
            'not JSON',
            { users: [{ localId: 'uid', customAttributes: '{' }] },
            { users: [{}] },
            { users: 'invalid' }
        ])('returns an error for invalid endpoint data %j', async (data) => {
            download.mockResolvedValue({ data, error: null } as Awaited<
                ReturnType<typeof downloadAccount>
            >);
            const result = await auth.listUsers();
            expect(result.data).toBeNull();
            expect(result.error?.code).toBe('auth/admin-list-users-failed');
        });

        it('returns unexpected endpoint failures rather than rejecting', async () => {
            const cause = new Error('offline');
            download.mockRejectedValue(cause);
            const result = await auth.listUsers();
            expect(result.data).toBeNull();
            expect(result.error?.cause).toBe(cause);
        });

        it('normalizes unexpected authentication failures', async () => {
            mockedGetToken.mockRejectedValue('token failure');
            const result = await auth.listUsers();
            expect(result.data).toBeNull();
            expect(result.error?.cause).toBeInstanceOf(Error);
        });
    });

    describe('getUser', () => {
        it('returns error when getToken returns an error', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
                )
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
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
                )
            });

            const result = await auth.getUser('uid-1');

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error!.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
                    .code
            );
        });

        it('returns user when everything succeeds', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: mockGoogleTokenResponse,
                error: null
            });

            mockedGetAccountInfo.mockResolvedValueOnce({
                data: mockUserRecord,
                error: null
            });

            const result = await auth.getUser('uid-1');

            expect(mockedGetToken).toHaveBeenCalledWith(
                serviceAccountKey,
                undefined
            );
            expect(mockedGetAccountInfo).toHaveBeenCalledWith(
                { uid: 'uid-1' },
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
            mockedGetAccountInfo.mockResolvedValueOnce({
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
            mockedGetAccountInfo.mockResolvedValueOnce({
                data: null,
                error: userError
            });

            const result = await auth.verifyIdToken('id-token', true);

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error!.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_LOOKUP_FAILED.code
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
            mockedGetAccountInfo.mockResolvedValueOnce({
                data: null,
                error: null
            });

            const result = await auth.verifyIdToken('id-token', true);

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error!.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_RECORD_NOT_FOUND.code
            );
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
            mockedGetAccountInfo.mockResolvedValueOnce({
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
            mockedGetAccountInfo.mockResolvedValueOnce({
                data: {
                    ...mockUserRecord,
                    disabled: false,
                    validSince: '2000000'
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
            mockedGetAccountInfo.mockResolvedValueOnce({
                data: {
                    ...mockUserRecord,
                    disabled: false,
                    validSince: '1000'
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
                FirebaseAdminAuthErrorInfo.ADMIN_TENANT_ID_INVALID.code
            );
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

            const result = await auth.createSessionCookie('id-token', 3600);

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
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
                )
            });

            const result = await auth.createSessionCookie('id-token', 3600);

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error!.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
                    .code
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

            const result = await auth.createSessionCookie('id-token', 3600);

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

            const result = await auth.createSessionCookie('id-token', 3600);

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
            mockedGetAccountInfo.mockResolvedValueOnce({
                data: null,
                error
            });

            const result = await auth.verifySessionCookie(
                'session-cookie',
                true
            );

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error!.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_LOOKUP_FAILED.code
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
            mockedGetAccountInfo.mockResolvedValueOnce({
                data: null,
                error: null
            });

            const result = await auth.verifySessionCookie(
                'session-cookie',
                true
            );

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error!.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_RECORD_NOT_FOUND.code
            );
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
            mockedGetAccountInfo.mockResolvedValueOnce({
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
                FirebaseAdminAuthErrorInfo.ADMIN_TENANT_ID_INVALID.code
            );
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
