import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { FirebaseAdminAuth } from './firebase-admin-auth.js';
import type {
    ServiceAccount,
    GoogleTokenResponse,
    FirebaseIdTokenPayload,
    UserInfo
} from './firebase-types.js';
import {
    generateEmailActionLink,
    deleteAccountsAdmin,
    importAccountsAdmin,
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
    generateEmailActionLink: vi.fn(),
    deleteAccountsAdmin: vi.fn(),
    importAccountsAdmin: vi.fn(),
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

    describe('getUserByProviderUid', () => {
        it.each([
            [
                'google.com',
                'google-123',
                {
                    federatedUserId: [
                        { providerId: 'google.com', rawId: 'google-123' }
                    ]
                }
            ],
            ['email', 'test@example.com', { email: ['test@example.com'] }],
            ['phone', '+15551234567', { phoneNumber: ['+15551234567'] }]
        ] as const)(
            'looks up %s using the existing batch helper',
            async (providerId, uid, request) => {
                const fetchFn = vi.fn();
                const admin = new FirebaseAdminAuth(
                    serviceAccountKey,
                    'tenant',
                    fetchFn
                );
                mockedGetToken.mockResolvedValue({
                    data: mockGoogleTokenResponse,
                    error: null
                });
                vi.mocked(getAccountsInfo).mockResolvedValue({
                    data: {
                        users: [
                            {
                                ...mockUserRecord,
                                phoneNumber: '+15551234567',
                                providerUserInfo: [
                                    {
                                        providerId: 'google.com',
                                        rawId: 'google-123'
                                    }
                                ]
                            }
                        ]
                    },
                    error: null
                });
                const result = await admin.getUserByProviderUid(
                    providerId,
                    uid
                );
                expect(result.error).toBeNull();
                expect(result.data?.uid).toBe('uid-1');
                expect(result.data?.toJSON()).toMatchObject({ uid: 'uid-1' });
                expect(getAccountsInfo).toHaveBeenCalledWith(
                    request,
                    'test-access-token',
                    'test-project',
                    'tenant',
                    fetchFn
                );
            }
        );
        it('returns user-not-found for an unmatched provider UID', async () => {
            vi.spyOn(auth, 'getUsers').mockResolvedValue({
                data: {
                    users: [],
                    notFound: [
                        { providerId: 'google.com', providerUid: 'missing' }
                    ]
                },
                error: null
            });
            expect(
                (await auth.getUserByProviderUid('google.com', 'missing')).error
                    ?.code
            ).toBe(FirebaseAdminAuthErrorInfo.ADMIN_USER_NOT_FOUND.code);
        });
        it.each([
            ['', 'uid'],
            ['google.com', ''],
            [null, 'uid'],
            ['google.com', null],
            ['email', 'invalid'],
            ['phone', 'invalid']
        ])(
            'rejects invalid identifiers %s/%s before authentication',
            async (providerId, uid) => {
                expect(
                    (
                        await auth.getUserByProviderUid(
                            providerId as string,
                            uid as string
                        )
                    ).error
                ).toBeInstanceOf(FirebaseEdgeError);
                expect(mockedGetToken).not.toHaveBeenCalled();
            }
        );
        it('preserves lookup failures', async () => {
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_LOOKUP_FAILED
            );
            vi.spyOn(auth, 'getUsers').mockResolvedValue({ data: null, error });
            expect(
                await auth.getUserByProviderUid('google.com', 'uid')
            ).toEqual({ data: null, error });
        });
    });

    describe('generateVerifyAndChangeEmailLink', () => {
        it.each([undefined, { url: 'https://example.com/account' }])(
            'generates a link with settings %j',
            async (settings) => {
                const fetchFn = vi.fn();
                const admin = new FirebaseAdminAuth(
                    serviceAccountKey,
                    'tenant',
                    fetchFn
                );
                mockedGetToken.mockResolvedValue({
                    data: mockGoogleTokenResponse,
                    error: null
                });
                vi.mocked(generateEmailActionLink).mockResolvedValue({
                    data: 'https://example.com/action',
                    error: null
                });
                expect(
                    await admin.generateVerifyAndChangeEmailLink(
                        'old@example.com',
                        'new@example.com',
                        settings
                    )
                ).toEqual({ data: 'https://example.com/action', error: null });
                expect(generateEmailActionLink).toHaveBeenCalledWith(
                    'test-project',
                    {
                        requestType: 'VERIFY_AND_CHANGE_EMAIL',
                        email: 'old@example.com',
                        newEmail: 'new@example.com',
                        returnOobLink: true,
                        ...(settings
                            ? {
                                  continueUrl: settings.url,
                                  canHandleCodeInApp: false
                              }
                            : {})
                    },
                    'test-access-token',
                    fetchFn,
                    'tenant'
                );
            }
        );
        it.each([
            ['invalid', 'new@example.com'],
            ['old@example.com', 'invalid'],
            ['old@example.com', undefined]
        ])('rejects invalid addresses %s/%s', async (email, newEmail) => {
            const result = await auth.generateVerifyAndChangeEmailLink(
                email!,
                newEmail as string
            );
            expect(result.error?.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT.code
            );
            expect(mockedGetToken).not.toHaveBeenCalled();
        });
        it('returns credential errors without requesting a link', async () => {
            mockedGetToken.mockResolvedValue({
                data: null,
                error: new Error('credentials')
            });
            expect(
                (
                    await auth.generateVerifyAndChangeEmailLink(
                        'old@example.com',
                        'new@example.com'
                    )
                ).error?.code
            ).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
                    .code
            );
            expect(generateEmailActionLink).not.toHaveBeenCalled();
        });
        it('wraps endpoint failures with their cause', async () => {
            const cause = new Error('email already exists');
            mockedGetToken.mockResolvedValue({
                data: mockGoogleTokenResponse,
                error: null
            });
            vi.mocked(generateEmailActionLink).mockResolvedValue({
                data: null,
                error: cause
            });
            const result = await auth.generateVerifyAndChangeEmailLink(
                'old@example.com',
                'new@example.com'
            );
            expect(result.error?.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_EMAIL_ACTION_LINK_FAILED.code
            );
            expect(result.error?.cause).toBe(cause);
        });
    });

    describe('setCustomUserClaims', () => {
        beforeEach(() => {
            mockedGetToken.mockResolvedValue({
                data: mockGoogleTokenResponse,
                error: null
            });
            vi.mocked(updateAccountAdmin).mockResolvedValue({
                data: { localId: 'uid' },
                error: null
            });
        });
        it('uses the existing update helper with tenant and custom fetch', async () => {
            const customFetch = vi.fn<typeof fetch>();
            const instance = new FirebaseAdminAuth(
                serviceAccountKey,
                'tenant',
                customFetch
            );
            expect(
                await instance.setCustomUserClaims('uid', { role: 'editor' })
            ).toEqual({ data: undefined, error: null });
            expect(updateAccountAdmin).toHaveBeenCalledExactlyOnceWith(
                'test-project',
                'uid',
                { customAttributes: '{"role":"editor"}' },
                'test-access-token',
                customFetch,
                'tenant'
            );
            expect(getAccountInfo).not.toHaveBeenCalled();
        });
        it('clears claims with null', async () => {
            expect(
                (await auth.setCustomUserClaims('uid', null)).error
            ).toBeNull();
            expect(updateAccountAdmin).toHaveBeenCalledWith(
                'test-project',
                'uid',
                { customAttributes: '{}' },
                'test-access-token',
                undefined,
                undefined
            );
        });
        it('validates UID and claims before authentication', async () => {
            expect(
                (await auth.setCustomUserClaims('', {})).error
            ).not.toBeNull();
            expect(
                (await auth.setCustomUserClaims('a'.repeat(129), {})).error
            ).not.toBeNull();
            expect(
                (await auth.setCustomUserClaims('uid', { sub: 'reserved' }))
                    .error
            ).not.toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(updateAccountAdmin).not.toHaveBeenCalled();
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
                (await instance.setCustomUserClaims('uid', {})).error
            ).toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
        });
        it('returns credential failures without updating', async () => {
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
            );
            mockedGetToken.mockResolvedValue({ data: null, error });
            expect(await auth.setCustomUserClaims('uid', {})).toEqual({
                data: null,
                error
            });
            expect(updateAccountAdmin).not.toHaveBeenCalled();
        });
        it('guards against missing access tokens', async () => {
            mockedGetToken.mockResolvedValue({
                data: {} as GoogleTokenResponse,
                error: null
            });
            expect(
                (await auth.setCustomUserClaims('uid', {})).error?.code
            ).toBe('auth/admin-no-token-returned');
            expect(updateAccountAdmin).not.toHaveBeenCalled();
        });
        it('preserves endpoint errors including user-not-found', async () => {
            const cause = new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_USER_NOT_FOUND
            );
            vi.mocked(updateAccountAdmin).mockResolvedValue({
                data: null,
                error: cause
            });
            const result = await auth.setCustomUserClaims('missing', {});
            expect(result.data).toBeNull();
            expect(result.error?.code).toBe(
                'auth/admin-set-custom-claims-failed'
            );
            expect(result.error?.cause).toBe(cause);
        });
        it('rejects missing confirmation data', async () => {
            vi.mocked(updateAccountAdmin).mockResolvedValue({
                data: { localId: '' },
                error: null
            });
            expect(
                (await auth.setCustomUserClaims('uid', {})).error?.code
            ).toBe('auth/admin-set-custom-claims-failed');
        });
        it('returns network and credential exceptions instead of rejecting', async () => {
            const cause = new Error('offline');
            vi.mocked(updateAccountAdmin).mockRejectedValue(cause);
            expect(
                (await auth.setCustomUserClaims('uid', {})).error?.cause
            ).toBe(cause);
            mockedGetToken.mockRejectedValue('token failure');
            expect(
                (await auth.setCustomUserClaims('uid', {})).error?.cause
            ).toBeInstanceOf(Error);
        });
    });

    describe('phone lookup and bulk user management', () => {
        beforeEach(() => {
            mockedGetToken.mockResolvedValue({
                data: mockGoogleTokenResponse,
                error: null
            });
            mockedGetAccountInfo.mockResolvedValue({
                data: mockUserRecord,
                error: null
            });
            vi.mocked(deleteAccountsAdmin).mockResolvedValue({
                data: {},
                error: null
            });
            vi.mocked(importAccountsAdmin).mockResolvedValue({
                data: {},
                error: null
            });
        });
        it('looks up a phone number and returns a converted user record', async () => {
            const customFetch = vi.fn<typeof fetch>();
            const instance = new FirebaseAdminAuth(
                serviceAccountKey,
                'tenant',
                customFetch
            );
            const result = await instance.getUserByPhoneNumber('+15555550100');
            expect(result.error).toBeNull();
            expect(result.data?.uid).toBe('uid-1');
            expect(result.data?.toJSON()).toMatchObject({ uid: 'uid-1' });
            expect(getAccountInfo).toHaveBeenCalledWith(
                { phoneNumber: '+15555550100' },
                'test-access-token',
                'test-project',
                'tenant',
                customFetch
            );
        });
        it('returns user-not-found when no phone match exists', async () => {
            mockedGetAccountInfo.mockResolvedValue({ data: null, error: null });
            expect(
                (await auth.getUserByPhoneNumber('+15555550100')).error?.code
            ).toBe('auth/admin-user-not-found');
        });
        it.each(['', '555', null, 1])(
            'rejects invalid phone number %s before authentication',
            async (phone) => {
                expect(
                    (await auth.getUserByPhoneNumber(phone as string)).error
                ).toBeInstanceOf(FirebaseEdgeError);
                expect(mockedGetToken).not.toHaveBeenCalled();
            }
        );
        it('deletes a batch with tenant, custom fetch, counts, and indexed errors', async () => {
            const customFetch = vi.fn<typeof fetch>();
            const instance = new FirebaseAdminAuth(
                serviceAccountKey,
                'tenant',
                customFetch
            );
            vi.mocked(deleteAccountsAdmin).mockResolvedValue({
                data: { errors: [{ index: 1, message: 'failure' }] },
                error: null
            });
            const result = await instance.deleteUsers([
                'one',
                'two',
                'missing'
            ]);
            expect(result.error).toBeNull();
            expect(result.data).toMatchObject({
                successCount: 2,
                failureCount: 1,
                errors: [{ index: 1, error: { message: 'failure' } }]
            });
            expect(deleteAccountsAdmin).toHaveBeenCalledWith(
                'test-project',
                ['one', 'two', 'missing'],
                'test-access-token',
                customFetch,
                'tenant'
            );
        });
        it('returns empty delete and import results without network requests', async () => {
            const result = {
                data: { successCount: 0, failureCount: 0, errors: [] },
                error: null
            };
            expect(await auth.deleteUsers([])).toEqual(result);
            expect(await auth.importUsers([])).toEqual(result);
            expect(mockedGetToken).not.toHaveBeenCalled();
        });
        it('rejects invalid delete batches and oversized imports before authentication', async () => {
            expect((await auth.deleteUsers(['one', ''])).error).not.toBeNull();
            expect(
                (await auth.deleteUsers(Array(1001).fill('uid'))).error
            ).not.toBeNull();
            expect(
                (await auth.importUsers(Array(1001).fill({ uid: 'uid' }))).error
            ).not.toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
        });
        it('merges local and server import failures using original indices', async () => {
            const customFetch = vi.fn<typeof fetch>();
            const instance = new FirebaseAdminAuth(
                serviceAccountKey,
                'tenant',
                customFetch
            );
            vi.mocked(importAccountsAdmin).mockResolvedValue({
                data: { error: [{ index: 1, message: 'DUPLICATE_LOCAL_ID' }] },
                error: null
            });
            const result = await instance.importUsers([
                { uid: '' },
                { uid: 'one' },
                { uid: 'two' }
            ]);
            expect(result.error).toBeNull();
            expect(result.data).toMatchObject({
                successCount: 1,
                failureCount: 2,
                errors: [{ index: 0 }, { index: 2 }]
            });
            expect(importAccountsAdmin).toHaveBeenCalledWith(
                'test-project',
                { users: [{ localId: 'one' }, { localId: 'two' }] },
                'test-access-token',
                customFetch,
                'tenant'
            );
        });
        it('returns all-invalid imports locally and rejects missing password settings', async () => {
            expect(await auth.importUsers([{ uid: '' }])).toMatchObject({
                data: { successCount: 0, failureCount: 1 },
                error: null
            });
            expect(
                (
                    await auth.importUsers([
                        { uid: 'uid', passwordHash: new Uint8Array([1]) }
                    ])
                ).error
            ).not.toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(importAccountsAdmin).not.toHaveBeenCalled();
        });
        it('sends the selected hashing configuration with password imports', async () => {
            await auth.importUsers(
                [{ uid: 'uid', passwordHash: new Uint8Array([1]) }],
                { hash: { algorithm: 'BCRYPT' } }
            );
            expect(importAccountsAdmin).toHaveBeenCalledWith(
                'test-project',
                {
                    users: [{ localId: 'uid', passwordHash: 'AQ==' }],
                    hashAlgorithm: 'BCRYPT'
                },
                'test-access-token',
                undefined,
                undefined
            );
        });
        it('uses cached credentials for all three methods', async () => {
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
                (await instance.getUserByPhoneNumber('+15555550100')).error
            ).toBeNull();
            expect((await instance.deleteUsers(['uid'])).error).toBeNull();
            expect(
                (await instance.importUsers([{ uid: 'uid' }])).error
            ).toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
        });
        const operations = [
            {
                name: 'phone',
                run: () => auth.getUserByPhoneNumber('+15555550100'),
                endpoint: vi.mocked(getAccountInfo)
            },
            {
                name: 'delete',
                run: () => auth.deleteUsers(['uid']),
                endpoint: vi.mocked(deleteAccountsAdmin)
            },
            {
                name: 'import',
                run: () => auth.importUsers([{ uid: 'uid' }]),
                endpoint: vi.mocked(importAccountsAdmin)
            }
        ];
        describe.each(operations)('$name failures', ({ run, endpoint }) => {
            it('propagates token failures without calling the endpoint', async () => {
                const error = new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
                );
                mockedGetToken.mockResolvedValue({ data: null, error });
                expect(await run()).toEqual({ data: null, error });
                expect(endpoint).not.toHaveBeenCalled();
            });
            it('guards against a missing access token', async () => {
                mockedGetToken.mockResolvedValue({
                    data: {} as GoogleTokenResponse,
                    error: null
                });
                expect((await run()).error?.code).toBe(
                    'auth/admin-no-token-returned'
                );
                expect(endpoint).not.toHaveBeenCalled();
            });
            it('returns endpoint errors and network exceptions', async () => {
                const error = new FirebaseEdgeError(
                    FirebaseEndpointErrorInfo.ENDPOINT_PERMISSION_DENIED
                );
                endpoint.mockResolvedValue({ data: null, error });
                expect(await run()).toMatchObject({
                    data: null,
                    error: expect.any(FirebaseEdgeError)
                });
                endpoint.mockRejectedValue(new Error('offline'));
                expect(await run()).toMatchObject({
                    data: null,
                    error: expect.any(FirebaseEdgeError)
                });
            });
        });
        it('returns errors for corrupt bulk responses instead of misleading counts', async () => {
            vi.mocked(deleteAccountsAdmin).mockResolvedValue({
                data: { errors: [{ index: 5 }] },
                error: null
            });
            vi.mocked(importAccountsAdmin).mockResolvedValue({
                data: { error: [{ index: 5 }] },
                error: null
            });
            expect((await auth.deleteUsers(['uid'])).error).not.toBeNull();
            expect(
                (await auth.importUsers([{ uid: 'uid' }])).error
            ).not.toBeNull();
        });
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

    describe.each([
        ['generatePasswordResetLink', 'PASSWORD_RESET'],
        ['generateEmailVerificationLink', 'VERIFY_EMAIL'],
        ['generateSignInWithEmailLink', 'EMAIL_SIGNIN']
    ] as const)('%s', (method, requestType) => {
        const settings = {
            url: 'https://example.com/finish',
            handleCodeInApp: true
        };
        it('returns the generated link and forwards credentials, settings, tenant and fetch', async () => {
            const fetchFn = vi.fn();
            const admin = new FirebaseAdminAuth(
                serviceAccountKey,
                'tenant',
                fetchFn
            );
            mockedGetToken.mockResolvedValue({
                data: mockGoogleTokenResponse,
                error: null
            });
            vi.mocked(generateEmailActionLink).mockResolvedValue({
                data: 'https://example.com/action',
                error: null
            });
            expect(await admin[method]('person@example.com', settings)).toEqual(
                { data: 'https://example.com/action', error: null }
            );
            expect(generateEmailActionLink).toHaveBeenCalledWith(
                'test-project',
                {
                    requestType,
                    email: 'person@example.com',
                    returnOobLink: true,
                    continueUrl: settings.url,
                    canHandleCodeInApp: true
                },
                'test-access-token',
                fetchFn,
                'tenant'
            );
        });
        it('rejects invalid input before obtaining credentials', async () => {
            expect((await auth[method]('invalid', settings)).error?.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT.code
            );
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(generateEmailActionLink).not.toHaveBeenCalled();
        });
        it('returns authentication errors without calling the endpoint', async () => {
            mockedGetToken.mockResolvedValue({
                data: null,
                error: new Error('credentials')
            });
            expect(
                (await auth[method]('person@example.com', settings)).error?.code
            ).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
                    .code
            );
            expect(generateEmailActionLink).not.toHaveBeenCalled();
        });
        it('wraps endpoint errors and preserves the cause', async () => {
            const cause = new Error('email not found');
            mockedGetToken.mockResolvedValue({
                data: mockGoogleTokenResponse,
                error: null
            });
            vi.mocked(generateEmailActionLink).mockResolvedValue({
                data: null,
                error: cause
            });
            const result = await auth[method]('person@example.com', settings);
            expect(result.error?.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_EMAIL_ACTION_LINK_FAILED.code
            );
            expect(result.error?.cause).toBe(cause);
        });
        it('returns unexpected failures using the package error convention', async () => {
            mockedGetToken.mockResolvedValue({
                data: mockGoogleTokenResponse,
                error: null
            });
            vi.mocked(generateEmailActionLink).mockRejectedValue(
                new Error('network')
            );
            expect(
                (await auth[method]('person@example.com', settings)).error?.code
            ).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_EMAIL_ACTION_LINK_FAILED.code
            );
        });
    });

    it.each([
        'generatePasswordResetLink',
        'generateEmailVerificationLink'
    ] as const)('%s allows omitted settings', async (method) => {
        mockedGetToken.mockResolvedValue({
            data: mockGoogleTokenResponse,
            error: null
        });
        vi.mocked(generateEmailActionLink).mockResolvedValue({
            data: 'https://example.com/action',
            error: null
        });
        expect((await auth[method]('person@example.com')).error).toBeNull();
        expect(generateEmailActionLink).toHaveBeenCalledWith(
            'test-project',
            expect.not.objectContaining({ continueUrl: expect.anything() }),
            'test-access-token',
            undefined,
            undefined
        );
    });

    it('requires settings when generating an email sign-in link', async () => {
        const result =
            // @ts-expect-error Settings are required for email sign-in.
            await auth.generateSignInWithEmailLink('person@example.com');
        expect(result.error?.code).toBe(
            FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT.code
        );
        expect(mockedGetToken).not.toHaveBeenCalled();
    });

    it.each([
        'generatePasswordResetLink',
        'generateEmailVerificationLink',
        'generateSignInWithEmailLink',
        'createSessionCookie'
    ] as const)('%s rejects missing access tokens', async (method) => {
        mockedGetToken.mockResolvedValue({
            data: { ...mockGoogleTokenResponse, access_token: '' },
            error: null
        });
        const result =
            method === 'createSessionCookie'
                ? await auth.createSessionCookie('id-token', {
                      expiresIn: 300000
                  })
                : await auth[method]('person@example.com', {
                      url: 'https://example.com'
                  });
        expect(result.error?.code).toBe(
            FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED.code
        );
        expect(generateEmailActionLink).not.toHaveBeenCalled();
        expect(mockedCreateSessionCookieEndpoint).not.toHaveBeenCalled();
    });

    describe('createSessionCookie', () => {
        it.each([
            undefined,
            null,
            3600000,
            {},
            { expiresIn: '3600000' },
            { expiresIn: NaN },
            { expiresIn: Infinity },
            { expiresIn: 299999 },
            { expiresIn: 1209600001 }
        ])(
            'rejects invalid options %j before authentication',
            async (options) => {
                const result = await auth.createSessionCookie(
                    'id-token',
                    options as { expiresIn: number }
                );
                expect(result.error?.code).toBe(
                    FirebaseAdminAuthErrorInfo
                        .ADMIN_SESSION_COOKIE_DURATION_INVALID.code
                );
                expect(mockedGetToken).not.toHaveBeenCalled();
            }
        );
        it.each(['', null, 1])(
            'rejects invalid ID token %s',
            async (idToken) => {
                const result = await auth.createSessionCookie(
                    idToken as string,
                    { expiresIn: 300000 }
                );
                expect(result.error?.code).toBe(
                    FirebaseAdminAuthErrorInfo.ADMIN_ID_TOKEN_INVALID.code
                );
                expect(mockedGetToken).not.toHaveBeenCalled();
            }
        );
        it.each([300000, 1209600000])(
            'accepts boundary lifetime %s and forwards tenant and fetch',
            async (expiresIn) => {
                const fetchFn = vi.fn();
                const admin = new FirebaseAdminAuth(
                    serviceAccountKey,
                    'tenant',
                    fetchFn
                );
                mockedGetToken.mockResolvedValue({
                    data: mockGoogleTokenResponse,
                    error: null
                });
                mockedCreateSessionCookieEndpoint.mockResolvedValue({
                    data: 'cookie',
                    error: null
                });
                expect(
                    await admin.createSessionCookie('id-token', { expiresIn })
                ).toEqual({ data: 'cookie', error: null });
                expect(mockedCreateSessionCookieEndpoint).toHaveBeenCalledWith(
                    'id-token',
                    'test-access-token',
                    'test-project',
                    expiresIn,
                    'tenant',
                    fetchFn
                );
            }
        );
        it('returns an error for an empty cookie response', async () => {
            mockedGetToken.mockResolvedValue({
                data: mockGoogleTokenResponse,
                error: null
            });
            mockedCreateSessionCookieEndpoint.mockResolvedValue({
                data: null,
                error: null
            });
            const result = await auth.createSessionCookie('id-token', {
                expiresIn: 300000
            });
            expect(result.error?.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_CREATE_FAILED
                    .code
            );
        });
        it('wraps unexpected endpoint failures', async () => {
            mockedGetToken.mockResolvedValue({
                data: mockGoogleTokenResponse,
                error: null
            });
            mockedCreateSessionCookieEndpoint.mockRejectedValue(
                new Error('network')
            );
            const result = await auth.createSessionCookie('id-token', {
                expiresIn: 300000
            });
            expect(result.error?.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_CREATE_FAILED
                    .code
            );
        });
        it('returns error when getToken fails', async () => {
            mockedGetToken.mockResolvedValueOnce({
                data: null,
                error: new Error('unauthorized')
            });

            const result = await auth.createSessionCookie('id-token', {
                expiresIn: 3600000
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
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
                )
            });

            const result = await auth.createSessionCookie('id-token', {
                expiresIn: 3600000
            });

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

            const result = await auth.createSessionCookie('id-token', {
                expiresIn: 3600000
            });

            expect(mockedCreateSessionCookieEndpoint).toHaveBeenCalledWith(
                'id-token',
                'test-access-token',
                'test-project',
                3600000,
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
                expiresIn: 3600000
            });

            expect(result.data).toEqual(cookieData);
            expect(result.error).toBeNull();
        });
    });

    describe('verifySessionCookie', () => {
        it('rejects disabled users when revocation checking is enabled', async () => {
            mockedVerifySessionJWT.mockResolvedValue({
                data: mockFirebasePayload,
                error: null
            });
            vi.spyOn(auth, 'getUser').mockResolvedValue({
                data: { ...mockUserRecord, disabled: true },
                error: null
            });
            expect(
                (await auth.verifySessionCookie('cookie', true)).error?.code
            ).toBe(FirebaseAdminAuthErrorInfo.ADMIN_USER_DISABLED.code);
        });
        it.each([
            [
                '1001',
                FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_REVOKED.code
            ],
            ['1000', undefined],
            ['999', undefined],
            [undefined, undefined]
        ])(
            'checks auth_time against validSince %s, not issuance time',
            async (validSince, expectedCode) => {
                mockedVerifySessionJWT.mockResolvedValue({
                    data: { ...mockFirebasePayload, iat: 1500 },
                    error: null
                });
                vi.spyOn(auth, 'getUser').mockResolvedValue({
                    data: { ...mockUserRecord, validSince },
                    error: null
                });
                const result = await auth.verifySessionCookie('cookie', true);
                expect(result.error?.code).toBe(expectedCode);
                expect(result.data === null).toBe(Boolean(expectedCode));
            }
        );
        it('skips the user lookup by default', async () => {
            mockedVerifySessionJWT.mockResolvedValue({
                data: mockFirebasePayload,
                error: null
            });
            const lookup = vi.spyOn(auth, 'getUser');
            expect(await auth.verifySessionCookie('cookie')).toEqual({
                data: mockFirebasePayload,
                error: null
            });
            expect(lookup).not.toHaveBeenCalled();
        });
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
