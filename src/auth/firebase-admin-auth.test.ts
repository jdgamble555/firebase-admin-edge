import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { FirebaseAdminAuth } from './firebase-admin-auth.js';
import type {
    ServiceAccount,
    GoogleTokenResponse,
    FirebaseIdTokenPayload,
    UserInfo
} from './firebase-types.js';
import {
    countAccounts,
    queryAccounts,
    revokeRefreshTokens,
    manageAuthConfig,
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
    verifyAuthBlockingJWT,
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

vi.mock('./firebase-auth-endpoints.js', async (importOriginal) => {
    const actual =
        await importOriginal<typeof import('./firebase-auth-endpoints.js')>();
    return {
        countAccounts: vi.fn(),
        queryAccounts: vi.fn(),
        createAuthEmulatorFetch: actual.createAuthEmulatorFetch,
        revokeRefreshTokens: vi.fn(),
        manageAuthConfig: vi.fn(),
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
    };
});

vi.mock('./firebase-jwt.js', () => ({
    verifyAuthBlockingJWT: vi.fn(),
    signJWTCustomToken: vi.fn(),
    verifyJWT: vi.fn(),
    verifySessionJWT: vi.fn()
}));

vi.mock('./google-oauth.js', () => ({
    getToken: vi.fn()
}));

const mockedGetToken = vi.mocked(getToken);

describe('Identity count orchestration', () => {
    beforeEach(() => vi.clearAllMocks());

    it('uses cached credentials and forwards the filter, tenant and custom fetch', async () => {
        const fetchFn = vi.fn();
        const cache = {
            getCache: vi.fn().mockResolvedValue(mockGoogleTokenResponse),
            setCache: vi.fn()
        };
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            tenantId: 'tenant',
            fetch: fetchFn,
            cache,
            emulatorHost: null
        });
        vi.mocked(countAccounts).mockResolvedValue({ data: 42, error: null });
        const { error, data } = await auth._countUsers({
            field: 'email',
            value: 'a@example.com'
        });
        expect(error).toBeNull();
        expect(data).toBe(42);
        expect(countAccounts).toHaveBeenCalledExactlyOnceWith(
            mockGoogleTokenResponse.access_token,
            serviceAccountKey.project_id,
            { field: 'email', value: 'a@example.com' },
            'tenant',
            fetchFn
        );
        expect(queryAccounts).not.toHaveBeenCalled();
        expect(getToken).not.toHaveBeenCalled();
    });

    it('stops at token failures or missing tokens', async () => {
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            emulatorHost: null
        });
        const failure = new Error('token failure');
        mockedGetToken.mockResolvedValueOnce({ data: null, error: failure });
        const { error } = await auth._countUsers();
        expect(error).toBe(failure);
        mockedGetToken.mockResolvedValueOnce({
            data: {} as GoogleTokenResponse,
            error: null
        });
        const { error: missing } = await auth._countUsers();
        expect(missing).toBeInstanceOf(FirebaseEdgeError);
        expect(countAccounts).not.toHaveBeenCalled();
    });

    it('uses emulator credentials and preserves endpoint failures', async () => {
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            emulatorHost: 'localhost:9099'
        });
        const failure = new Error('count failure');
        vi.mocked(countAccounts).mockResolvedValueOnce({
            data: null,
            error: failure
        });
        const { error, data } = await auth._countUsers();
        expect(error).toBe(failure);
        expect(data).toBeNull();
        expect(countAccounts).toHaveBeenCalledWith(
            'owner',
            serviceAccountKey.project_id,
            undefined,
            undefined,
            expect.any(Function)
        );
        vi.mocked(countAccounts).mockRejectedValueOnce(failure);
        const { error: thrown } = await auth._countUsers();
        expect(thrown).toBe(failure);
    });
});

describe('Identity query orchestration', () => {
    beforeEach(() => vi.clearAllMocks());

    it('uses cached credentials, forwards tenant and fetch, and converts users', async () => {
        const fetchFn = vi.fn();
        const cache = {
            getCache: vi.fn().mockResolvedValue(mockGoogleTokenResponse),
            setCache: vi.fn()
        };
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            tenantId: 'tenant',
            fetch: fetchFn,
            cache,
            emulatorHost: null
        });
        vi.mocked(queryAccounts).mockResolvedValue({
            data: [
                { localId: 'u', disabled: true, createdAt: '1000' } as UserInfo
            ],
            error: null
        });
        const { error, data } = await auth._queryUsers({ limit: 10 });
        expect(error).toBeNull();
        expect(data?.[0]).toMatchObject({ uid: 'u', disabled: true });
        expect(queryAccounts).toHaveBeenCalledWith(
            mockGoogleTokenResponse.access_token,
            serviceAccountKey.project_id,
            { limit: 10 },
            'tenant',
            fetchFn
        );
        expect(getToken).not.toHaveBeenCalled();
    });

    it('returns token failures and missing-token errors before querying', async () => {
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            emulatorHost: null
        });
        const failure = new Error('token failure');
        mockedGetToken.mockResolvedValueOnce({ data: null, error: failure });
        const { error } = await auth._queryUsers({});
        expect(error).toBe(failure);
        mockedGetToken.mockResolvedValueOnce({
            data: {} as GoogleTokenResponse,
            error: null
        });
        const { error: missing } = await auth._queryUsers({});
        expect(missing).toBeInstanceOf(FirebaseEdgeError);
        expect(queryAccounts).not.toHaveBeenCalled();
    });

    it('uses emulator credentials and returns endpoint failures', async () => {
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            emulatorHost: 'localhost:9099'
        });
        const failure = new Error('query failure');
        vi.mocked(queryAccounts).mockResolvedValueOnce({
            data: null,
            error: failure
        });
        const { error, data } = await auth._queryUsers({});
        expect(error).toBe(failure);
        expect(data).toBeNull();
        expect(queryAccounts).toHaveBeenCalledWith(
            'owner',
            serviceAccountKey.project_id,
            {},
            undefined,
            expect.any(Function)
        );
        vi.mocked(queryAccounts).mockRejectedValueOnce(failure);
        const { error: thrown } = await auth._queryUsers({});
        expect(thrown).toBe(failure);
    });
});

describe('blocking token orchestration', () => {
    beforeEach(() => vi.clearAllMocks());
    it.each([null, 'localhost:9099'])(
        'forwards the captured emulator setting %s and custom audience',
        async (emulatorHost) => {
            const fetchFn = vi.fn();
            const auth = new FirebaseAdminAuth(serviceAccountKey, {
                fetch: fetchFn,
                emulatorHost
            });
            const data = {
                iss: 'issuer',
                aud: 'audience',
                iat: 1,
                exp: 2,
                event_type: 'beforeSignIn',
                event_id: 'event',
                sub: 'user'
            };
            vi.mocked(verifyAuthBlockingJWT).mockResolvedValue({
                data,
                error: null
            });
            const result = await auth._verifyAuthBlockingToken(
                'jwt',
                'run.app'
            );
            expect(result).toEqual({ data, error: null });
            expect(verifyAuthBlockingJWT).toHaveBeenCalledWith(
                'jwt',
                'test-project',
                'run.app',
                emulatorHost ? expect.any(Function) : fetchFn,
                !!emulatorHost
            );
            expect(getToken).not.toHaveBeenCalled();
            expect(getAccountInfo).not.toHaveBeenCalled();
        }
    );

    it.each(['tenant-a', 'other', undefined])(
        'checks the top-level tenant_id (%s)',
        async (tenant_id) => {
            const auth = new FirebaseAdminAuth(serviceAccountKey, {
                emulatorHost: null
            })
                .tenantManager()
                .authForTenant('tenant-a');
            vi.mocked(verifyAuthBlockingJWT).mockResolvedValue({
                data: {
                    iss: 'issuer',
                    aud: 'audience',
                    iat: 1,
                    exp: 2,
                    event_type: 'beforeSendEmail',
                    event_id: 'event',
                    tenant_id
                },
                error: null
            });
            const result = await auth._verifyAuthBlockingToken('jwt');
            if (tenant_id === 'tenant-a') {
                expect(result.error).toBeNull();
                return;
            }
            expect(result.error?.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_TENANT_ID_INVALID.code
            );
        }
    );

    it('preserves verification errors', async () => {
        const error = new FirebaseEdgeError({
            code: 'auth/auth-blocking-token-expired',
            message: 'Expired'
        });
        vi.mocked(verifyAuthBlockingJWT).mockResolvedValue({
            data: null,
            error
        });
        const auth = new FirebaseAdminAuth(serviceAccountKey);
        const result = await auth._verifyAuthBlockingToken('expired');
        expect(result.error).toBe(error);
    });
});

it('isolates Auth tokens across accounts sharing a cache and prefix', async () => {
    vi.clearAllMocks();
    const cached = new Map<string, unknown>();
    const cache = {
        getCache: vi.fn((key: string) => cached.get(key)) as never,
        setCache: vi.fn((key: string, value: unknown) => {
            cached.set(key, value);
        })
    };
    mockedGetToken.mockResolvedValue({
        error: null,
        data: mockGoogleTokenResponse
    });
    vi.mocked(manageAuthConfig).mockResolvedValue({ error: null, data: {} });
    for (const email of [
        'first@example.com',
        'second@example.com',
        'first@example.com'
    ]) {
        const auth = new FirebaseAdminAuth(
            { ...serviceAccountKey, client_email: email },
            { cache, cacheName: 'shared', emulatorHost: null }
        );
        const { error } = await auth.projectConfigManager().getProjectConfig();
        expect(error).toBeNull();
    }
    expect(mockedGetToken).toHaveBeenCalledTimes(2);
    expect([...cached.keys()]).toEqual([
        'shared:auth:first@example.com',
        'shared:auth:second@example.com'
    ]);
});

describe('admin auth emulator', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.stubEnv('FIREBASE_AUTH_EMULATOR_HOST', 'localhost:9099');
        vi.mocked(getAccountInfo).mockResolvedValue({
            data: mockUserRecord,
            error: null
        });
    });
    afterEach(() => vi.unstubAllEnvs());

    it('uses owner credentials without reading or writing the OAuth cache', async () => {
        const cache = {
            getCache: vi.fn().mockResolvedValue(mockGoogleTokenResponse),
            setCache: vi.fn()
        };
        const fetchFn = vi.fn().mockResolvedValue(new Response('{}'));
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            fetch: fetchFn,
            cache
        });
        const result = await auth.getUser('uid-1');
        expect(result.error).toBeNull();
        expect(getToken).not.toHaveBeenCalled();
        expect(cache.getCache).not.toHaveBeenCalled();
        expect(cache.setCache).not.toHaveBeenCalled();
        expect(getAccountInfo).toHaveBeenCalledWith(
            { uid: 'uid-1' },
            'owner',
            'test-project',
            undefined,
            expect.any(Function)
        );
        const transport = vi.mocked(getAccountInfo).mock.calls[0]![4]!;
        await transport(
            'https://identitytoolkit.googleapis.com/v1/projects/test-project/accounts:lookup'
        );
        expect(fetchFn.mock.calls[0]![0]).toBe(
            'http://localhost:9099/identitytoolkit.googleapis.com/v1/projects/test-project/accounts:lookup'
        );
    });

    it('captures emulator settings and propagates them to tenants and configuration operations', async () => {
        const fetchFn = vi.fn().mockResolvedValue(new Response('{}'));
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            fetch: fetchFn
        });
        vi.stubEnv('FIREBASE_AUTH_EMULATOR_HOST', 'other-host:9199');
        const tenant = auth.tenantManager().authForTenant('tenant-a');
        vi.mocked(manageAuthConfig).mockResolvedValue({
            data: {},
            error: null
        });
        await tenant.getProviderConfig('oidc.a');
        await auth.projectConfigManager().getProjectConfig();
        await auth.tenantManager().getTenant('tenant-a');
        for (const call of vi.mocked(manageAuthConfig).mock.calls) {
            expect(call[2]).toBe('owner');
            const transport = call[3]!;
            await transport(
                'https://identitytoolkit.googleapis.com/v2/projects/test-project/config'
            );
            expect(fetchFn).toHaveBeenLastCalledWith(
                'http://localhost:9099/identitytoolkit.googleapis.com/v2/projects/test-project/config',
                expect.any(Object)
            );
        }
        expect(vi.mocked(manageAuthConfig).mock.calls[0]![4]).toBe('tenant-a');
    });

    it('supports explicit production mode alongside an emulator instance', async () => {
        const fetchFn = vi.fn();
        const production = new FirebaseAdminAuth(serviceAccountKey, {
            fetch: fetchFn,
            emulatorHost: null
        });
        vi.mocked(getToken).mockResolvedValue({
            data: mockGoogleTokenResponse,
            error: null
        });
        await production.getUser('uid-1');
        expect(getToken).toHaveBeenCalledWith(serviceAccountKey, fetchFn);
        expect(getAccountInfo).toHaveBeenLastCalledWith(
            { uid: 'uid-1' },
            'test-access-token',
            'test-project',
            undefined,
            fetchFn
        );
        const tenant = production.tenantManager().authForTenant('tenant-a');
        await tenant.getUser('uid-1');
        expect(getAccountInfo).toHaveBeenLastCalledWith(
            { uid: 'uid-1' },
            'test-access-token',
            'test-project',
            'tenant-a',
            fetchFn
        );
    });

    it('passes emulator mode to token helpers and still enforces tenant matching', async () => {
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            tenantId: 'tenant-a'
        });
        vi.mocked(verifyJWT).mockResolvedValue({
            data: {
                ...mockFirebasePayload,
                firebase: { ...mockFirebasePayload.firebase, tenant: 'other' }
            },
            error: null
        });
        vi.mocked(verifySessionJWT).mockResolvedValue({
            data: {
                ...mockFirebasePayload,
                firebase: { ...mockFirebasePayload.firebase, tenant: 'other' }
            },
            error: null
        });
        vi.mocked(signJWTCustomToken).mockResolvedValue({
            data: 'custom',
            error: null
        });
        const id = await auth.verifyIdToken('unsigned');
        const cookie = await auth.verifySessionCookie('unsigned');
        await auth.createCustomToken('user', { role: 'editor' });
        expect(id.error?.code).toBe(
            FirebaseAdminAuthErrorInfo.ADMIN_TENANT_ID_INVALID.code
        );
        expect(cookie.error?.code).toBe(
            FirebaseAdminAuthErrorInfo.ADMIN_TENANT_ID_INVALID.code
        );
        expect(verifyJWT).toHaveBeenCalledWith(
            'unsigned',
            'test-project',
            expect.any(Function),
            true
        );
        expect(verifySessionJWT).toHaveBeenCalledWith(
            'unsigned',
            'test-project',
            expect.any(Function),
            true
        );
        expect(signJWTCustomToken).toHaveBeenCalledWith(
            'user',
            serviceAccountKey,
            { role: 'editor' },
            'tenant-a',
            true
        );
    });

    it.each(['id', 'session'] as const)(
        'still checks disabled users and revocation for %s tokens',
        async (kind) => {
            const auth = new FirebaseAdminAuth(serviceAccountKey);
            vi.mocked(verifyJWT).mockResolvedValue({
                data: mockFirebasePayload,
                error: null
            });
            vi.mocked(verifySessionJWT).mockResolvedValue({
                data: mockFirebasePayload,
                error: null
            });
            vi.mocked(getAccountInfo)
                .mockResolvedValueOnce({
                    data: { ...mockUserRecord, disabled: true },
                    error: null
                })
                .mockResolvedValueOnce({
                    data: {
                        ...mockUserRecord,
                        validSince: String(mockFirebasePayload.auth_time + 1)
                    },
                    error: null
                });
            const verify =
                kind === 'id'
                    ? auth.verifyIdToken.bind(auth)
                    : auth.verifySessionCookie.bind(auth);
            const disabled = await verify('unsigned');
            const revoked = await verify('unsigned');
            expect(disabled.error?.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_DISABLED.code
            );
            expect(revoked.error?.code).toBe(
                kind === 'id'
                    ? FirebaseAdminAuthErrorInfo.ADMIN_ID_TOKEN_REVOKED.code
                    : FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_REVOKED
                          .code
            );
            expect(getToken).not.toHaveBeenCalled();
        }
    );

    it('uses emulator credentials for session creation', async () => {
        vi.mocked(createSessionCookieEndpoint).mockResolvedValue({
            data: 'cookie',
            error: null
        });
        const auth = new FirebaseAdminAuth(serviceAccountKey);
        const result = await auth.createSessionCookie('unsigned-id', {
            expiresIn: 300000
        });
        expect(result.error).toBeNull();
        expect(createSessionCookieEndpoint).toHaveBeenCalledWith(
            'unsigned-id',
            'owner',
            'test-project',
            300000,
            undefined,
            expect.any(Function)
        );
        expect(getToken).not.toHaveBeenCalled();
    });
});

describe('admin configuration orchestration', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.mocked(getToken).mockResolvedValue({
            data: mockGoogleTokenResponse,
            error: null
        });
        vi.mocked(manageAuthConfig).mockResolvedValue({
            data: { providerId: 'oidc.a' },
            error: null
        });
    });

    it('delegates each provider operation with credentials and tenant scope', async () => {
        const customFetch = vi.fn();
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            tenantId: 'tenant-a',
            fetch: customFetch
        });
        const config = {
            providerId: 'oidc.a',
            enabled: true,
            clientId: 'client',
            issuer: 'https://idp.example'
        };
        const created = await auth.createProviderConfig(config);
        const fetched = await auth.getProviderConfig('oidc.a');
        const updated = await auth.updateProviderConfig('oidc.a', {
            enabled: false
        });
        const listed = await auth.listProviderConfigs({
            type: 'oidc',
            maxResults: 10,
            pageToken: 'next'
        });
        const deleted = await auth.deleteProviderConfig('oidc.a');
        for (const result of [created, fetched, updated, listed, deleted])
            expect(result.error).toBeNull();
        expect(
            vi.mocked(manageAuthConfig).mock.calls.map((call) => call[1].action)
        ).toEqual(['create', 'get', 'update', 'list', 'delete']);
        for (const call of vi.mocked(manageAuthConfig).mock.calls) {
            expect(call[0]).toBe('test-project');
            expect(call.slice(2)).toEqual([
                'test-access-token',
                customFetch,
                'tenant-a'
            ]);
        }
    });

    it('rejects invalid inputs before fetching a token', async () => {
        const auth = new FirebaseAdminAuth(serviceAccountKey);
        const results = [
            await auth.createProviderConfig(null as never),
            await auth.getProviderConfig('google.com'),
            await auth.updateProviderConfig('oidc.a', {}),
            await auth.deleteProviderConfig(''),
            await auth.listProviderConfigs({ type: 'saml', maxResults: 101 }),
            await auth.projectConfigManager().updateProjectConfig({}),
            await auth.tenantManager().getTenant(''),
            await auth.tenantManager().listTenants(0)
        ];
        for (const result of results)
            expect(result.error?.code).toBe('auth/invalid-argument');
        expect(getToken).not.toHaveBeenCalled();
        expect(manageAuthConfig).not.toHaveBeenCalled();
    });

    it('caches managers and tenant auth instances and preserves runtime configuration', async () => {
        const fetchFn = vi.fn();
        const cache = {
            getCache: vi.fn().mockResolvedValue(mockGoogleTokenResponse),
            setCache: vi.fn()
        };
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            fetch: fetchFn,
            cache,
            cacheName: 'custom-cache'
        });
        expect(auth.projectConfigManager()).toBe(auth.projectConfigManager());
        expect(auth.tenantManager()).toBe(auth.tenantManager());
        const scoped = auth.tenantManager().authForTenant('t');
        expect(scoped.tenantId).toBe('t');
        expect(scoped).toBe(auth.tenantManager().authForTenant('t'));
        expect(scoped).not.toBe(auth.tenantManager().authForTenant('other'));
        await scoped.getProviderConfig('oidc.a');
        expect(cache.getCache).toHaveBeenCalledWith(
            `custom-cache:auth:${serviceAccountKey.client_email}`
        );
        expect(getToken).not.toHaveBeenCalled();
        expect(manageAuthConfig).toHaveBeenCalledWith(
            'test-project',
            expect.objectContaining({ resource: 'provider' }),
            'test-access-token',
            fetchFn,
            't'
        );
        vi.mocked(getAccountInfo).mockResolvedValue({
            data: mockUserRecord,
            error: null
        });
        await scoped.getUser('uid-1');
        expect(getAccountInfo).toHaveBeenCalledWith(
            { uid: 'uid-1' },
            'test-access-token',
            'test-project',
            't',
            fetchFn
        );
    });

    it('delegates project and tenant manager operations', async () => {
        const auth = new FirebaseAdminAuth(serviceAccountKey);
        await auth.projectConfigManager().getProjectConfig();
        await auth.projectConfigManager().updateProjectConfig({
            emailPrivacyConfig: { enableImprovedEmailPrivacy: true }
        });
        await auth.tenantManager().createTenant({ displayName: 'New' });
        await auth.tenantManager().getTenant('t');
        await auth
            .tenantManager()
            .updateTenant('t', { displayName: 'Changed' });
        await auth.tenantManager().deleteTenant('t');
        await auth.tenantManager().listTenants(10, 'next');
        expect(
            vi
                .mocked(manageAuthConfig)
                .mock.calls.map((call) => [call[1].resource, call[1].action])
        ).toEqual([
            ['project', 'get'],
            ['project', 'update'],
            ['tenant', 'create'],
            ['tenant', 'get'],
            ['tenant', 'update'],
            ['tenant', 'delete'],
            ['tenant', 'list']
        ]);
    });

    it('returns token failures, missing tokens, thrown exceptions, and endpoint errors', async () => {
        const auth = new FirebaseAdminAuth(serviceAccountKey);
        const error = new FirebaseEdgeError({
            message: 'failure',
            code: 'auth/test'
        });
        vi.mocked(getToken)
            .mockResolvedValueOnce({ data: null, error })
            .mockResolvedValueOnce({
                data: { ...mockGoogleTokenResponse, access_token: '' },
                error: null
            })
            .mockRejectedValueOnce(new Error('offline'));
        const tokenFailure = await auth.getProviderConfig('oidc.a');
        const missing = await auth.getProviderConfig('oidc.a');
        const thrown = await auth.getProviderConfig('oidc.a');
        expect(tokenFailure.error).toBe(error);
        expect(missing.error?.code).toBe(
            FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED.code
        );
        expect(thrown.error?.cause).toMatchObject({ message: 'offline' });
        expect(manageAuthConfig).not.toHaveBeenCalled();
        vi.mocked(manageAuthConfig).mockResolvedValueOnce({
            data: null,
            error
        });
        const endpoint = await auth.getProviderConfig('oidc.a');
        expect(endpoint.error).toBe(error);
    });
});
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
        authWithTenant = new FirebaseAdminAuth(serviceAccountKey, {
            tenantId: 'test-tenant-id'
        });
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.resetAllMocks();
    });

    describe('audit regressions', () => {
        it.each(['', '..', 'tenant/other', null])(
            'rejects invalid constructor tenant %j',
            (tenant) => {
                expect(
                    () =>
                        new FirebaseAdminAuth(serviceAccountKey, {
                            tenantId: tenant as string
                        })
                ).toThrow(FirebaseEdgeError);
            }
        );

        it.each([undefined, 'custom-cache'])(
            'reads and writes the same cache key (%s) with millisecond TTL',
            async (cacheName) => {
                let cached: GoogleTokenResponse | undefined;
                const cache = {
                    getCache: vi.fn(() => cached) as never,
                    setCache: vi.fn((_key, value: unknown) => {
                        cached = value as GoogleTokenResponse;
                    })
                };
                const cachedAuth = new FirebaseAdminAuth(serviceAccountKey, {
                    cache,
                    cacheName
                });
                mockedGetToken.mockResolvedValue({
                    data: { ...mockGoogleTokenResponse, expires_in: 1800 },
                    error: null
                });
                mockedGetAccountInfo.mockResolvedValue({
                    data: mockUserRecord,
                    error: null
                });
                await cachedAuth.getUser('uid-1');
                await cachedAuth.getUser('uid-1');
                expect(mockedGetToken).toHaveBeenCalledTimes(1);
                expect(cache.setCache).toHaveBeenCalledWith(
                    `${cacheName ?? '__cache'}:auth:${serviceAccountKey.client_email}`,
                    expect.any(Object),
                    1740000
                );
                expect(cache.getCache).toHaveBeenCalledWith(
                    `${cacheName ?? '__cache'}:auth:${serviceAccountKey.client_email}`
                );
            }
        );

        it.each(['read', 'write'])(
            'returns rejected cache %s operations as structured errors',
            async (phase) => {
                const failure = new Error('Cache unavailable');
                const cache = {
                    getCache: vi
                        .fn()
                        .mockImplementation(() =>
                            phase === 'read'
                                ? Promise.reject(failure)
                                : undefined
                        ),
                    setCache: vi.fn().mockRejectedValue(failure)
                };
                mockedGetToken.mockResolvedValue({
                    data: mockGoogleTokenResponse,
                    error: null
                });
                const cachedAuth = new FirebaseAdminAuth(serviceAccountKey, {
                    cache
                });
                const result = await cachedAuth.getUser('uid-1');
                expect(result.data).toBeNull();
                expect(result.error?.cause).toBe(failure);
                expect(mockedGetAccountInfo).not.toHaveBeenCalled();
            }
        );

        const operations = [
            {
                name: 'getUser',
                run: (instance: FirebaseAdminAuth, value: string) =>
                    instance.getUser(value),
                valid: 'uid-1',
                endpoint: getAccountInfo
            },
            {
                name: 'getUserByEmail',
                run: (instance: FirebaseAdminAuth, value: string) =>
                    instance.getUserByEmail(value),
                valid: 'user@example.com',
                endpoint: getAccountInfo
            },
            {
                name: 'revokeRefreshTokens',
                run: (instance: FirebaseAdminAuth, value: string) =>
                    instance.revokeRefreshTokens(value),
                valid: 'uid-1',
                endpoint: revokeRefreshTokens
            }
        ];
        describe.each(operations)(
            '$name error contract',
            ({ run, valid, endpoint }) => {
                it('validates before obtaining credentials', async () => {
                    const result = await run(auth, '');
                    expect(result.data).toBeNull();
                    expect(result.error).toBeInstanceOf(FirebaseEdgeError);
                    expect(mockedGetToken).not.toHaveBeenCalled();
                });
                it('handles a missing access token', async () => {
                    mockedGetToken.mockResolvedValue({
                        data: { ...mockGoogleTokenResponse, access_token: '' },
                        error: null
                    });
                    const result = await run(auth, valid);
                    expect(result.error?.code).toBe(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED.code
                    );
                    expect(endpoint).not.toHaveBeenCalled();
                });
                it('catches network failures', async () => {
                    mockedGetToken.mockResolvedValue({
                        data: mockGoogleTokenResponse,
                        error: null
                    });
                    const failure = new Error('Network unavailable');
                    vi.mocked(endpoint).mockRejectedValue(failure);
                    const result = await run(auth, valid);
                    expect(result.data).toBeNull();
                    expect(result.error?.cause).toBe(failure);
                });
                it('rejects an empty success response', async () => {
                    mockedGetToken.mockResolvedValue({
                        data: mockGoogleTokenResponse,
                        error: null
                    });
                    vi.mocked(endpoint).mockResolvedValue({
                        data: null,
                        error: null
                    } as never);
                    const result = await run(auth, valid);
                    expect(result.data).toBeNull();
                    expect(result.error).toBeInstanceOf(FirebaseEdgeError);
                });
            }
        );

        it('routes revocation through the tenant endpoint and returns its data', async () => {
            mockedGetToken.mockResolvedValue({
                data: mockGoogleTokenResponse,
                error: null
            });
            vi.mocked(revokeRefreshTokens).mockResolvedValue({
                data: { localId: 'uid-1' } as never,
                error: null
            });
            const result = await authWithTenant.revokeRefreshTokens('uid-1');
            expect(result.error).toBeNull();
            expect(result.data).toEqual({ localId: 'uid-1' });
            expect(revokeRefreshTokens).toHaveBeenCalledWith(
                'test-project',
                'uid-1',
                'test-access-token',
                undefined,
                'test-tenant-id'
            );
        });
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
                const admin = new FirebaseAdminAuth(serviceAccountKey, {
                    tenantId: 'tenant',
                    fetch: fetchFn
                });
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
            const getUserByProviderUidResult = await auth.getUserByProviderUid(
                'google.com',
                'missing'
            );
            expect(getUserByProviderUidResult.error?.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_NOT_FOUND.code
            );
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
                const getUserByProviderUidResult2 =
                    await auth.getUserByProviderUid(
                        providerId as string,
                        uid as string
                    );
                expect(getUserByProviderUidResult2.error).toBeInstanceOf(
                    FirebaseEdgeError
                );
                expect(mockedGetToken).not.toHaveBeenCalled();
            }
        );
        it('preserves lookup failures', async () => {
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_LOOKUP_FAILED
            );
            vi.spyOn(auth, 'getUsers').mockResolvedValue({ data: null, error });
            const getUserByProviderUidResult3 = await auth.getUserByProviderUid(
                'google.com',
                'uid'
            );
            expect(getUserByProviderUidResult3).toEqual({ data: null, error });
        });
    });

    describe('generateVerifyAndChangeEmailLink', () => {
        it.each([undefined, { url: 'https://example.com/account' }])(
            'generates a link with settings %j',
            async (settings) => {
                const fetchFn = vi.fn();
                const admin = new FirebaseAdminAuth(serviceAccountKey, {
                    tenantId: 'tenant',
                    fetch: fetchFn
                });
                mockedGetToken.mockResolvedValue({
                    data: mockGoogleTokenResponse,
                    error: null
                });
                vi.mocked(generateEmailActionLink).mockResolvedValue({
                    data: 'https://example.com/action',
                    error: null
                });
                const generateVerifyAndChangeEmailLinkResult =
                    await admin.generateVerifyAndChangeEmailLink(
                        'old@example.com',
                        'new@example.com',
                        settings
                    );
                expect(generateVerifyAndChangeEmailLinkResult).toEqual({
                    data: 'https://example.com/action',
                    error: null
                });
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
            const generateVerifyAndChangeEmailLinkResult2 =
                await auth.generateVerifyAndChangeEmailLink(
                    'old@example.com',
                    'new@example.com'
                );
            expect(generateVerifyAndChangeEmailLinkResult2.error?.code).toBe(
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
            const instance = new FirebaseAdminAuth(serviceAccountKey, {
                tenantId: 'tenant',
                fetch: customFetch
            });
            const setCustomUserClaimsResult =
                await instance.setCustomUserClaims('uid', { role: 'editor' });
            expect(setCustomUserClaimsResult).toEqual({
                data: undefined,
                error: null
            });
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
            const setCustomUserClaimsResult2 = await auth.setCustomUserClaims(
                'uid',
                null
            );
            expect(setCustomUserClaimsResult2.error).toBeNull();
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
            const setCustomUserClaimsResult3 = await auth.setCustomUserClaims(
                '',
                {}
            );
            expect(setCustomUserClaimsResult3.error).not.toBeNull();
            const setCustomUserClaimsResult4 = await auth.setCustomUserClaims(
                'a'.repeat(129),
                {}
            );
            expect(setCustomUserClaimsResult4.error).not.toBeNull();
            const setCustomUserClaimsResult5 = await auth.setCustomUserClaims(
                'uid',
                { sub: 'reserved' }
            );
            expect(setCustomUserClaimsResult5.error).not.toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(updateAccountAdmin).not.toHaveBeenCalled();
        });
        it('uses cached credentials', async () => {
            const cache = {
                getCache: vi.fn().mockResolvedValue(mockGoogleTokenResponse),
                setCache: vi.fn()
            };
            const instance = new FirebaseAdminAuth(serviceAccountKey, {
                cache
            });
            const setCustomUserClaimsResult6 =
                await instance.setCustomUserClaims('uid', {});
            expect(setCustomUserClaimsResult6.error).toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
        });
        it('returns credential failures without updating', async () => {
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
            );
            mockedGetToken.mockResolvedValue({ data: null, error });
            const setCustomUserClaimsResult7 = await auth.setCustomUserClaims(
                'uid',
                {}
            );
            expect(setCustomUserClaimsResult7).toEqual({
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
            const setCustomUserClaimsResult8 = await auth.setCustomUserClaims(
                'uid',
                {}
            );
            expect(setCustomUserClaimsResult8.error?.code).toBe(
                'auth/admin-no-token-returned'
            );
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
            const setCustomUserClaimsResult9 = await auth.setCustomUserClaims(
                'uid',
                {}
            );
            expect(setCustomUserClaimsResult9.error?.code).toBe(
                'auth/admin-set-custom-claims-failed'
            );
        });
        it('returns network and credential exceptions instead of rejecting', async () => {
            const cause = new Error('offline');
            vi.mocked(updateAccountAdmin).mockRejectedValue(cause);
            const setCustomUserClaimsResult10 = await auth.setCustomUserClaims(
                'uid',
                {}
            );
            expect(setCustomUserClaimsResult10.error?.cause).toBe(cause);
            mockedGetToken.mockRejectedValue('token failure');
            const setCustomUserClaimsResult11 = await auth.setCustomUserClaims(
                'uid',
                {}
            );
            expect(setCustomUserClaimsResult11.error?.cause).toBeInstanceOf(
                Error
            );
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
            const instance = new FirebaseAdminAuth(serviceAccountKey, {
                tenantId: 'tenant',
                fetch: customFetch
            });
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
            const getUserByPhoneNumberResult =
                await auth.getUserByPhoneNumber('+15555550100');
            expect(getUserByPhoneNumberResult.error?.code).toBe(
                'auth/admin-user-not-found'
            );
        });
        it.each(['', '555', null, 1])(
            'rejects invalid phone number %s before authentication',
            async (phone) => {
                const getUserByPhoneNumberResult2 =
                    await auth.getUserByPhoneNumber(phone as string);
                expect(getUserByPhoneNumberResult2.error).toBeInstanceOf(
                    FirebaseEdgeError
                );
                expect(mockedGetToken).not.toHaveBeenCalled();
            }
        );
        it('deletes a batch with tenant, custom fetch, counts, and indexed errors', async () => {
            const customFetch = vi.fn<typeof fetch>();
            const instance = new FirebaseAdminAuth(serviceAccountKey, {
                tenantId: 'tenant',
                fetch: customFetch
            });
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
            const deleteUsersResult = await auth.deleteUsers([]);
            expect(deleteUsersResult).toEqual(result);
            const importUsersResult = await auth.importUsers([]);
            expect(importUsersResult).toEqual(result);
            expect(mockedGetToken).not.toHaveBeenCalled();
        });
        it('rejects invalid delete batches and oversized imports before authentication', async () => {
            const deleteUsersResult2 = await auth.deleteUsers(['one', '']);
            expect(deleteUsersResult2.error).not.toBeNull();
            const deleteUsersResult3 = await auth.deleteUsers(
                Array(1001).fill('uid')
            );
            expect(deleteUsersResult3.error).not.toBeNull();
            const importUsersResult2 = await auth.importUsers(
                Array(1001).fill({ uid: 'uid' })
            );
            expect(importUsersResult2.error).not.toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
        });
        it('merges local and server import failures using original indices', async () => {
            const customFetch = vi.fn<typeof fetch>();
            const instance = new FirebaseAdminAuth(serviceAccountKey, {
                tenantId: 'tenant',
                fetch: customFetch
            });
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
            const importUsersResult3 = await auth.importUsers([{ uid: '' }]);
            expect(importUsersResult3).toMatchObject({
                data: { successCount: 0, failureCount: 1 },
                error: null
            });
            const importUsersResult4 = await auth.importUsers([
                { uid: 'uid', passwordHash: new Uint8Array([1]) }
            ]);
            expect(importUsersResult4.error).not.toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(importAccountsAdmin).not.toHaveBeenCalled();
        });
        it.each([true, false])(
            'forwards allowOverwrite=%s in one import request',
            async (allowOverwrite) => {
                const { error } = await auth.importUsers([{ uid: 'one' }], {
                    allowOverwrite
                });
                expect(error).toBeNull();
                expect(importAccountsAdmin).toHaveBeenCalledExactlyOnceWith(
                    'test-project',
                    { users: [{ localId: 'one' }], allowOverwrite },
                    'test-access-token',
                    undefined,
                    undefined
                );
            }
        );
        it.each([true, false])(
            'forwards sanityCheck=%s in one import request',
            async (sanityCheck) => {
                const { error } = await auth.importUsers([{ uid: 'one' }], {
                    sanityCheck
                });
                expect(error).toBeNull();
                expect(importAccountsAdmin).toHaveBeenCalledExactlyOnceWith(
                    'test-project',
                    { users: [{ localId: 'one' }], sanityCheck },
                    'test-access-token',
                    undefined,
                    undefined
                );
            }
        );
        it('rejects invalid sanity checks before requesting credentials', async () => {
            const { error, data } = await auth.importUsers([{ uid: 'one' }], {
                // @ts-expect-error Sanity checks require a boolean.
                sanityCheck: 'true'
            });
            expect(error).toBeInstanceOf(Error);
            expect(data).toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(importAccountsAdmin).not.toHaveBeenCalled();
        });
        it('rejects invalid overwrite settings before requesting credentials', async () => {
            const { error, data } = await auth.importUsers([{ uid: 'one' }], {
                // @ts-expect-error Overwrite requires a boolean.
                allowOverwrite: 'true'
            });
            expect(error).toBeInstanceOf(Error);
            expect(data).toBeNull();
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
            const instance = new FirebaseAdminAuth(serviceAccountKey, {
                cache
            });
            const getUserByPhoneNumberResult3 =
                await instance.getUserByPhoneNumber('+15555550100');
            expect(getUserByPhoneNumberResult3.error).toBeNull();
            const deleteUsersResult4 = await instance.deleteUsers(['uid']);
            expect(deleteUsersResult4.error).toBeNull();
            const importUsersResult5 = await instance.importUsers([
                { uid: 'uid' }
            ]);
            expect(importUsersResult5.error).toBeNull();
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
                const runResult = await run();
                expect(runResult).toEqual({ data: null, error });
                expect(endpoint).not.toHaveBeenCalled();
            });
            it('guards against a missing access token', async () => {
                mockedGetToken.mockResolvedValue({
                    data: {} as GoogleTokenResponse,
                    error: null
                });
                const runResult2 = await run();
                expect(runResult2.error?.code).toBe(
                    'auth/admin-no-token-returned'
                );
                expect(endpoint).not.toHaveBeenCalled();
            });
            it('returns endpoint errors and network exceptions', async () => {
                const error = new FirebaseEdgeError(
                    FirebaseEndpointErrorInfo.ENDPOINT_PERMISSION_DENIED
                );
                endpoint.mockResolvedValue({ data: null, error });
                const runResult3 = await run();
                expect(runResult3).toMatchObject({
                    data: null,
                    error: expect.any(FirebaseEdgeError)
                });
                endpoint.mockRejectedValue(new Error('offline'));
                const runResult4 = await run();
                expect(runResult4).toMatchObject({
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
            const deleteUsersResult5 = await auth.deleteUsers(['uid']);
            expect(deleteUsersResult5.error).not.toBeNull();
            const importUsersResult6 = await auth.importUsers([{ uid: 'uid' }]);
            expect(importUsersResult6.error).not.toBeNull();
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
        it('looks up initial emails in one request and preserves multiple matches', async () => {
            vi.mocked(getAccountsInfo).mockResolvedValue({
                error: null,
                data: {
                    users: [
                        { localId: 'one', initialEmail: 'old@example.com' },
                        { localId: 'two', initialEmail: 'old@example.com' }
                    ]
                }
            });
            const { error, data } = await auth.getUsers([
                { initialEmail: 'old@example.com' }
            ]);
            expect(error).toBeNull();
            expect(data?.users.map((user) => user.uid)).toEqual(['one', 'two']);
            expect(data?.notFound).toEqual([]);
            expect(getAccountsInfo).toHaveBeenCalledTimes(1);
            expect(getAccountsInfo).toHaveBeenCalledWith(
                { initialEmail: ['old@example.com'] },
                'test-access-token',
                'test-project',
                undefined,
                undefined
            );
        });
        it('returns records and unmatched identifiers using one batch request', async () => {
            const customFetch = vi.fn<typeof fetch>();
            const instance = new FirebaseAdminAuth(serviceAccountKey, {
                tenantId: 'tenant',
                fetch: customFetch
            });
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
            const getUsersResult = await auth.getUsers([]);
            expect(getUsersResult).toEqual({
                data: { users: [], notFound: [] },
                error: null
            });
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(getAccountsInfo).not.toHaveBeenCalled();
        });
        it('rejects invalid inputs before authentication', async () => {
            const getUsersResult2 = await auth.getUsers([{ uid: '' }]);
            expect(getUsersResult2.error).toBeInstanceOf(FirebaseEdgeError);
            const getUsersResult3 = await auth.getUsers(
                Array(101).fill({ uid: 'uid' })
            );
            expect(getUsersResult3.error).toBeInstanceOf(FirebaseEdgeError);
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(getAccountsInfo).not.toHaveBeenCalled();
        });
        it('returns all identifiers in notFound when there are no matches', async () => {
            const getUsersResult4 = await auth.getUsers([{ uid: 'missing' }]);
            expect(getUsersResult4).toEqual({
                data: { users: [], notFound: [{ uid: 'missing' }] },
                error: null
            });
        });
        it('uses cached credentials', async () => {
            const cache = {
                getCache: vi.fn().mockResolvedValue(mockGoogleTokenResponse),
                setCache: vi.fn()
            };
            const instance = new FirebaseAdminAuth(serviceAccountKey, {
                cache
            });
            const getUsersResult5 = await instance.getUsers([{ uid: 'uid' }]);
            expect(getUsersResult5.error).toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(getAccountsInfo).toHaveBeenCalledTimes(1);
        });
        it('returns credential failures without a lookup', async () => {
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED
            );
            mockedGetToken.mockResolvedValue({ data: null, error });
            const getUsersResult6 = await auth.getUsers([{ uid: 'uid' }]);
            expect(getUsersResult6).toEqual({
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
            const getUsersResult7 = await auth.getUsers([{ uid: 'uid' }]);
            expect(getUsersResult7.error?.code).toBe(
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
            const getUsersResult8 = await auth.getUsers([{ uid: 'uid' }]);
            expect(getUsersResult8.error?.cause).toBeInstanceOf(Error);
            mockedGetToken.mockRejectedValue('token failure');
            const getUsersResult9 = await auth.getUsers([{ uid: 'uid' }]);
            expect(getUsersResult9.error?.cause).toBeInstanceOf(Error);
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
            const instance = new FirebaseAdminAuth(serviceAccountKey, {
                tenantId: 'tenant',
                fetch: customFetch
            });
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
            const deleteUserResult = await authWithTenant.deleteUser('uid-1');
            expect(deleteUserResult).toEqual({
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
                const updateUserResult = await auth.updateUser(
                    uid as string,
                    {}
                );
                expect(updateUserResult.error).toBeInstanceOf(
                    FirebaseEdgeError
                );
                const deleteUserResult2 = await auth.deleteUser(uid as string);
                expect(deleteUserResult2.error).toBeInstanceOf(
                    FirebaseEdgeError
                );
                expect(mockedGetToken).not.toHaveBeenCalled();
            }
        );

        it('rejects invalid create and update properties before authentication', async () => {
            const createUserResult = await auth.createUser({
                email: 'invalid'
            });
            expect(createUserResult.error).toBeInstanceOf(FirebaseEdgeError);
            const updateUserResult2 = await auth.updateUser('uid', {
                password: 'short'
            });
            expect(updateUserResult2.error).toBeInstanceOf(FirebaseEdgeError);
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
                const runResult5 = await run();
                expect(runResult5).toEqual({ data: null, error });
                expect(endpoint).not.toHaveBeenCalled();
            });
            it('guards against missing credentials', async () => {
                mockedGetToken.mockResolvedValue({
                    data: {} as GoogleTokenResponse,
                    error: null
                });
                const runResult6 = await run();
                expect(runResult6.error?.code).toBe(
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
                    const runResult7 = await run();
                    expect(runResult7.error).toBeInstanceOf(FirebaseEdgeError);
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
                    const runResult8 = await run();
                    expect(runResult8).toEqual({ data: null, error });
                });
                it('handles a missing user in the lookup response', async () => {
                    mockedGetAccountInfo.mockResolvedValue({
                        data: null,
                        error: null
                    });
                    const runResult9 = await run();
                    expect(runResult9.error?.code).toBe(
                        'auth/admin-user-record-not-found'
                    );
                });
                it('returns conversion errors rather than rejecting', async () => {
                    mockedGetAccountInfo.mockResolvedValue({
                        data: { localId: 'uid', customAttributes: '{' },
                        error: null
                    });
                    const runResult10 = await run();
                    expect(runResult10.error).toBeInstanceOf(FirebaseEdgeError);
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
            const instance = new FirebaseAdminAuth(serviceAccountKey, {
                tenantId: 'tenant',
                fetch: customFetch
            });
            const listUsersResult = await instance.listUsers(25, 'opaque+/=');
            expect(listUsersResult).toEqual({
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
            const listUsersResult2 = await auth.listUsers(undefined);
            expect(listUsersResult2).toEqual({
                data: { users: [] },
                error: null
            });
        });

        it('preserves an explicitly returned empty page token', async () => {
            download.mockResolvedValue({
                data: { nextPageToken: '' },
                error: null
            });
            const listUsersResult3 = await auth.listUsers();
            expect(listUsersResult3).toEqual({
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
            const listUsersResult4 = await auth.listUsers();
            expect(listUsersResult4).toEqual({ data: null, error });
            expect(download).not.toHaveBeenCalled();
        });

        it('uses cached credentials', async () => {
            const cache = {
                getCache: vi.fn().mockResolvedValue(mockGoogleTokenResponse),
                setCache: vi.fn()
            };
            const instance = new FirebaseAdminAuth(serviceAccountKey, {
                cache
            });
            const listUsersResult5 = await instance.listUsers();
            expect(listUsersResult5.error).toBeNull();
            expect(mockedGetToken).not.toHaveBeenCalled();
            expect(cache.getCache).toHaveBeenCalledWith(
                `__cache:auth:${serviceAccountKey.client_email}`
            );
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
            const listUsersResult6 = await auth.listUsers();
            expect(listUsersResult6.error?.code).toBe(
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
                undefined,
                false
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
            const admin = new FirebaseAdminAuth(serviceAccountKey, {
                tenantId: 'tenant',
                fetch: fetchFn
            });
            mockedGetToken.mockResolvedValue({
                data: mockGoogleTokenResponse,
                error: null
            });
            vi.mocked(generateEmailActionLink).mockResolvedValue({
                data: 'https://example.com/action',
                error: null
            });
            const operationResult = await admin[method](
                'person@example.com',
                settings
            );
            expect(operationResult).toEqual({
                data: 'https://example.com/action',
                error: null
            });
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
            const operationResult2 = await auth[method]('invalid', settings);
            expect(operationResult2.error?.code).toBe(
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
            const operationResult3 = await auth[method](
                'person@example.com',
                settings
            );
            expect(operationResult3.error?.code).toBe(
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
            const operationResult4 = await auth[method](
                'person@example.com',
                settings
            );
            expect(operationResult4.error?.code).toBe(
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
        const operationResult5 = await auth[method]('person@example.com');
        expect(operationResult5.error).toBeNull();
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
                const admin = new FirebaseAdminAuth(serviceAccountKey, {
                    tenantId: 'tenant',
                    fetch: fetchFn
                });
                mockedGetToken.mockResolvedValue({
                    data: mockGoogleTokenResponse,
                    error: null
                });
                mockedCreateSessionCookieEndpoint.mockResolvedValue({
                    data: 'cookie',
                    error: null
                });
                const createSessionCookieResult =
                    await admin.createSessionCookie('id-token', { expiresIn });
                expect(createSessionCookieResult).toEqual({
                    data: 'cookie',
                    error: null
                });
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
            const verifySessionCookieResult = await auth.verifySessionCookie(
                'cookie',
                true
            );
            expect(verifySessionCookieResult.error?.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_DISABLED.code
            );
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
            const verifySessionCookieResult2 =
                await auth.verifySessionCookie('cookie');
            expect(verifySessionCookieResult2).toEqual({
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
                {},
                undefined,
                false
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
                claims,
                undefined,
                false
            );
            expect(result.data).toBe('custom-token');
            expect(result.error).toBeNull();
        });

        it('passes the tenant separately from developer claims', async () => {
            mockedSignJWTCustomToken.mockResolvedValueOnce({
                data: 'custom-token-with-tenant',
                error: null
            });

            const claims = Object.freeze({ role: 'admin' });
            const result = await authWithTenant.createCustomToken(
                'uid-1',
                claims
            );

            expect(mockedSignJWTCustomToken).toHaveBeenCalledWith(
                'uid-1',
                serviceAccountKey,
                claims,
                'test-tenant-id',
                false
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
                claims,
                undefined,
                false
            );
            expect(result.data).toBe('custom-token');
            expect(result.error).toBeNull();
        });
    });
});

describe('Identity writes without readback', () => {
    it('creates before setting prevalidated claims and reports partial failures with the UID', async () => {
        const fetchFn = vi.fn();
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            tenantId: 'tenant',
            fetch: fetchFn,
            emulatorHost: null
        });
        const create = vi.mocked(createAccountAdmin);
        const update = vi.mocked(updateAccountAdmin);
        create.mockResolvedValue({
            error: null,
            data: { localId: 'generated' }
        });
        update.mockResolvedValue({
            error: null,
            data: { localId: 'generated' }
        });
        const invalid = await auth._writeIdentityUser(undefined, {
            customClaims: { sub: 'reserved' }
        });
        expect(invalid.error).toBeInstanceOf(Error);
        expect(create).not.toHaveBeenCalled();
        for (const customClaims of [{ role: 'editor' }, {}, null]) {
            const result = await auth._writeIdentityUser(undefined, {
                email: 'a@example.com',
                customClaims
            });
            expect(result).toEqual({ error: null, data: { uid: 'generated' } });
            expect(create).toHaveBeenLastCalledWith(
                serviceAccountKey.project_id,
                { email: 'a@example.com' },
                mockGoogleTokenResponse.access_token,
                fetchFn,
                'tenant'
            );
            expect(update).toHaveBeenLastCalledWith(
                serviceAccountKey.project_id,
                'generated',
                { customAttributes: JSON.stringify(customClaims ?? {}) },
                mockGoogleTokenResponse.access_token,
                fetchFn,
                'tenant'
            );
        }
        expect(create.mock.invocationCallOrder[0]).toBeLessThan(
            update.mock.invocationCallOrder[0]!
        );
        const failure = new Error('denied');
        update.mockResolvedValueOnce({ error: failure, data: null });
        const partial = await auth._writeIdentityUser(undefined, {
            customClaims: {}
        });
        expect(partial.data).toBeNull();
        expect(partial.error).toMatchObject({
            context: { uid: 'generated' },
            cause: failure
        });
        expect(partial.error?.message).toContain('was created');
        update.mockRejectedValueOnce(failure);
        const thrown = await auth._writeIdentityUser(undefined, {
            customClaims: {}
        });
        expect(thrown.error).toMatchObject({
            context: { uid: 'generated' },
            cause: failure
        });
        update.mockClear();
        create.mockResolvedValueOnce({ error: failure, data: null });
        const denied = await auth._writeIdentityUser(undefined, {
            customClaims: {}
        });
        expect(denied).toEqual({ error: failure, data: null });
        expect(update).not.toHaveBeenCalled();
        expect(getAccountsInfo).not.toHaveBeenCalled();
    });
    it('combines profile, claims, and timestamps in one account write', async () => {
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            emulatorHost: null
        });
        vi.mocked(updateAccountAdmin).mockResolvedValue({
            error: null,
            data: { localId: 'one' }
        });
        const { error, data } = await auth._writeIdentityUser('one', {
            displayName: 'Sam',
            customClaims: { admin: true },
            metadata: { lastSignInTime: '2024-01-01T00:00:00Z' }
        });
        expect(error).toBeNull();
        expect(data).toEqual({ uid: 'one' });
        expect(updateAccountAdmin).toHaveBeenCalledExactlyOnceWith(
            serviceAccountKey.project_id,
            'one',
            {
                displayName: 'Sam',
                customAttributes: '{"admin":true}',
                lastLoginAt: '1704067200000'
            },
            mockGoogleTokenResponse.access_token,
            undefined,
            undefined
        );
        expect(getAccountInfo).not.toHaveBeenCalled();
        expect(getAccountsInfo).not.toHaveBeenCalled();
    });
    beforeEach(() => {
        vi.clearAllMocks();
        mockedGetToken.mockResolvedValue({
            error: null,
            data: mockGoogleTokenResponse
        });
    });
    it('creates or updates using one write and forwards tenant and fetch', async () => {
        const fetchFn = vi.fn();
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            tenantId: 'tenant',
            fetch: fetchFn,
            emulatorHost: null
        });
        vi.mocked(createAccountAdmin).mockResolvedValue({
            error: null,
            data: { localId: 'one' }
        });
        const created = await auth._writeIdentityUser(undefined, {
            uid: 'one',
            email: 'a@example.com'
        });
        expect(created).toEqual({ error: null, data: { uid: 'one' } });
        expect(createAccountAdmin).toHaveBeenCalledExactlyOnceWith(
            serviceAccountKey.project_id,
            { localId: 'one', email: 'a@example.com' },
            mockGoogleTokenResponse.access_token,
            fetchFn,
            'tenant'
        );
        vi.mocked(updateAccountAdmin).mockResolvedValue({
            error: null,
            data: { localId: 'one' }
        });
        const updated = await auth._writeIdentityUser('one', {
            disabled: true
        });
        expect(updated).toEqual({ error: null, data: { uid: 'one' } });
        expect(updateAccountAdmin).toHaveBeenCalledExactlyOnceWith(
            serviceAccountKey.project_id,
            'one',
            { disableUser: true },
            mockGoogleTokenResponse.access_token,
            fetchFn,
            'tenant'
        );
        expect(getAccountInfo).not.toHaveBeenCalled();
        expect(getAccountsInfo).not.toHaveBeenCalled();
    });
    it('rejects invalid data and handles credential and endpoint failures without retry', async () => {
        const auth = new FirebaseAdminAuth(serviceAccountKey, {
            emulatorHost: null
        });
        const invalidUid = await auth._writeIdentityUser('', {});
        const invalidData = await auth._writeIdentityUser('one', {
            customClaims: { sub: 'bad' }
        });
        expect(invalidUid.error).not.toBeNull();
        expect(invalidData.error).not.toBeNull();
        expect(mockedGetToken).not.toHaveBeenCalled();
        const failure = new Error('failed');
        const token = vi.spyOn(
            auth as unknown as { getCachedToken(): Promise<unknown> },
            'getCachedToken'
        );
        token.mockResolvedValueOnce({ error: failure, data: null } as never);
        const denied = await auth._writeIdentityUser('one', {});
        expect(denied.error).toBe(failure);
        token.mockResolvedValueOnce({ error: null, data: {} } as never);
        const missing = await auth._writeIdentityUser('one', {});
        expect(missing.error).not.toBeNull();
        vi.mocked(updateAccountAdmin).mockResolvedValueOnce({
            error: failure,
            data: null
        });
        const failed = await auth._writeIdentityUser('one', {});
        expect(failed.error).toBe(failure);
        vi.mocked(updateAccountAdmin).mockResolvedValueOnce({
            error: null,
            data: { localId: 'other' }
        });
        const wrongUid = await auth._writeIdentityUser('one', {});
        expect(wrongUid.error).not.toBeNull();
        vi.mocked(updateAccountAdmin).mockRejectedValueOnce(failure);
        const thrown = await auth._writeIdentityUser('one', {});
        expect(thrown.error).toBe(failure);
        expect(updateAccountAdmin).toHaveBeenCalledTimes(3);
    });
});

it('sets existing UID profiles with no create fallback or readback', async () => {
    vi.clearAllMocks();
    mockedGetToken.mockResolvedValue({
        error: null,
        data: mockGoogleTokenResponse
    });
    const auth = new FirebaseAdminAuth(serviceAccountKey, {
        emulatorHost: null
    });
    vi.mocked(updateAccountAdmin).mockResolvedValueOnce({
        error: null,
        data: { localId: 'one' }
    });
    const result = await auth._writeIdentityUser(
        'one',
        { displayName: 'Sam' },
        'set'
    );
    expect(result).toEqual({ error: null, data: { uid: 'one' } });
    expect(updateAccountAdmin).toHaveBeenCalledExactlyOnceWith(
        serviceAccountKey.project_id,
        'one',
        {
            displayName: 'Sam',
            disableUser: false,
            emailVerified: false,
            deleteAttribute: ['PHOTO_URL', 'EMAIL'],
            deleteProvider: ['phone'],
            customAttributes: '{}',
            createdAt: '0',
            lastLoginAt: '0'
        },
        mockGoogleTokenResponse.access_token,
        undefined,
        undefined
    );
    const error = new FirebaseEdgeError({
        code: 'auth/user-not-found',
        message: 'Missing user'
    });
    vi.mocked(updateAccountAdmin).mockResolvedValueOnce({ error, data: null });
    const missing = await auth._writeIdentityUser('missing', {}, 'set');
    expect(missing).toEqual({ error, data: null });
    const invalid = await auth._writeIdentityUser(undefined, {}, 'set');
    expect(invalid.error).not.toBeNull();
    expect(updateAccountAdmin).toHaveBeenCalledTimes(2);
    expect(createAccountAdmin).not.toHaveBeenCalled();
    expect(getAccountInfo).not.toHaveBeenCalled();
    expect(getAccountsInfo).not.toHaveBeenCalled();
});

it('sends a dedicated metadata update without readback', async () => {
    vi.clearAllMocks();
    mockedGetToken.mockResolvedValue({
        error: null,
        data: mockGoogleTokenResponse
    });
    vi.mocked(updateAccountAdmin).mockResolvedValue({
        error: null,
        data: { localId: 'one' }
    });
    const auth = new FirebaseAdminAuth(serviceAccountKey, {
        emulatorHost: null
    });
    const { error } = await auth._writeIdentityUser(
        'one',
        { creationTime: '2020-01-01T00:00:00Z' },
        'metadata'
    );
    expect(error).toBeNull();
    expect(updateAccountAdmin).toHaveBeenCalledExactlyOnceWith(
        serviceAccountKey.project_id,
        'one',
        {
            createdAt: '1577836800000'
        },
        mockGoogleTokenResponse.access_token,
        undefined,
        undefined
    );
    expect(getAccountInfo).not.toHaveBeenCalled();
    expect(getAccountsInfo).not.toHaveBeenCalled();
});
