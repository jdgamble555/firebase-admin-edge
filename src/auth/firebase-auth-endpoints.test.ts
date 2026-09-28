import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
    countAccounts,
    queryAccounts,
    createAuthEmulatorFetch,
    manageAuthConfig,
    generateEmailActionLink,
    deleteAccountsAdmin,
    importAccountsAdmin,
    getAccountsInfo,
    createAccountAdmin,
    updateAccountAdmin,
    deleteAccountAdmin,
    refreshFirebaseIdToken,
    createAuthUri,
    signInWithIdp,
    executeProviderSignIn,
    signInWithCustomToken,
    getAccountInfo,
    downloadAccount,
    createSessionCookie,
    getJWKs,
    getPublicKeys,
    sendOobCode,
    confirmPasswordReset,
    applyActionCode,
    signInWithEmailLink,
    linkWithOAuthCredential,
    unlinkProvider
} from './firebase-auth-endpoints.js';
import * as restFetch from '../rest-fetch.js';
import { FirebaseEdgeError, FirebaseEndpointErrorInfo } from './errors.js';
import type { AuthConfigOperation } from './auth-config-types.js';

vi.mock('../rest-fetch.js');

describe('countAccounts', () => {
    beforeEach(() => vi.resetAllMocks());

    it.each([null, 'invalid', []])(
        'rejects malformed count response bodies',
        async (body) => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: body,
                error: null
            });
            const { error, data } = await countAccounts('token', 'p');
            expect(error).toMatchObject({ code: 'auth/internal-error' });
            expect(data).toBeNull();
        }
    );

    it.each(['uid', 'email', 'phoneNumber'] as const)(
        'counts %s with the same expression as fetch and no pagination fields',
        async (field) => {
            const fetchFn = vi.fn();
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: { recordsCount: '12000' },
                error: null
            });
            const { error, data } = await countAccounts(
                'token',
                'project/id',
                { field, value: 'value' },
                'tenant',
                fetchFn
            );
            expect(error).toBeNull();
            expect(data).toBe(12000);
            expect(restFetch.restFetch).toHaveBeenCalledExactlyOnceWith(
                'https://identitytoolkit.googleapis.com/v1/projects/project%2Fid/accounts:query',
                {
                    method: 'POST',
                    bearerToken: 'token',
                    global: { fetch: fetchFn },
                    body: {
                        returnUserInfo: false,
                        tenantId: 'tenant',
                        expression: [
                            { [field === 'uid' ? 'userId' : field]: 'value' }
                        ]
                    }
                }
            );
        }
    );

    it('counts the entire project and accepts the omitted proto zero value', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: {},
            error: null
        });
        const { data } = await countAccounts('token', 'p');
        expect(data).toBe(0);
        expect(restFetch.restFetch).toHaveBeenCalledWith(
            expect.any(String),
            expect.objectContaining({ body: { returnUserInfo: false } })
        );
    });

    it.each(['-1', '1.5', 'NaN', '', '9007199254740992', 10, null])(
        'rejects invalid or unsafe counts %s',
        async (recordsCount) => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: { recordsCount },
                error: null
            });
            const { error, data } = await countAccounts('token', 'p');
            expect(error).toMatchObject({ code: 'auth/internal-error' });
            expect(data).toBeNull();
        }
    );

    it('accepts the largest safe integer count', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: { recordsCount: String(Number.MAX_SAFE_INTEGER) },
            error: null
        });
        const { data } = await countAccounts('token', 'p');
        expect(data).toBe(Number.MAX_SAFE_INTEGER);
    });

    it('returns API and network errors without falling back to fetching users', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValueOnce({
            data: null,
            error: { error: { code: 403, message: 'PERMISSION_DENIED' } }
        });
        const { error, data } = await countAccounts('token', 'p');
        expect(error).toBeInstanceOf(FirebaseEdgeError);
        expect(data).toBeNull();
        const failure = new Error('network');
        vi.mocked(restFetch.restFetch).mockRejectedValueOnce(failure);
        const { error: thrown } = await countAccounts('token', 'p');
        expect(thrown).toBe(failure);
        expect(restFetch.restFetch).toHaveBeenCalledTimes(2);
    });
});

describe('queryAccounts', () => {
    beforeEach(() => vi.resetAllMocks());

    it('posts native expressions, sorting and string pagination with tenant scope', async () => {
        const fetchFn = vi.fn();
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: { userInfo: [{ localId: 'u' }], recordsCount: '1' },
            error: null
        });
        const { error, data } = await queryAccounts(
            'token',
            'project/id',
            {
                filter: { field: 'uid', value: 'u' },
                orderBy: { field: 'createdAt', direction: 'desc' },
                offset: 20,
                limit: 10
            },
            'tenant',
            fetchFn
        );
        expect(error).toBeNull();
        expect(data).toEqual([{ localId: 'u' }]);
        expect(restFetch.restFetch).toHaveBeenCalledWith(
            'https://identitytoolkit.googleapis.com/v1/projects/project%2Fid/accounts:query',
            {
                method: 'POST',
                bearerToken: 'token',
                global: { fetch: fetchFn },
                body: {
                    returnUserInfo: true,
                    limit: '10',
                    offset: '20',
                    tenantId: 'tenant',
                    expression: [{ userId: 'u' }],
                    sortBy: 'CREATED_AT',
                    order: 'DESC'
                }
            }
        );
    });

    it.each([
        ['uid', 'USER_ID'],
        ['displayName', 'NAME'],
        ['createdAt', 'CREATED_AT'],
        ['lastLoginAt', 'LAST_LOGIN_AT'],
        ['email', 'USER_EMAIL']
    ] as const)('maps sort field %s', async (field, sortBy) => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: {},
            error: null
        });
        const { data } = await queryAccounts('token', 'p', {
            orderBy: { field, direction: 'asc' }
        });
        expect(data).toEqual([]);
        expect(restFetch.restFetch).toHaveBeenLastCalledWith(
            expect.any(String),
            expect.objectContaining({
                body: {
                    returnUserInfo: true,
                    offset: '0',
                    limit: '500',
                    sortBy,
                    order: 'ASC'
                }
            })
        );
    });

    it.each(['email', 'phoneNumber'] as const)(
        'preserves %s expressions',
        async (field) => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: {},
                error: null
            });
            await queryAccounts('token', 'p', {
                filter: { field, value: 'value' }
            });
            expect(restFetch.restFetch).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    body: {
                        returnUserInfo: true,
                        offset: '0',
                        limit: '500',
                        expression: [{ [field]: 'value' }]
                    }
                })
            );
        }
    );

    it('omits optional fields and handles empty responses', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: { recordsCount: '0' },
            error: null
        });
        const { error, data } = await queryAccounts('token', 'p', {});
        expect(error).toBeNull();
        expect(data).toEqual([]);
        expect(restFetch.restFetch).toHaveBeenCalledWith(
            expect.any(String),
            expect.objectContaining({
                body: { returnUserInfo: true, offset: '0', limit: '500' }
            })
        );
    });

    it('normalizes REST errors and transport failures', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: null,
            error: { error: { code: 403, message: 'PERMISSION_DENIED' } }
        });
        const { error, data } = await queryAccounts('token', 'p', {});
        expect(error).toBeInstanceOf(FirebaseEdgeError);
        expect(data).toBeNull();
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: null,
            error: 'gateway failure'
        });
        const { error: textError } = await queryAccounts('token', 'p', {});
        expect(textError).toBeInstanceOf(Error);
        const failure = new Error('network');
        vi.mocked(restFetch.restFetch).mockRejectedValue(failure);
        const { error: networkError } = await queryAccounts('token', 'p', {});
        expect(networkError).toBe(failure);
    });
});

describe('auth emulator transport', () => {
    it.each([
        [
            'identitytoolkit.googleapis.com/v1/projects/p/accounts:lookup',
            'identitytoolkit.googleapis.com/v1/projects/p/accounts:lookup'
        ],
        [
            'identitytoolkit.googleapis.com/v1/projects/p/tenants/t/accounts:lookup',
            'identitytoolkit.googleapis.com/v1/projects/p/tenants/t/accounts:lookup'
        ],
        [
            'identitytoolkit.googleapis.com/v2/projects/p/tenants/t/oauthIdpConfigs?pageSize=10',
            'identitytoolkit.googleapis.com/v2/projects/p/tenants/t/oauthIdpConfigs?pageSize=10'
        ],
        [
            'identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=fake',
            'identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=fake'
        ],
        [
            'securetoken.googleapis.com/v1/token?key=fake',
            'securetoken.googleapis.com/v1/token?key=fake'
        ]
    ])(
        'routes %s and replaces production credentials',
        async (source, target) => {
            const fetchFn = vi.fn().mockResolvedValue(new Response('{}'));
            const emulatorFetch = createAuthEmulatorFetch(
                'localhost:9099',
                fetchFn
            );
            await emulatorFetch(`https://${source}`, {
                method: 'POST',
                body: '{"test":true}',
                headers: {
                    Authorization: 'Bearer production-secret',
                    'X-Test': 'yes'
                }
            });
            expect(fetchFn).toHaveBeenCalledWith(
                `http://localhost:9099/${target}`,
                expect.objectContaining({
                    method: 'POST',
                    body: '{"test":true}'
                })
            );
            const headers = fetchFn.mock.calls[0]![1].headers as Headers;
            expect(headers.get('Authorization')).toBe('Bearer owner');
            expect(headers.get('X-Test')).toBe('yes');
        }
    );

    it('supports URL and Request inputs, retaining their method and body', async () => {
        const fetchFn = vi.fn().mockResolvedValue(new Response('{}'));
        const emulatorFetch = createAuthEmulatorFetch('[::1]:9099', fetchFn);
        await emulatorFetch(
            new URL('https://securetoken.googleapis.com/v1/token')
        );
        expect(fetchFn.mock.calls[0]![0]).toBe(
            'http://[::1]:9099/securetoken.googleapis.com/v1/token'
        );
        const request = new Request(
            'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken',
            {
                method: 'POST',
                body: '{}',
                headers: { Authorization: 'Bearer secret' }
            }
        );
        await emulatorFetch(request);
        const forwarded = fetchFn.mock.calls[1]![0] as Request;
        expect(forwarded.url).toContain(
            'http://[::1]:9099/identitytoolkit.googleapis.com/'
        );
        expect(forwarded.method).toBe('POST');
        const body = await forwarded.text();
        expect(body).toBe('{}');
        expect(fetchFn.mock.calls[1]![1].headers.get('Authorization')).toBe(
            'Bearer owner'
        );
    });

    it('leaves other services and their credentials unchanged', async () => {
        const fetchFn = vi.fn().mockResolvedValue(new Response('{}'));
        const emulatorFetch = createAuthEmulatorFetch(
            'localhost:9099',
            fetchFn
        );
        const options = { headers: { Authorization: 'Bearer secret' } };
        for (const url of [
            'https://firestore.googleapis.com/v1/projects/p',
            'https://oauth2.googleapis.com/token',
            'https://identitytoolkit.googleapis.com.example.com/path'
        ]) {
            await emulatorFetch(url, options);
            expect(fetchFn).toHaveBeenLastCalledWith(url, options);
        }
    });

    it('rejects invalid hosts before creating a transport', () => {
        expect(() =>
            createAuthEmulatorFetch('http://localhost:9099', vi.fn())
        ).toThrow();
    });

    it('propagates emulator failures without retrying production', async () => {
        const fetchFn = vi.fn().mockRejectedValue(new Error('offline'));
        const emulatorFetch = createAuthEmulatorFetch(
            'localhost:9099',
            fetchFn
        );
        const result = emulatorFetch(
            'https://identitytoolkit.googleapis.com/v1/accounts:lookup'
        );
        await expect(result).rejects.toThrow('offline');
        expect(fetchFn).toHaveBeenCalledTimes(1);
    });
});

describe('configuration endpoints', () => {
    beforeEach(() => vi.clearAllMocks());
    it.each([
        ['provider', 404, 'auth/configuration-not-found'],
        ['tenant', 404, 'auth/tenant-not-found'],
        ['provider', 409, 'auth/configuration-exists']
    ] as const)('maps %s HTTP %s to %s', async (resource, code, expected) => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: null,
            error: { error: { code, message: 'API error' } }
        });
        const result = await manageAuthConfig(
            'p',
            {
                resource,
                action: 'get',
                id: resource === 'provider' ? 'oidc.a' : 't'
            },
            'token'
        );
        expect(result.error?.code).toBe(expected);
    });
    it.each([
        ['provider', 'create', 'oidc.example', 'oauthIdpConfigs', 'POST'],
        [
            'provider',
            'get',
            'oidc.example',
            'oauthIdpConfigs/oidc.example',
            'GET'
        ],
        [
            'provider',
            'update',
            'oidc.example',
            'oauthIdpConfigs/oidc.example',
            'PATCH'
        ],
        [
            'provider',
            'delete',
            'oidc.example',
            'oauthIdpConfigs/oidc.example',
            'DELETE'
        ],
        ['provider', 'list', undefined, 'oauthIdpConfigs', 'GET'],
        ['provider', 'create', 'saml.example', 'inboundSamlConfigs', 'POST'],
        [
            'provider',
            'get',
            'saml.example',
            'inboundSamlConfigs/saml.example',
            'GET'
        ],
        [
            'provider',
            'update',
            'saml.example',
            'inboundSamlConfigs/saml.example',
            'PATCH'
        ],
        [
            'provider',
            'delete',
            'saml.example',
            'inboundSamlConfigs/saml.example',
            'DELETE'
        ],
        ['project', 'get', undefined, 'config', 'GET'],
        ['project', 'update', undefined, 'config', 'PATCH'],
        ['tenant', 'create', undefined, 'tenants', 'POST'],
        ['tenant', 'get', 't', 'tenants/t', 'GET'],
        ['tenant', 'update', 't', 'tenants/t', 'PATCH'],
        ['tenant', 'delete', 't', 'tenants/t', 'DELETE'],
        ['tenant', 'list', undefined, 'tenants', 'GET']
    ] as const)(
        'routes %s %s %s using %s %s',
        async (resource, action, id, path, method) => {
            const provider = id?.startsWith('saml.')
                ? {
                      idpEntityId: 'idp',
                      ssoURL: 'https://idp.example',
                      x509Certificates: ['cert'],
                      rpEntityId: 'rp'
                  }
                : { clientId: 'client', issuer: 'https://idp.example' };
            const properties =
                resource === 'provider'
                    ? provider
                    : resource === 'project'
                      ? {
                            emailPrivacyConfig: {
                                enableImprovedEmailPrivacy: true
                            }
                        }
                      : { displayName: 'Tenant' };
            const operation: AuthConfigOperation = {
                resource,
                action,
                id,
                type: 'oidc',
                properties
            };
            if (id?.startsWith('saml.')) operation.type = 'saml';
            const response =
                action === 'list' || resource === 'project'
                    ? {}
                    : {
                          name: `projects/p/${path.split('/')[0]}/${id ?? 'new-tenant'}`,
                          clientId: 'client',
                          issuer: 'https://idp.example',
                          idpConfig: {
                              idpEntityId: 'idp',
                              ssoUrl: 'https://idp.example'
                          },
                          spConfig: { spEntityId: 'rp' }
                      };
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: response,
                error: null
            });
            const fetchFn = vi.fn();
            const result = await manageAuthConfig(
                'p',
                operation,
                'token',
                fetchFn,
                'scope'
            );
            expect(result.error).toBeNull();
            expect(restFetch.restFetch).toHaveBeenCalledWith(
                `https://identitytoolkit.googleapis.com/v2/projects/p${resource === 'provider' ? '/tenants/scope' : ''}/${path}`,
                expect.objectContaining({
                    method,
                    bearerToken: 'token',
                    global: { fetch: fetchFn }
                })
            );
            const options = vi.mocked(restFetch.restFetch).mock.calls[0]![1]!;
            if (action === 'get' || action === 'list' || action === 'delete')
                expect(options.body).toBeUndefined();
            if (action === 'create' && resource === 'provider')
                expect(options.params).toEqual({
                    [id!.startsWith('oidc.')
                        ? 'oauthIdpConfigId'
                        : 'inboundSamlConfigId']: id
                });
            if (action === 'update')
                expect(options.params?.updateMask).toBeTruthy();
            if (action === 'delete') expect(result.data).toBeUndefined();
        }
    );

    it('preserves nested SAML siblings with leaf masks and handles project scope', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: {
                name: 'projects/p/inboundSamlConfigs/saml.a',
                idpConfig: {
                    signRequest: false,
                    idpEntityId: 'idp',
                    ssoUrl: 'https://idp.example'
                },
                spConfig: { spEntityId: 'rp' }
            },
            error: null
        });
        const result = await manageAuthConfig(
            'p',
            {
                resource: 'provider',
                action: 'update',
                id: 'saml.a',
                properties: { enableRequestSigning: false }
            },
            'token'
        );
        expect(result.data).toMatchObject({ enableRequestSigning: false });
        expect(restFetch.restFetch).toHaveBeenCalledWith(
            'https://identitytoolkit.googleapis.com/v2/projects/p/inboundSamlConfigs/saml.a',
            expect.objectContaining({
                body: { idpConfig: { signRequest: false } },
                params: { updateMask: 'idpConfig.signRequest' }
            })
        );
    });

    it('sends pagination and parses SAML pages', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: { inboundSamlConfigs: [], nextPageToken: 'next' },
            error: null
        });
        const result = await manageAuthConfig(
            'p',
            {
                resource: 'provider',
                action: 'list',
                type: 'saml',
                maxResults: 10,
                pageToken: 'opaque token'
            },
            'token'
        );
        expect(result.data).toEqual({ providerConfigs: [], pageToken: 'next' });
        expect(restFetch.restFetch).toHaveBeenCalledWith(
            expect.stringContaining('/inboundSamlConfigs'),
            expect.objectContaining({
                params: { pageSize: '10', pageToken: 'opaque token' }
            })
        );
    });

    it('rejects invalid operations without HTTP calls', async () => {
        const result = await manageAuthConfig(
            'p',
            { resource: 'provider', action: 'get', id: 'bad' },
            'token'
        );
        expect(result.error?.code).toBe('auth/invalid-argument');
        expect(restFetch.restFetch).not.toHaveBeenCalled();
    });

    it.each([
        { error: { code: 403, message: 'PERMISSION_DENIED' } },
        'unavailable'
    ])('maps API errors %j', async (error) => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({ data: null, error });
        const result = await manageAuthConfig(
            'p',
            { resource: 'project', action: 'get' },
            'token'
        );
        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
    });

    it('handles network and malformed response failures', async () => {
        vi.mocked(restFetch.restFetch)
            .mockRejectedValueOnce(new Error('offline'))
            .mockResolvedValueOnce({ data: null, error: null });
        const network = await manageAuthConfig(
            'p',
            { resource: 'project', action: 'get' },
            'token'
        );
        const malformed = await manageAuthConfig(
            'p',
            { resource: 'project', action: 'get' },
            'token'
        );
        expect(network.error?.cause).toMatchObject({ message: 'offline' });
        expect(malformed.error).toBeInstanceOf(FirebaseEdgeError);
    });
});

describe('firebase-auth-endpoints', () => {
    const mockFetch = vi.fn();
    const API_KEY = 'test-api-key';
    const PROJECT_ID = 'test-project';
    const ACCESS_TOKEN = 'test-access-token';

    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('generateEmailActionLink', () => {
        const body = {
            requestType: 'PASSWORD_RESET',
            email: 'person@example.com',
            returnOobLink: true,
            continueUrl: 'https://example.com/login'
        } as const;
        it.each([undefined, 'tenant'])(
            'requests a link without sending email for tenant %s',
            async (tenant) => {
                vi.mocked(restFetch.restFetch).mockResolvedValue({
                    data: { oobLink: 'https://example.com/action' },
                    error: null
                });
                const generateEmailActionLinkResult =
                    await generateEmailActionLink(
                        PROJECT_ID,
                        body,
                        ACCESS_TOKEN,
                        mockFetch,
                        tenant
                    );
                expect(generateEmailActionLinkResult).toEqual({
                    data: 'https://example.com/action',
                    error: null
                });
                expect(restFetch.restFetch).toHaveBeenCalledWith(
                    `https://identitytoolkit.googleapis.com/v1/projects/test-project${tenant ? '/tenants/tenant' : ''}/accounts:sendOobCode`,
                    {
                        body,
                        bearerToken: ACCESS_TOKEN,
                        global: { fetch: mockFetch }
                    }
                );
            }
        );
        it('maps Firebase errors', async () => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: { error: { code: 400, message: 'EMAIL_NOT_FOUND' } }
            });
            const result = await generateEmailActionLink(
                PROJECT_ID,
                body,
                ACCESS_TOKEN
            );
            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        });
        it('preserves ordinary transport errors', async () => {
            const cause = new Error('network');
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: cause
            });
            const generateEmailActionLinkResult2 =
                await generateEmailActionLink(PROJECT_ID, body, ACCESS_TOKEN);
            expect(generateEmailActionLinkResult2).toEqual({
                data: null,
                error: cause
            });
        });
        it.each([null, {}, { oobLink: '' }, { oobLink: 123 }])(
            'rejects an absent or invalid link %j',
            async (data) => {
                vi.mocked(restFetch.restFetch).mockResolvedValue({
                    data,
                    error: null
                });
                const result = await generateEmailActionLink(
                    PROJECT_ID,
                    body,
                    ACCESS_TOKEN
                );
                expect(result.data).toBeNull();
                expect(result.error).toBeInstanceOf(Error);
            }
        );
    });

    it('sends custom claims through the existing admin update endpoint', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: { localId: 'uid' },
            error: null
        });
        await updateAccountAdmin(
            PROJECT_ID,
            'uid',
            { customAttributes: '{"role":"editor"}' },
            ACCESS_TOKEN,
            mockFetch,
            'tenant'
        );
        expect(restFetch.restFetch).toHaveBeenCalledWith(
            'https://identitytoolkit.googleapis.com/v1/projects/test-project/tenants/tenant/accounts:update',
            {
                body: { localId: 'uid', customAttributes: '{"role":"editor"}' },
                bearerToken: ACCESS_TOKEN,
                global: { fetch: mockFetch }
            }
        );
    });

    describe('bulk admin endpoints', () => {
        it.each([undefined, 'tenant'])(
            'posts a forced delete batch to tenant %s',
            async (tenantId) => {
                vi.mocked(restFetch.restFetch).mockResolvedValue({
                    data: {},
                    error: null
                });
                const deleteAccountsAdminResult = await deleteAccountsAdmin(
                    PROJECT_ID,
                    ['one', 'two'],
                    ACCESS_TOKEN,
                    mockFetch,
                    tenantId
                );
                expect(deleteAccountsAdminResult).toEqual({
                    data: {},
                    error: null
                });
                expect(restFetch.restFetch).toHaveBeenCalledWith(
                    `https://identitytoolkit.googleapis.com/v1/projects/test-project${tenantId ? '/tenants/tenant' : ''}/accounts:batchDelete`,
                    {
                        body: { localIds: ['one', 'two'], force: true },
                        bearerToken: ACCESS_TOKEN,
                        global: { fetch: mockFetch }
                    }
                );
            }
        );
        it.each([undefined, 'tenant'])(
            'posts imported users and hash settings to tenant %s',
            async (tenantId) => {
                const body = {
                    users: [{ localId: 'uid', passwordHash: 'AQ==' }],
                    hashAlgorithm: 'BCRYPT',
                    allowOverwrite: true,
                    sanityCheck: true
                };
                const response = { error: [{ index: 0, message: 'failure' }] };
                vi.mocked(restFetch.restFetch).mockResolvedValue({
                    data: response,
                    error: null
                });
                const importAccountsAdminResult = await importAccountsAdmin(
                    PROJECT_ID,
                    body,
                    ACCESS_TOKEN,
                    mockFetch,
                    tenantId
                );
                expect(importAccountsAdminResult).toEqual({
                    data: response,
                    error: null
                });
                expect(restFetch.restFetch).toHaveBeenCalledWith(
                    `https://identitytoolkit.googleapis.com/v1/projects/test-project${tenantId ? '/tenants/tenant' : ''}/accounts:batchCreate`,
                    {
                        body,
                        bearerToken: ACCESS_TOKEN,
                        global: { fetch: mockFetch }
                    }
                );
            }
        );
        it('maps HTTP errors and preserves non-JSON failures', async () => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: { error: { code: 403, message: 'PERMISSION_DENIED' } }
            });
            const deleteAccountsAdminResult2 = await deleteAccountsAdmin(
                PROJECT_ID,
                ['uid'],
                ACCESS_TOKEN
            );
            expect(deleteAccountsAdminResult2.error).toMatchObject({
                code: FirebaseEndpointErrorInfo.ENDPOINT_PERMISSION_DENIED.code
            });
            const importAccountsAdminResult2 = await importAccountsAdmin(
                PROJECT_ID,
                { users: [] },
                ACCESS_TOKEN
            );
            expect(importAccountsAdminResult2.error).toMatchObject({
                code: FirebaseEndpointErrorInfo.ENDPOINT_PERMISSION_DENIED.code
            });
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: 'Unavailable'
            });
            const deleteAccountsAdminResult3 = await deleteAccountsAdmin(
                PROJECT_ID,
                ['uid'],
                ACCESS_TOKEN
            );
            expect(deleteAccountsAdminResult3.error?.message).toContain(
                'Unavailable'
            );
            const importAccountsAdminResult3 = await importAccountsAdmin(
                PROJECT_ID,
                { users: [] },
                ACCESS_TOKEN
            );
            expect(importAccountsAdminResult3.error?.message).toContain(
                'Unavailable'
            );
        });
        it('sends phone lookups as an array', async () => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: {
                    users: [{ localId: 'uid', phoneNumber: '+15555550100' }]
                },
                error: null
            });
            const result = await getAccountInfo(
                { phoneNumber: '+15555550100' },
                ACCESS_TOKEN,
                PROJECT_ID,
                'tenant',
                mockFetch
            );
            expect(result.data).toMatchObject({
                localId: 'uid',
                phoneNumber: '+15555550100'
            });
            expect(restFetch.restFetch).toHaveBeenCalledWith(
                expect.stringContaining('/tenants/tenant/accounts:lookup'),
                expect.objectContaining({
                    body: { phoneNumber: ['+15555550100'], tenantId: 'tenant' }
                })
            );
        });
    });

    describe('getAccountsInfo', () => {
        it.each([undefined, 'tenant'])(
            'looks up a mixed batch for tenant %s',
            async (tenantId) => {
                const body = {
                    localId: ['uid'],
                    email: ['user@example.com'],
                    initialEmail: ['original@example.com'],
                    phoneNumber: ['+15555550100'],
                    federatedUserId: [
                        { providerId: 'google.com', rawId: 'external' }
                    ]
                };
                const data = { users: [{ localId: 'uid' }] };
                vi.mocked(restFetch.restFetch).mockResolvedValue({
                    data,
                    error: null
                });
                const getAccountsInfoResult = await getAccountsInfo(
                    body,
                    ACCESS_TOKEN,
                    PROJECT_ID,
                    tenantId,
                    mockFetch
                );
                expect(getAccountsInfoResult).toEqual({ data, error: null });
                expect(restFetch.restFetch).toHaveBeenCalledWith(
                    `https://identitytoolkit.googleapis.com/v1/projects/test-project${tenantId ? '/tenants/tenant' : ''}/accounts:lookup`,
                    {
                        body,
                        bearerToken: ACCESS_TOKEN,
                        global: { fetch: mockFetch }
                    }
                );
            }
        );
        it('allows a successful response with no matching users', async () => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: {},
                error: null
            });
            const getAccountsInfoResult2 = await getAccountsInfo(
                { localId: ['missing'] },
                ACCESS_TOKEN,
                PROJECT_ID
            );
            expect(getAccountsInfoResult2).toEqual({ data: {}, error: null });
        });
        it('maps Firebase failures and normalizes plain-text errors', async () => {
            vi.mocked(restFetch.restFetch)
                .mockResolvedValueOnce({
                    data: null,
                    error: {
                        error: { code: 403, message: 'PERMISSION_DENIED' }
                    }
                })
                .mockResolvedValueOnce({ data: null, error: 'Unavailable' });
            const getAccountsInfoResult3 = await getAccountsInfo(
                { localId: ['uid'] },
                ACCESS_TOKEN,
                PROJECT_ID
            );
            expect(getAccountsInfoResult3.error).toMatchObject({
                code: FirebaseEndpointErrorInfo.ENDPOINT_PERMISSION_DENIED.code
            });
            const getAccountsInfoResult4 = await getAccountsInfo(
                { localId: ['uid'] },
                ACCESS_TOKEN,
                PROJECT_ID
            );
            expect(getAccountsInfoResult4.error?.message).toContain(
                'Unavailable'
            );
        });
    });

    describe('admin user writes', () => {
        it.each([undefined, 'tenant'])(
            'creates at the accounts resource for tenant %s',
            async (tenantId) => {
                vi.mocked(restFetch.restFetch).mockResolvedValue({
                    data: { localId: 'uid' },
                    error: null
                });
                const createAccountAdminResult = await createAccountAdmin(
                    PROJECT_ID,
                    { email: 'user@example.com', disabled: false },
                    ACCESS_TOKEN,
                    mockFetch,
                    tenantId
                );
                expect(createAccountAdminResult).toEqual({
                    data: { localId: 'uid' },
                    error: null
                });
                expect(restFetch.restFetch).toHaveBeenCalledWith(
                    `https://identitytoolkit.googleapis.com/v1/projects/test-project${tenantId ? '/tenants/tenant' : ''}/accounts`,
                    {
                        body: { email: 'user@example.com', disabled: false },
                        bearerToken: ACCESS_TOKEN,
                        global: { fetch: mockFetch }
                    }
                );
            }
        );
        it('reuses the update endpoint for admin user changes', async () => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: { localId: 'uid' },
                error: null
            });
            await updateAccountAdmin(
                PROJECT_ID,
                'uid',
                { disableUser: true, deleteAttribute: ['PHOTO_URL'] },
                ACCESS_TOKEN,
                mockFetch,
                'tenant'
            );
            expect(restFetch.restFetch).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/projects/test-project/tenants/tenant/accounts:update',
                {
                    body: {
                        localId: 'uid',
                        disableUser: true,
                        deleteAttribute: ['PHOTO_URL']
                    },
                    bearerToken: ACCESS_TOKEN,
                    global: { fetch: mockFetch }
                }
            );
        });
        it.each([undefined, 'tenant'])(
            'deletes a single UID for tenant %s',
            async (tenantId) => {
                vi.mocked(restFetch.restFetch).mockResolvedValue({
                    data: {},
                    error: null
                });
                const deleteAccountAdminResult = await deleteAccountAdmin(
                    PROJECT_ID,
                    'uid',
                    ACCESS_TOKEN,
                    mockFetch,
                    tenantId
                );
                expect(deleteAccountAdminResult).toEqual({ error: null });
                expect(restFetch.restFetch).toHaveBeenCalledWith(
                    `https://identitytoolkit.googleapis.com/v1/projects/test-project${tenantId ? '/tenants/tenant' : ''}/accounts:delete`,
                    {
                        body: { localId: 'uid' },
                        bearerToken: ACCESS_TOKEN,
                        global: { fetch: mockFetch }
                    }
                );
            }
        );
        it.each(['EMAIL_EXISTS', 'USER_NOT_FOUND', 'PERMISSION_DENIED'])(
            'maps %s write errors',
            async (message) => {
                vi.mocked(restFetch.restFetch).mockResolvedValue({
                    data: null,
                    error: { error: { code: 400, message } }
                });
                const createAccountAdminResult2 = await createAccountAdmin(
                    PROJECT_ID,
                    {},
                    ACCESS_TOKEN
                );
                expect(createAccountAdminResult2.error).toBeInstanceOf(
                    FirebaseEdgeError
                );
                const updateAccountAdminResult = await updateAccountAdmin(
                    PROJECT_ID,
                    'uid',
                    {},
                    ACCESS_TOKEN
                );
                expect(updateAccountAdminResult.error).toBeInstanceOf(
                    FirebaseEdgeError
                );
                const deleteAccountAdminResult2 = await deleteAccountAdmin(
                    PROJECT_ID,
                    'uid',
                    ACCESS_TOKEN
                );
                expect(deleteAccountAdminResult2.error).toBeInstanceOf(
                    FirebaseEdgeError
                );
            }
        );
        it('normalizes non-JSON errors for admin writes', async () => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: 'Unavailable'
            });
            const createAccountAdminResult3 = await createAccountAdmin(
                PROJECT_ID,
                {},
                ACCESS_TOKEN
            );
            expect(createAccountAdminResult3.error?.message).toContain(
                'Unavailable'
            );
            const updateAccountAdminResult2 = await updateAccountAdmin(
                PROJECT_ID,
                'uid',
                {},
                ACCESS_TOKEN
            );
            expect(updateAccountAdminResult2.error?.message).toContain(
                'Unavailable'
            );
            const deleteAccountAdminResult3 = await deleteAccountAdmin(
                PROJECT_ID,
                'uid',
                ACCESS_TOKEN
            );
            expect(deleteAccountAdminResult3.error?.message).toContain(
                'Unavailable'
            );
        });
        it('looks up the complete record with a UID array', async () => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: { users: [{ localId: 'uid' }] },
                error: null
            });
            await getAccountInfo({ uid: 'uid' }, ACCESS_TOKEN, PROJECT_ID);
            expect(restFetch.restFetch).toHaveBeenCalledWith(
                expect.stringContaining('/accounts:lookup'),
                expect.objectContaining({ body: { localId: ['uid'] } })
            );
        });
    });

    describe('downloadAccount', () => {
        it('encodes opaque pagination tokens and sends a body-free authenticated GET', async () => {
            const actual =
                await vi.importActual<typeof restFetch>('../rest-fetch.js');
            vi.mocked(restFetch.restFetch).mockImplementationOnce(
                actual.restFetch
            );
            const fetchFn = vi
                .fn<typeof fetch>()
                .mockResolvedValue(Response.json({ users: [] }));
            await downloadAccount(
                ACCESS_TOKEN,
                PROJECT_ID,
                25,
                'a+/=? &',
                'tenant',
                fetchFn
            );
            const [url, options] = fetchFn.mock.calls[0]!;
            const parsed = new URL(String(url));
            expect(parsed.pathname).toBe(
                '/v1/projects/test-project/tenants/tenant/accounts:batchGet'
            );
            expect(parsed.searchParams.get('nextPageToken')).toBe('a+/=? &');
            expect(parsed.searchParams.get('maxResults')).toBe('25');
            expect(options).toMatchObject({
                method: 'GET',
                body: undefined,
                headers: { Authorization: `Bearer ${ACCESS_TOKEN}` }
            });
        });

        it('normalizes an actual non-JSON HTTP failure', async () => {
            const actual =
                await vi.importActual<typeof restFetch>('../rest-fetch.js');
            vi.mocked(restFetch.restFetch).mockImplementationOnce(
                actual.restFetch
            );
            const fetchFn = vi
                .fn<typeof fetch>()
                .mockResolvedValue(
                    new Response('Service unavailable', { status: 503 })
                );
            const result = await downloadAccount(
                ACCESS_TOKEN,
                PROJECT_ID,
                25,
                undefined,
                undefined,
                fetchFn
            );
            expect(result.data).toBeNull();
            expect(result.error?.message).toContain('Service unavailable');
        });

        it('propagates JSON decoding failures to the admin error handler', async () => {
            const actual =
                await vi.importActual<typeof restFetch>('../rest-fetch.js');
            vi.mocked(restFetch.restFetch).mockImplementationOnce(
                actual.restFetch
            );
            const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(
                new Response('{', {
                    headers: { 'content-type': 'application/json' }
                })
            );
            await expect(
                downloadAccount(
                    ACCESS_TOKEN,
                    PROJECT_ID,
                    25,
                    undefined,
                    undefined,
                    fetchFn
                )
            ).rejects.toBeInstanceOf(SyntaxError);
        });

        it('downloads the default page through the admin URL and shared fetch helper', async () => {
            const data = { users: [{ localId: 'uid' }], nextPageToken: 'next' };
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data,
                error: null
            });
            const downloadAccountResult = await downloadAccount(
                ACCESS_TOKEN,
                PROJECT_ID
            );
            expect(downloadAccountResult).toEqual({
                data,
                error: null
            });
            expect(restFetch.restFetch).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/projects/test-project/accounts:batchGet',
                {
                    method: 'GET',
                    bearerToken: ACCESS_TOKEN,
                    global: { fetch: undefined },
                    params: { maxResults: '1000' }
                }
            );
        });

        it('forwards tenant, pagination, and custom fetch options', async () => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: {},
                error: null
            });
            await downloadAccount(
                ACCESS_TOKEN,
                PROJECT_ID,
                10,
                'opaque+/=',
                'tenant',
                mockFetch
            );
            expect(restFetch.restFetch).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/projects/test-project/tenants/tenant/accounts:batchGet',
                {
                    method: 'GET',
                    bearerToken: ACCESS_TOKEN,
                    global: { fetch: mockFetch },
                    params: { maxResults: '10', nextPageToken: 'opaque+/=' }
                }
            );
        });

        it('maps Firebase API errors', async () => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: { error: { code: 403, message: 'PERMISSION_DENIED' } }
            });
            const result = await downloadAccount(ACCESS_TOKEN, PROJECT_ID);
            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error).toMatchObject({
                code: FirebaseEndpointErrorInfo.ENDPOINT_PERMISSION_DENIED.code
            });
        });

        it('normalizes non-JSON error responses', async () => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: 'Service unavailable'
            });
            const result = await downloadAccount(ACCESS_TOKEN, PROJECT_ID);
            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(Error);
            expect(result.error?.message).toContain('Service unavailable');
        });
    });

    describe('refreshFirebaseIdToken', () => {
        it('should refresh token successfully', async () => {
            const mockResponse = {
                access_token: 'new-token',
                refresh_token: 'new-refresh-token'
            };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await refreshFirebaseIdToken(
                'refresh-token',
                API_KEY,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(result.error).toBeNull();
            expect(restFetchSpy).toHaveBeenCalledWith(
                'https://securetoken.googleapis.com/v1/token',
                expect.objectContaining({
                    body: {
                        grant_type: 'refresh_token',
                        refresh_token: 'refresh-token'
                    },
                    params: { key: API_KEY },
                    form: true,
                    global: { fetch: mockFetch }
                })
            );
        });

        it('should handle error response', async () => {
            const mockError = {
                code: 400,
                message: 'INVALID_GRANT: Invalid refresh token'
            };

            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: { error: mockError }
            });

            const result = await refreshFirebaseIdToken(
                'invalid-token',
                API_KEY
            );

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error!.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_REFRESH_TOKEN.code
            );
        });
    });

    describe('createAuthUri', () => {
        it.each(['google', 'google.com', 'github', 'apple', 'oidc.company'])(
            'uses server callback code flow only for Google: %s',
            async (provider) => {
                vi.mocked(restFetch.restFetch).mockResolvedValue({
                    data: { authUri: 'https://provider/authorize' },
                    error: null
                });
                await createAuthUri(
                    'https://app/auth/callback',
                    API_KEY,
                    undefined,
                    mockFetch,
                    provider
                );
                const options = vi
                    .mocked(restFetch.restFetch)
                    .mock.calls.at(-1)?.[1];
                if (provider === 'google' || provider === 'google.com') {
                    expect(options?.body).toMatchObject({
                        providerId: 'google.com',
                        authFlowType: 'CODE_FLOW'
                    });
                    return;
                }
                expect(options?.body).not.toHaveProperty('authFlowType');
            }
        );
        it('should create auth URI successfully', async () => {
            const mockResponse = { authUri: 'https://auth.example.com' };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await createAuthUri(
                'https://redirect.com',
                API_KEY,
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(restFetchSpy).toHaveBeenCalled();
            expect(result.error).toBeNull();
            expect(restFetchSpy).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri',
                expect.objectContaining({
                    body: {
                        continueUri: 'https://redirect.com',
                        providerId: 'google.com',
                        authFlowType: 'CODE_FLOW'
                    },
                    params: { key: API_KEY },
                    global: { fetch: mockFetch }
                })
            );
        });

        it('should create auth URI with tenant ID', async () => {
            const mockResponse = { authUri: 'https://auth.example.com' };
            const tenantId = 'tenant-123';

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await createAuthUri(
                'https://redirect.com',
                API_KEY,
                tenantId,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(result.error).toBeNull();
            expect(restFetchSpy).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri',
                expect.objectContaining({
                    body: {
                        continueUri: 'https://redirect.com',
                        providerId: 'google.com',
                        authFlowType: 'CODE_FLOW',
                        tenantId: tenantId
                    },
                    params: { key: API_KEY },
                    global: { fetch: mockFetch }
                })
            );
        });
    });

    describe('signInWithIdp', () => {
        it('should sign in with IDP successfully', async () => {
            const mockResponse = {
                idToken: 'firebase-token',
                refreshToken: 'refresh'
            };

            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: mockResponse,
                error: null
            });

            const result = await signInWithIdp(
                'provider-token',
                'https://request.com',
                'google.com',
                API_KEY,
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(result.error).toBeNull();
            expect(restFetch.restFetch).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp',
                expect.objectContaining({
                    body: {
                        postBody:
                            'id_token=provider-token&providerId=google.com',
                        requestUri: 'https://request.com',
                        returnSecureToken: true,
                        returnIdpCredential: true
                    }
                })
            );
        });

        it('should sign in with IDP and tenant ID', async () => {
            const mockResponse = {
                idToken: 'firebase-token',
                refreshToken: 'refresh'
            };
            const tenantId = 'tenant-456';

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await signInWithIdp(
                'provider-token',
                'https://request.com',
                'google.com',
                API_KEY,
                tenantId,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(result.error).toBeNull();
            expect(restFetchSpy).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp',
                expect.objectContaining({
                    body: {
                        postBody:
                            'id_token=provider-token&providerId=google.com',
                        requestUri: 'https://request.com',
                        returnSecureToken: true,
                        returnIdpCredential: true,
                        tenantId: tenantId
                    }
                })
            );
        });

        it('should use access_token for GitHub provider', async () => {
            const mockResponse = {
                idToken: 'firebase-token',
                refreshToken: 'refresh'
            };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await signInWithIdp(
                'github-token',
                'https://request.com',
                'github.com',
                API_KEY,
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(restFetchSpy).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp',
                expect.objectContaining({
                    body: expect.objectContaining({
                        postBody:
                            'access_token=github-token&providerId=github.com'
                    })
                })
            );
        });
    });

    describe('signInWithCustomToken', () => {
        it('should sign in with custom token successfully', async () => {
            const mockResponse = { idToken: 'firebase-token' };

            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: mockResponse,
                error: null
            });

            const result = await signInWithCustomToken(
                'jwt-token',
                API_KEY,
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(result.error).toBeNull();
        });

        it('should sign in with custom token and tenant ID', async () => {
            const mockResponse = { idToken: 'firebase-token' };
            const tenantId = 'tenant-789';

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await signInWithCustomToken(
                'jwt-token',
                API_KEY,
                tenantId,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(result.error).toBeNull();
            expect(restFetchSpy).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken',
                expect.objectContaining({
                    body: {
                        token: 'jwt-token',
                        returnSecureToken: true,
                        tenantId: tenantId
                    }
                })
            );
        });
    });

    describe('getAccountInfo', () => {
        it('should get account info successfully', async () => {
            const mockUser = { localId: 'user-123', email: 'test@example.com' };

            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: { users: [mockUser] },
                error: null
            });

            const result = await getAccountInfo(
                { uid: 'user-123' },
                ACCESS_TOKEN,
                PROJECT_ID,
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockUser);
            expect(result.error).toBeNull();
        });

        it('should get account info with tenant ID', async () => {
            const mockUser = { localId: 'user-123', email: 'test@example.com' };
            const tenantId = 'tenant-abc';

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: { users: [mockUser] },
                    error: null
                });

            const result = await getAccountInfo(
                { uid: 'user-123' },
                ACCESS_TOKEN,
                PROJECT_ID,
                tenantId,
                mockFetch
            );

            expect(result.data).toEqual(mockUser);
            expect(result.error).toBeNull();
            expect(restFetchSpy).toHaveBeenCalledWith(
                `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT_ID}/tenants/${tenantId}/accounts:lookup`,
                expect.objectContaining({
                    body: {
                        localId: ['user-123'],
                        tenantId: tenantId
                    },
                    bearerToken: ACCESS_TOKEN
                })
            );
        });

        it('should return null when no users found', async () => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: { users: [] },
                error: null
            });

            const result = await getAccountInfo(
                { uid: 'user-123' },
                ACCESS_TOKEN,
                PROJECT_ID
            );

            expect(result.data).toBeNull();
        });
    });

    describe('createSessionCookie', () => {
        it('should create session cookie with default expiry (14 days in seconds)', async () => {
            const mockResponse = { sessionCookie: 'cookie-value' };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await createSessionCookie(
                'id-token',
                ACCESS_TOKEN,
                PROJECT_ID,
                undefined,
                undefined,
                mockFetch
            );

            expect(result.data).toBe('cookie-value');
            expect(restFetchSpy).toHaveBeenCalledWith(
                `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT_ID}:createSessionCookie`,
                expect.objectContaining({
                    body: expect.objectContaining({
                        // default is 14 days in ms converted to seconds
                        validDuration: 1209600
                    })
                })
            );
        });

        it('should create session cookie with tenant ID', async () => {
            const mockResponse = { sessionCookie: 'cookie-value' };
            const tenantId = 'tenant-def';

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await createSessionCookie(
                'id-token',
                ACCESS_TOKEN,
                PROJECT_ID,
                3600000, // 1 hour in ms
                tenantId,
                mockFetch
            );

            expect(result.data).toBe('cookie-value');
            expect(restFetchSpy).toHaveBeenCalledWith(
                `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT_ID}/tenants/${tenantId}:createSessionCookie`,
                expect.objectContaining({
                    body: {
                        idToken: 'id-token',
                        validDuration: 3600, // converted to seconds
                        tenantId: tenantId
                    },
                    bearerToken: ACCESS_TOKEN
                })
            );
        });

        it('should create session cookie with custom expiry (using seconds)', async () => {
            const mockResponse = { sessionCookie: 'cookie-value' };

            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: mockResponse,
                error: null
            });

            const result = await createSessionCookie(
                'id-token',
                ACCESS_TOKEN,
                PROJECT_ID,
                3600, // 1 hour in seconds
                undefined,
                mockFetch
            );

            expect(result.data).toBe('cookie-value');
        });
    });

    describe('getJWKs', () => {
        it('should get JWKs successfully', async () => {
            const mockKeys = [{ kid: 'key-1', kty: 'RSA' }];

            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: { keys: mockKeys },
                error: null
            });

            const result = await getJWKs(mockFetch);

            expect(result.data).toEqual(mockKeys);
            expect(result.error).toBeNull();
        });

        it('should return null when no keys found', async () => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: null
            });

            const result = await getJWKs();

            expect(result.data).toBeNull();
        });
    });

    describe('getPublicKeys', () => {
        it('should get public keys successfully', async () => {
            const mockKeys = { 'key-1': 'public-key-value' };

            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: mockKeys,
                error: null
            });

            const result = await getPublicKeys(mockFetch);

            expect(result.data).toEqual(mockKeys);
            expect(result.error).toBeNull();
        });

        it('should handle error response', async () => {
            const mockError = {
                code: 403,
                message: 'PERMISSION_DENIED: Failed to fetch keys'
            };

            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: { error: mockError }
            });

            const result = await getPublicKeys();

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error!.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_PERMISSION_DENIED.code
            );
        });
    });
    describe('createAdminIdentityURL (indirectly via functions)', () => {
        it('should call createSessionCookie URL without /accounts segment', async () => {
            const mockResponse = { sessionCookie: 'cookie-value' };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const idToken = 'id-token';
            const token = 'access-token';
            const projectId = 'test-project';

            const result = await createSessionCookie(
                idToken,
                token,
                projectId,
                3600_000,
                undefined,
                vi.fn()
            );

            expect(result.data).toBe('cookie-value');
            expect(restFetchSpy).toHaveBeenCalledTimes(1);

            const [calledUrl, options] = restFetchSpy.mock
                .calls[0] as unknown as [string, unknown];

            const opts = options as {
                bearerToken?: string;
                body?: { idToken?: string };
            };

            expect(calledUrl).toBe(
                `https://identitytoolkit.googleapis.com/v1/projects/${projectId}:createSessionCookie`
            );
            expect(opts.bearerToken).toBe(token);
            expect(opts.body?.idToken).toBe(idToken);
        });

        it('should call createSessionCookie tenant URL when tenant ID provided', async () => {
            const mockResponse = { sessionCookie: 'cookie-value' };
            const tenantId = 'tenant-test';

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await createSessionCookie(
                'id-token',
                'access-token',
                'test-project',
                3600_000,
                tenantId,
                vi.fn()
            );

            expect(result.data).toBe('cookie-value');
            const [calledUrl] = restFetchSpy.mock.calls[0] as [string, unknown];

            expect(calledUrl).toBe(
                `https://identitytoolkit.googleapis.com/v1/projects/test-project/tenants/${tenantId}:createSessionCookie`
            );
        });

        it('should call accounts lookup URL with /accounts segment via getAccountInfo', async () => {
            const mockUser = { localId: 'user-123', email: 'test@example.com' };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: { users: [mockUser] },
                    error: null
                });

            const uid = 'user-123';
            const token = 'access-token';
            const projectId = 'test-project';

            const result = await getAccountInfo(
                { uid },
                token,
                projectId,
                undefined,
                vi.fn()
            );

            expect(result.data).toEqual(mockUser);
            expect(restFetchSpy).toHaveBeenCalledTimes(1);

            const [calledUrl, options] = restFetchSpy.mock
                .calls[0] as unknown as [string, unknown];

            const opts = options as {
                bearerToken?: string;
                body?: { localId?: string };
            };

            expect(calledUrl).toBe(
                `https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:lookup`
            );
            expect(opts.bearerToken).toBe(token);
            expect(opts.body?.localId).toEqual([uid]);
        });

        it('should call accounts lookup tenant URL when tenant ID provided', async () => {
            const mockUser = { localId: 'user-123', email: 'test@example.com' };
            const tenantId = 'tenant-lookup';

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: { users: [mockUser] },
                    error: null
                });

            const result = await getAccountInfo(
                { uid: 'user-123' },
                'access-token',
                'test-project',
                tenantId,
                vi.fn()
            );

            expect(result.data).toEqual(mockUser);
            const [calledUrl] = restFetchSpy.mock.calls[0] as [string, unknown];

            expect(calledUrl).toBe(
                `https://identitytoolkit.googleapis.com/v1/projects/test-project/tenants/${tenantId}/accounts:lookup`
            );
        });
    });

    describe('createSessionCookie with ms input', () => {
        it('should convert ms to seconds when creating session cookie', async () => {
            const mockResponse = { sessionCookie: 'cookie-value' };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await createSessionCookie(
                'id-token',
                ACCESS_TOKEN,
                PROJECT_ID,
                1209600000, // 14 days in ms
                undefined, // tenantId
                mockFetch
            );

            expect(result.data).toBe('cookie-value');
            expect(restFetchSpy).toHaveBeenCalledWith(
                expect.stringContaining('createSessionCookie'),
                expect.objectContaining({
                    body: expect.objectContaining({
                        validDuration: 1209600
                    })
                })
            );
        });
    });

    describe('sendOobCode', () => {
        it('sends magic links through Firebase email delivery', async () => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: { email: 'a@b.com' },
                error: null
            });
            const result = await sendOobCode(
                'EMAIL_SIGNIN',
                API_KEY,
                {
                    email: 'a@b.com',
                    continueUrl: 'https://app/email',
                    locale: 'fr'
                },
                'tenant',
                mockFetch
            );
            expect(result.error).toBeNull();
            expect(restFetch.restFetch).toHaveBeenCalledWith(
                expect.stringContaining('accounts:sendOobCode'),
                expect.objectContaining({
                    body: {
                        requestType: 'EMAIL_SIGNIN',
                        email: 'a@b.com',
                        continueUrl: 'https://app/email',
                        canHandleCodeInApp: true,
                        tenantId: 'tenant'
                    },
                    headers: { 'X-Firebase-Locale': 'fr' },
                    params: { key: API_KEY },
                    global: { fetch: mockFetch }
                })
            );
        });
        it.each([
            ['invalid', 'https://app'],
            ['a@b.com', 'javascript:bad']
        ])('validates magic link settings', async (email, continueUrl) => {
            const result = await sendOobCode('EMAIL_SIGNIN', API_KEY, {
                email: email!,
                continueUrl: continueUrl!
            });
            expect(result.error).toBeTruthy();
            expect(restFetch.restFetch).not.toHaveBeenCalled();
        });
        it('should send password reset email successfully', async () => {
            const mockResponse = { email: 'test@example.com' };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await sendOobCode(
                'PASSWORD_RESET',
                API_KEY,
                { email: 'test@example.com' },
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(result.error).toBeNull();
            expect(restFetchSpy).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode',
                expect.objectContaining({
                    body: expect.objectContaining({
                        requestType: 'PASSWORD_RESET',
                        email: 'test@example.com',
                        canHandleCodeInApp: false
                    }),
                    params: { key: API_KEY }
                })
            );
        });

        it('should send verification email successfully', async () => {
            const mockResponse = { email: 'test@example.com' };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await sendOobCode(
                'VERIFY_EMAIL',
                API_KEY,
                { idToken: 'test-id-token' },
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(result.error).toBeNull();
            expect(restFetchSpy).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode',
                expect.objectContaining({
                    body: expect.objectContaining({
                        requestType: 'VERIFY_EMAIL',
                        idToken: 'test-id-token',
                        canHandleCodeInApp: false
                    })
                })
            );
        });

        it('should include continue URL when provided', async () => {
            const mockResponse = { email: 'test@example.com' };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await sendOobCode(
                'PASSWORD_RESET',
                API_KEY,
                {
                    email: 'test@example.com',
                    continueUrl: 'https://example.com/reset'
                },
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(restFetchSpy).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    body: expect.objectContaining({
                        continueUrl: 'https://example.com/reset'
                    })
                })
            );
        });

        it('should include locale header when provided', async () => {
            const mockResponse = { email: 'test@example.com' };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await sendOobCode(
                'PASSWORD_RESET',
                API_KEY,
                { email: 'test@example.com', locale: 'es' },
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(restFetchSpy).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    headers: { 'X-Firebase-Locale': 'es' }
                })
            );
        });

        it('should include tenant ID when provided', async () => {
            const mockResponse = { email: 'test@example.com' };
            const tenantId = 'tenant-123';

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await sendOobCode(
                'PASSWORD_RESET',
                API_KEY,
                { email: 'test@example.com' },
                tenantId,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(restFetchSpy).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    body: expect.objectContaining({
                        tenantId: tenantId
                    })
                })
            );
        });

        it('should handle error response', async () => {
            const mockError = {
                code: 400,
                message: 'INVALID_EMAIL'
            };

            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: { error: mockError }
            });

            const result = await sendOobCode('PASSWORD_RESET', API_KEY, {
                email: 'invalid-email'
            });

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        });
    });

    describe('signInWithEmailLink', () => {
        it('should sign in with email link successfully', async () => {
            const mockResponse = {
                idToken: 'test-id-token',
                refreshToken: 'test-refresh-token',
                localId: 'test-uid'
            };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await signInWithEmailLink(
                'test-oob-code',
                'test@example.com',
                API_KEY,
                undefined,
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(result.error).toBeNull();
            expect(restFetchSpy).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/accounts:signInWithEmailLink',
                expect.objectContaining({
                    body: {
                        oobCode: 'test-oob-code',
                        email: 'test@example.com'
                    },
                    params: { key: API_KEY }
                })
            );
        });

        it('should include idToken when linking account', async () => {
            const mockResponse = {
                idToken: 'new-id-token',
                refreshToken: 'new-refresh-token',
                localId: 'test-uid'
            };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await signInWithEmailLink(
                'test-oob-code',
                'test@example.com',
                API_KEY,
                'existing-id-token',
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(restFetchSpy).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    body: expect.objectContaining({
                        idToken: 'existing-id-token'
                    })
                })
            );
        });

        it('should include tenant ID when provided', async () => {
            const mockResponse = {
                idToken: 'test-id-token',
                localId: 'test-uid'
            };
            const tenantId = 'tenant-456';

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await signInWithEmailLink(
                'test-oob-code',
                'test@example.com',
                API_KEY,
                undefined,
                tenantId,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(restFetchSpy).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    body: expect.objectContaining({
                        tenantId: tenantId
                    })
                })
            );
        });

        it('should handle error response', async () => {
            const mockError = {
                code: 400,
                message: 'INVALID_OOB_CODE'
            };

            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: { error: mockError }
            });

            const result = await signInWithEmailLink(
                'invalid-code',
                'test@example.com',
                API_KEY
            );

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        });
    });

    describe('linkWithOAuthCredential', () => {
        it('should link OAuth credential successfully', async () => {
            const mockResponse = {
                idToken: 'new-id-token',
                refreshToken: 'new-refresh-token',
                localId: 'test-uid',
                federatedId: 'google-user-id'
            };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await linkWithOAuthCredential(
                'existing-id-token',
                'google-provider-token',
                'https://example.com/callback',
                'google.com',
                API_KEY,
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(result.error).toBeNull();
            expect(restFetchSpy).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp',
                expect.objectContaining({
                    body: expect.objectContaining({
                        idToken: 'existing-id-token',
                        postBody:
                            'id_token=google-provider-token&providerId=google.com',
                        requestUri: 'https://example.com/callback',
                        returnSecureToken: true,
                        returnIdpCredential: true
                    }),
                    params: { key: API_KEY }
                })
            );
        });

        it('should use access_token for GitHub provider when linking', async () => {
            const mockResponse = {
                idToken: 'new-id-token',
                localId: 'test-uid'
            };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await linkWithOAuthCredential(
                'existing-id-token',
                'github-access-token',
                'https://example.com/callback',
                'github.com',
                API_KEY,
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(restFetchSpy).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    body: expect.objectContaining({
                        postBody:
                            'access_token=github-access-token&providerId=github.com'
                    })
                })
            );
        });

        it('should include tenant ID when provided', async () => {
            const mockResponse = {
                idToken: 'new-id-token',
                localId: 'test-uid'
            };
            const tenantId = 'tenant-789';

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await linkWithOAuthCredential(
                'existing-id-token',
                'provider-token',
                'https://example.com/callback',
                'google.com',
                API_KEY,
                tenantId,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(restFetchSpy).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    body: expect.objectContaining({
                        tenantId: tenantId
                    })
                })
            );
        });

        it('should handle error response', async () => {
            const mockError = {
                code: 400,
                message: 'CREDENTIAL_TOO_OLD_LOGIN_AGAIN'
            };

            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: { error: mockError }
            });

            const result = await linkWithOAuthCredential(
                'old-id-token',
                'provider-token',
                'https://example.com/callback',
                'google.com',
                API_KEY
            );

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        });
    });

    describe('unlinkProvider', () => {
        it('should unlink provider successfully', async () => {
            const mockResponse = {
                localId: 'test-uid',
                email: 'test@example.com',
                providerUserInfo: []
            };

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await unlinkProvider(
                'test-id-token',
                'google.com',
                API_KEY,
                undefined,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(result.error).toBeNull();
            expect(restFetchSpy).toHaveBeenCalledWith(
                'https://identitytoolkit.googleapis.com/v1/accounts:update',
                expect.objectContaining({
                    body: {
                        idToken: 'test-id-token',
                        deleteProvider: ['google.com']
                    },
                    params: { key: API_KEY }
                })
            );
        });

        it('should include tenant ID when provided', async () => {
            const mockResponse = {
                localId: 'test-uid',
                providerUserInfo: []
            };
            const tenantId = 'tenant-abc';

            const restFetchSpy = vi
                .mocked(restFetch.restFetch)
                .mockResolvedValue({
                    data: mockResponse,
                    error: null
                });

            const result = await unlinkProvider(
                'test-id-token',
                'github.com',
                API_KEY,
                tenantId,
                mockFetch
            );

            expect(result.data).toEqual(mockResponse);
            expect(restFetchSpy).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    body: expect.objectContaining({
                        tenantId: tenantId
                    })
                })
            );
        });

        it('should handle error response', async () => {
            const mockError = {
                code: 400,
                message: 'INVALID_ID_TOKEN'
            };

            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: { error: mockError }
            });

            const result = await unlinkProvider(
                'invalid-token',
                'google.com',
                API_KEY
            );

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        });
    });
});

describe('provider authorization endpoints', () => {
    it.each([
        'apple.com',
        'microsoft.com',
        'yahoo.com',
        'oidc.company',
        'facebook.com'
    ])('preserves returned nonce when linking %s', async (providerId) => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: { idToken: 'linked' },
            error: null
        });
        await linkWithOAuthCredential(
            'existing',
            { idToken: 'provider-id', rawNonce: 'nonce&+' },
            'https://app',
            providerId,
            'key'
        );
        const options = vi.mocked(restFetch.restFetch).mock.calls.at(-1)![1]!;
        const body = options.body as { postBody: string };
        const post = new URLSearchParams(body.postBody);
        expect(post.get('nonce')).toBe('nonce&+');
        expect(post.get('id_token')).toBe('provider-id');
        expect(post.get('providerId')).toBe(providerId);
    });
    it('retains EMAIL_EXISTS credentials for automatic linking without mutating the response', async () => {
        const response = Object.freeze({
            errorMessage: 'EMAIL_EXISTS',
            email: 'user@example.com',
            providerId: 'facebook.com',
            oauthAccessToken: 'access'
        });
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: response,
            error: null
        });
        const result = await executeProviderSignIn(
            { callback: { requestUri: 'https://app', sessionId: 's' } },
            'key'
        );
        expect(result).toEqual({
            data: { ...response, needConfirmation: true },
            error: null
        });
        expect(response).not.toHaveProperty('needConfirmation');
    });
    it.each([
        'EMAIL_EXISTS',
        'FEDERATED_USER_ID_ALREADY_LINKED',
        'USER_DISABLED'
    ])('rejects HTTP-success linking errors: %s', async (errorMessage) => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: { errorMessage, idToken: 'must-not-be-used' },
            error: null
        });
        const result = await executeProviderSignIn(
            {
                callback: {
                    requestUri: 'https://app',
                    pendingToken: 'pending'
                },
                idToken: 'existing'
            },
            'key'
        );
        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
    });
    beforeEach(() => vi.resetAllMocks());
    it.each([
        'facebook.com',
        'apple.com',
        'twitter.com',
        'microsoft.com',
        'yahoo.com',
        'oidc.company',
        'saml.company'
    ])(
        'starts %s authorization with tenant and options',
        async (providerId) => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: { authUri: 'https://provider', sessionId: 'session' },
                error: null
            });
            const fetchFn = vi.fn();
            const result = await createAuthUri(
                'https://app/callback',
                'key',
                'tenant',
                fetchFn,
                providerId,
                {
                    addScopes: ['email', 'profile'],
                    customParameters: { tenant: 'organization' }
                }
            );
            expect(result.data?.sessionId).toBe('session');
            expect(restFetch.restFetch).toHaveBeenCalledWith(
                expect.stringContaining('accounts:createAuthUri'),
                expect.objectContaining({
                    global: { fetch: fetchFn },
                    params: { key: 'key' },
                    body: {
                        continueUri: 'https://app/callback',
                        providerId,
                        tenantId: 'tenant',
                        oauthScope: 'email profile',
                        customParameter: { tenant: 'organization' }
                    }
                })
            );
        }
    );
    it.each([false, true])(
        'encodes Twitter sign-in/link credentials (link=%s)',
        async (link) => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: { idToken: 'firebase' },
                error: null
            });
            const credential = { accessToken: 'a&b', secret: 's+e' };
            if (link)
                await linkWithOAuthCredential(
                    'firebase-user',
                    credential,
                    'https://app',
                    'twitter.com',
                    'key',
                    'tenant'
                );
            else
                await signInWithIdp(
                    credential,
                    'https://app',
                    'twitter.com',
                    'key',
                    'tenant'
                );
            const options = vi.mocked(restFetch.restFetch).mock.calls[0]![1]!;
            const body = options.body as Record<string, string>;
            const post = new URLSearchParams(body.postBody);
            expect(post.get('access_token')).toBe('a&b');
            expect(post.get('oauth_token_secret')).toBe('s+e');
            expect(post.get('providerId')).toBe('twitter.com');
            expect(body.tenantId).toBe('tenant');
            expect(body.idToken).toBe(link ? 'firebase-user' : undefined);
        }
    );
    it('completes form callbacks with session binding and optional linking', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: { idToken: 'firebase' },
            error: null
        });
        const result = await executeProviderSignIn(
            {
                callback: {
                    requestUri: 'https://app/callback',
                    sessionId: 'session',
                    postBody: 'SAMLResponse=encoded'
                },
                idToken: 'existing-user'
            },
            'key',
            'tenant'
        );
        expect(result.data?.idToken).toBe('firebase');
        expect(restFetch.restFetch).toHaveBeenCalledWith(
            expect.stringContaining('accounts:signInWithIdp'),
            expect.objectContaining({
                body: {
                    requestUri: 'https://app/callback',
                    sessionId: 'session',
                    postBody: 'SAMLResponse=encoded',
                    idToken: 'existing-user',
                    returnSecureToken: true,
                    returnIdpCredential: true,
                    tenantId: 'tenant'
                }
            })
        );
    });
    it('rejects incomplete callbacks before fetching', async () => {
        const request = executeProviderSignIn(
            { callback: { requestUri: 'https://app', sessionId: '' } },
            'key'
        );
        await expect(request).rejects.toThrow('session ID');
        expect(restFetch.restFetch).not.toHaveBeenCalled();
    });
    it('links a pending credential without replaying the authorization callback', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: { idToken: 'linked' },
            error: null
        });
        const result = await executeProviderSignIn(
            {
                callback: {
                    requestUri: 'https://app/callback',
                    pendingToken: 'pending'
                },
                idToken: 'existing'
            },
            'key',
            'tenant'
        );
        expect(result.data?.idToken).toBe('linked');
        expect(restFetch.restFetch).toHaveBeenCalledWith(
            expect.stringContaining('accounts:signInWithIdp'),
            expect.objectContaining({
                body: {
                    requestUri: 'https://app/callback',
                    pendingToken: 'pending',
                    idToken: 'existing',
                    returnSecureToken: true,
                    returnIdpCredential: true,
                    tenantId: 'tenant'
                }
            })
        );
    });
    it.each([
        { requestUri: 'https://app/callback', pendingToken: '' },
        { requestUri: '', pendingToken: 'pending' }
    ])('rejects incomplete pending credentials: %j', async (callback) => {
        const result = executeProviderSignIn({ callback }, 'key');
        await expect(result).rejects.toThrow('pending token');
        expect(restFetch.restFetch).not.toHaveBeenCalled();
    });
    it('maps provider authorization errors', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: null,
            error: { error: { message: 'OPERATION_NOT_ALLOWED' } }
        });
        const result = await createAuthUri(
            'https://app',
            'key',
            undefined,
            undefined,
            'facebook'
        );
        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
    });
});

describe('password reset and email changes', () => {
    beforeEach(() => vi.resetAllMocks());
    it('sends a verification to the new email with the user token and tenant', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: { email: 'new@example.com' },
            error: null
        });
        const fetchFn = vi.fn();
        const result = await sendOobCode(
            'VERIFY_AND_CHANGE_EMAIL',
            'key',
            {
                idToken: 'id',
                newEmail: 'new@example.com',
                continueUrl: 'https://app/auth/callback',
                locale: 'fr'
            },
            'tenant',
            fetchFn
        );
        expect(result.error).toBeNull();
        expect(restFetch.restFetch).toHaveBeenCalledWith(
            'https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode',
            expect.objectContaining({
                global: { fetch: fetchFn },
                params: { key: 'key' },
                headers: { 'X-Firebase-Locale': 'fr' },
                body: {
                    requestType: 'VERIFY_AND_CHANGE_EMAIL',
                    idToken: 'id',
                    newEmail: 'new@example.com',
                    continueUrl: 'https://app/auth/callback',
                    canHandleCodeInApp: false,
                    tenantId: 'tenant'
                }
            })
        );
    });
    it.each(['email', 'token', 'url'])(
        'rejects invalid email-change %s',
        async (field) => {
            const result = await sendOobCode('VERIFY_AND_CHANGE_EMAIL', 'key', {
                idToken: field === 'token' ? '' : 'id',
                newEmail: field === 'email' ? 'bad' : 'a@b.com',
                continueUrl: field === 'url' ? 'javascript:bad' : 'https://app'
            });
            expect(result.error).toBeTruthy();
            expect(restFetch.restFetch).not.toHaveBeenCalled();
        }
    );
    it('rejects an invalid reset email', async () => {
        const result = await sendOobCode('PASSWORD_RESET', 'key', {
            email: 'bad'
        });
        expect(result.error).toBeTruthy();
        expect(restFetch.restFetch).not.toHaveBeenCalled();
    });
    it('completes a reset with the exact password and tenant', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: { email: 'a@b.com' },
            error: null
        });
        const fetchFn = vi.fn();
        const result = await confirmPasswordReset(
            'code',
            ' password ',
            'key',
            'tenant',
            fetchFn
        );
        expect(result.data).toEqual({ email: 'a@b.com' });
        expect(restFetch.restFetch).toHaveBeenCalledWith(
            'https://identitytoolkit.googleapis.com/v1/accounts:resetPassword',
            {
                global: { fetch: fetchFn },
                params: { key: 'key' },
                body: {
                    oobCode: 'code',
                    newPassword: ' password ',
                    tenantId: 'tenant'
                }
            }
        );
    });
    it.each([
        ['', 'password'],
        ['code', '']
    ])('rejects empty reset inputs', async (code, password) => {
        const result = await confirmPasswordReset(code!, password!, 'key');
        expect(result.error).toBeTruthy();
        expect(restFetch.restFetch).not.toHaveBeenCalled();
    });
    it('applies an email code with tenant and custom fetch', async () => {
        vi.mocked(restFetch.restFetch).mockResolvedValue({
            data: { email: 'new@b.com' },
            error: null
        });
        const fetchFn = vi.fn();
        const result = await applyActionCode('code', 'key', 'tenant', fetchFn);
        expect(result.error).toBeNull();
        expect(restFetch.restFetch).toHaveBeenCalledWith(
            'https://identitytoolkit.googleapis.com/v1/accounts:update',
            {
                global: { fetch: fetchFn },
                params: { key: 'key' },
                body: { oobCode: 'code', tenantId: 'tenant' }
            }
        );
    });
    it('rejects a missing email code', async () => {
        const result = await applyActionCode(' ', 'key');
        expect(result.error?.code).toBe('auth/invalid-action-code');
        expect(restFetch.restFetch).not.toHaveBeenCalled();
    });
    it.each(['reset', 'email'])(
        'maps expired code errors for %s',
        async (operation) => {
            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: null,
                error: { error: { message: 'EXPIRED_OOB_CODE' } }
            });
            const result =
                operation === 'reset'
                    ? await confirmPasswordReset('code', 'password', 'key')
                    : await applyActionCode('code', 'key');
            expect(result.error?.code).toBe('auth/expired-action-code');
        }
    );
});
