import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
    refreshFirebaseIdToken,
    createAuthUri,
    signInWithIdp,
    signInWithCustomToken,
    getAccountInfoByUid,
    createSessionCookie,
    getJWKs,
    getPublicKeys
} from './firebase-auth-endpoints.js';
import * as restFetch from '../rest-fetch.js';
import { FirebaseEdgeError, FirebaseEndpointErrorInfo } from './errors.js';

vi.mock('../rest-fetch.js');

describe('firebase-auth-endpoints', () => {
    const mockFetch = vi.fn();
    const API_KEY = 'test-api-key';
    const PROJECT_ID = 'test-project';
    const ACCESS_TOKEN = 'test-access-token';

    beforeEach(() => {
        vi.clearAllMocks();
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
                        providerId: 'google.com'
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

    describe('getAccountInfoByUid', () => {
        it('should get account info successfully', async () => {
            const mockUser = { localId: 'user-123', email: 'test@example.com' };

            vi.mocked(restFetch.restFetch).mockResolvedValue({
                data: { users: [mockUser] },
                error: null
            });

            const result = await getAccountInfoByUid(
                'user-123',
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

            const result = await getAccountInfoByUid(
                'user-123',
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
                        localId: 'user-123',
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

            const result = await getAccountInfoByUid(
                'user-123',
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
                .calls[0] as unknown as [string, any];

            expect(calledUrl).toBe(
                `https://identitytoolkit.googleapis.com/v1/projects/${projectId}:createSessionCookie`
            );
            expect(options.bearerToken).toBe(token);
            expect(options.body.idToken).toBe(idToken);
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
            const [calledUrl] = restFetchSpy.mock.calls[0] as [string, any];

            expect(calledUrl).toBe(
                `https://identitytoolkit.googleapis.com/v1/projects/test-project/tenants/${tenantId}:createSessionCookie`
            );
        });

        it('should call accounts lookup URL with /accounts segment via getAccountInfoByUid', async () => {
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

            const result = await getAccountInfoByUid(
                uid,
                token,
                projectId,
                undefined,
                vi.fn()
            );

            expect(result.data).toEqual(mockUser);
            expect(restFetchSpy).toHaveBeenCalledTimes(1);

            const [calledUrl, options] = restFetchSpy.mock
                .calls[0] as unknown as [string, any];

            expect(calledUrl).toBe(
                `https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:lookup`
            );
            expect(options.bearerToken).toBe(token);
            expect(options.body.localId).toBe(uid);
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

            const result = await getAccountInfoByUid(
                'user-123',
                'access-token',
                'test-project',
                tenantId,
                vi.fn()
            );

            expect(result.data).toEqual(mockUser);
            const [calledUrl] = restFetchSpy.mock.calls[0] as [string, any];

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
});
