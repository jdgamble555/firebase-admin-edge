import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { FirebaseAuth } from './firebase-auth.js';
import * as endpoints from './firebase-auth-endpoints.js';
import { FirebaseEdgeError } from './errors.js';
import { mapFirebaseError } from './auth-endpoint-errors.js';
import { FirebaseAuthErrorInfo } from './auth-error-codes.js';

vi.mock('./firebase-auth-endpoints.js', async (importOriginal) => {
    const actual =
        await importOriginal<typeof import('./firebase-auth-endpoints.js')>();
    return {
        ...actual,
        signInWithIdp: vi.fn(),
        executeProviderSignIn: vi.fn(),
        createAuthUri: vi.fn(),
        signInWithCustomToken: vi.fn(),
        linkWithOAuthCredential: vi.fn(),
        unlinkProvider: vi.fn(),
        sendOobCode: vi.fn(),
        confirmPasswordReset: vi.fn(),
        applyActionCode: vi.fn(),
        signInWithEmailLink: vi.fn()
    };
});

describe('FirebaseAuth', () => {
    it.each([undefined, null, 42, {}, '', '   '])(
        'returns invalid custom tokens as results: %j',
        async (token) => {
            const { error, data } = await firebaseAuth.signInWithCustomToken(
                token as never
            );
            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(data).toBeNull();
            expect(endpoints.signInWithCustomToken).not.toHaveBeenCalled();
        }
    );
    it.each([undefined, null, 42, {}])(
        'returns invalid email-link codes as results: %j',
        async (code) => {
            const { error, data } = await firebaseAuth.signInWithEmailLink(
                'a@b.com',
                code as never
            );
            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(data).toBeNull();
            expect(endpoints.signInWithEmailLink).not.toHaveBeenCalled();
        }
    );
    it('does not expose custom tokens in error context', async () => {
        vi.mocked(endpoints.signInWithCustomToken).mockRejectedValue(
            new Error('offline')
        );
        const { error, data } = await firebaseAuth.signInWithCustomToken(
            'secret-custom-token'
        );
        expect(data).toBeNull();
        expect(error?.context).toEqual({ operation: 'signInWithCustomToken' });
    });
    it('sends and completes email links with project, tenant, and custom fetch', async () => {
        const fetchFn = vi.fn();
        const auth = new FirebaseAuth(mockConfig, 'https://app/callback', {
            tenantId: 'tenant',
            fetch: fetchFn
        });
        vi.mocked(endpoints.sendOobCode).mockResolvedValue({
            data: { email: 'a@b.com' },
            error: null
        });
        vi.mocked(endpoints.signInWithEmailLink).mockResolvedValue({
            data: { idToken: 'id' },
            error: null
        });
        const sent = await auth.sendSignInLinkToEmail(
            'a@b.com',
            'https://app/email',
            'en'
        );
        const signed = await auth.signInWithEmailLink('a@b.com', 'code');
        expect(sent.error).toBeNull();
        expect(signed.data?.idToken).toBe('id');
        expect(endpoints.sendOobCode).toHaveBeenCalledWith(
            'EMAIL_SIGNIN',
            mockConfig.apiKey,
            {
                email: 'a@b.com',
                continueUrl: 'https://app/email',
                locale: 'en'
            },
            'tenant',
            fetchFn
        );
        expect(endpoints.signInWithEmailLink).toHaveBeenCalledWith(
            'code',
            'a@b.com',
            mockConfig.apiKey,
            undefined,
            'tenant',
            fetchFn
        );
    });
    it.each([
        ['invalid', 'code'],
        ['a@b.com', '']
    ])('rejects invalid email-link inputs', async (email, code) => {
        const result = await firebaseAuth.signInWithEmailLink(email!, code!);
        expect(result.error).toBeTruthy();
        expect(endpoints.signInWithEmailLink).not.toHaveBeenCalled();
    });
    it('returns email endpoint exceptions as errors', async () => {
        const error = new Error('network');
        vi.mocked(endpoints.sendOobCode).mockRejectedValue(error);
        vi.mocked(endpoints.signInWithEmailLink).mockRejectedValue(error);
        const sent = await firebaseAuth.sendSignInLinkToEmail(
            'a@b.com',
            'https://app'
        );
        const signed = await firebaseAuth.signInWithEmailLink(
            'a@b.com',
            'code'
        );
        expect(sent.error).toBe(error);
        expect(signed.error).toBe(error);
    });
    afterEach(() => vi.unstubAllEnvs());
    it('routes client auth to a captured emulator host and allows production opt-out', async () => {
        vi.stubEnv('FIREBASE_AUTH_EMULATOR_HOST', 'localhost:9099');
        const fetchFn = vi.fn().mockResolvedValue(new Response('{}'));
        const emulator = new FirebaseAuth(mockConfig, 'http://localhost', {
            tenantId: 't',
            fetch: fetchFn
        });
        const production = new FirebaseAuth(mockConfig, 'http://localhost', {
            fetch: fetchFn,
            emulatorHost: null
        });
        vi.stubEnv('FIREBASE_AUTH_EMULATOR_HOST', 'different:9199');
        vi.mocked(endpoints.signInWithCustomToken).mockResolvedValue({
            data: { idToken: 'id' },
            error: null
        });
        await emulator.signInWithCustomToken('custom');
        const transport = vi.mocked(endpoints.signInWithCustomToken).mock
            .calls[0]![3]!;
        await transport(
            'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=fake'
        );
        expect(fetchFn.mock.calls[0]![0]).toBe(
            'http://localhost:9099/identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=fake'
        );
        await production.signInWithCustomToken('custom');
        expect(endpoints.signInWithCustomToken).toHaveBeenLastCalledWith(
            'custom',
            mockConfig.apiKey,
            undefined,
            fetchFn
        );
    });
    const mockConfig = {
        apiKey: 'test-api-key',
        authDomain: 'test-project.firebaseapp.com',
        projectId: 'test-project'
    };

    let firebaseAuth: FirebaseAuth;
    let mockFetch: typeof globalThis.fetch;

    beforeEach(() => {
        vi.clearAllMocks();
        mockFetch = vi.fn() as unknown as typeof globalThis.fetch;
        firebaseAuth = new FirebaseAuth(mockConfig, 'http://localhost', {
            fetch: mockFetch
        });
    });

    describe('signInWithProvider', () => {
        it('should return data on successful sign in', async () => {
            const mockData = {
                idToken: 'token123',
                refreshToken: 'refresh123',
                expiresIn: '3600',
                localId: 'user123',
                providerId: 'google.com',
                federatedId: 'fed123'
            };
            vi.mocked(endpoints.signInWithIdp).mockResolvedValue({
                data: mockData,
                error: null
            });

            const result = await firebaseAuth.signInWithProvider(
                'idToken',
                'google.com'
            );

            expect(result.data).toEqual(mockData);
            expect(result.error).toBeNull();
            expect(endpoints.signInWithIdp).toHaveBeenCalledWith(
                'idToken',
                'http://localhost',
                'google.com',
                'test-api-key',
                undefined,
                mockFetch
            );
        });

        it('should return error on failed sign in', async () => {
            const mockError = mapFirebaseError({
                code: 400,
                message: 'INVALID_ID_TOKEN'
            });
            vi.mocked(endpoints.signInWithIdp).mockResolvedValue({
                data: null,
                error: mockError
            });

            const result = await firebaseAuth.signInWithProvider('idToken');

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/provider-sign-in-failed');
            expect(result.error?.message).toBe(
                FirebaseAuthErrorInfo.AUTH_PROVIDER_SIGN_IN_FAILED.message
            );
        });

        it('should return error when no data returned', async () => {
            vi.mocked(endpoints.signInWithIdp).mockResolvedValue({
                data: null,
                error: null
            });

            const result = await firebaseAuth.signInWithProvider('idToken');

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/provider-data-missing');
            expect(result.error?.message).toBe(
                FirebaseAuthErrorInfo.AUTH_PROVIDER_DATA_MISSING.message
            );
        });
    });

    describe('signInWithCustomToken', () => {
        it('should return data on successful sign in', async () => {
            const mockData = {
                idToken: 'token456',
                refreshToken: 'refresh456',
                expiresIn: '3600',
                localId: 'user456',
                providerId: 'custom',
                federatedId: 'fed456'
            };
            vi.mocked(endpoints.signInWithCustomToken).mockResolvedValue({
                data: mockData,
                error: null
            });

            const result =
                await firebaseAuth.signInWithCustomToken('customToken');

            expect(result.data).toEqual(mockData);
            expect(result.error).toBeNull();
            expect(endpoints.signInWithCustomToken).toHaveBeenCalledWith(
                'customToken',
                'test-api-key',
                undefined,
                mockFetch
            );
        });

        it('should return error on failed sign in', async () => {
            const mockError = mapFirebaseError({
                code: 400,
                message: 'INVALID_CUSTOM_TOKEN'
            });
            vi.mocked(endpoints.signInWithCustomToken).mockResolvedValue({
                data: null,
                error: mockError
            });

            const result =
                await firebaseAuth.signInWithCustomToken('customToken');

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/invalid-custom-token');
            expect(result.error?.message).toBe(
                FirebaseAuthErrorInfo.AUTH_INVALID_CUSTOM_TOKEN.message
            );
        });

        it('should return error when no data returned', async () => {
            vi.mocked(endpoints.signInWithCustomToken).mockResolvedValue({
                data: null,
                error: null
            });

            const result =
                await firebaseAuth.signInWithCustomToken('customToken');

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/provider-data-missing');
            expect(result.error?.message).toBe(
                FirebaseAuthErrorInfo.AUTH_PROVIDER_DATA_MISSING.message
            );
        });
    });

    describe('linkWithCredential', () => {
        it('should return data on successful link', async () => {
            const mockData = {
                idToken: 'new-token',
                refreshToken: 'new-refresh',
                expiresIn: '3600',
                localId: 'user123',
                providerId: 'google.com',
                federatedId: 'google-fed-id'
            };
            vi.mocked(endpoints.linkWithOAuthCredential).mockResolvedValue({
                data: mockData,
                error: null
            });

            const result = await firebaseAuth.linkWithCredential(
                'existing-id-token',
                'provider-token',
                'google.com'
            );

            expect(result.data).toEqual(mockData);
            expect(result.error).toBeNull();
            expect(endpoints.linkWithOAuthCredential).toHaveBeenCalledWith(
                'existing-id-token',
                'provider-token',
                'http://localhost',
                'google.com',
                'test-api-key',
                undefined,
                mockFetch
            );
        });

        it('should return error on failed link', async () => {
            const mockError = mapFirebaseError({
                code: 400,
                message: 'CREDENTIAL_TOO_OLD_LOGIN_AGAIN'
            });
            vi.mocked(endpoints.linkWithOAuthCredential).mockResolvedValue({
                data: null,
                error: mockError
            });

            const result = await firebaseAuth.linkWithCredential(
                'old-id-token',
                'provider-token',
                'google.com'
            );

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/provider-link-failed');
            expect(result.error?.message).toBe(
                FirebaseAuthErrorInfo.AUTH_PROVIDER_LINK_FAILED.message
            );
        });

        it('should return error when no data returned', async () => {
            vi.mocked(endpoints.linkWithOAuthCredential).mockResolvedValue({
                data: null,
                error: null
            });

            const result = await firebaseAuth.linkWithCredential(
                'id-token',
                'provider-token',
                'google.com'
            );

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/provider-data-missing');
            expect(result.error?.message).toBe(
                FirebaseAuthErrorInfo.AUTH_PROVIDER_DATA_MISSING.message
            );
        });

        it('should handle exceptions during link', async () => {
            vi.mocked(endpoints.linkWithOAuthCredential).mockRejectedValue(
                new Error('Network error')
            );

            const result = await firebaseAuth.linkWithCredential(
                'id-token',
                'provider-token',
                'google.com'
            );

            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/provider-link-failed');
        });
    });
});

describe('FirebaseAuth provider authorization', () => {
    const fetchFn = vi.fn();
    const auth = new FirebaseAuth(
        { apiKey: 'key', projectId: 'p', authDomain: 'p.firebaseapp.com' },
        'https://app/callback',
        { tenantId: 'tenant', fetch: fetchFn, emulatorHost: null }
    );
    beforeEach(() => vi.resetAllMocks());
    it('delegates authorization with options', async () => {
        const response = {
            data: { authUri: 'https://provider', sessionId: 'session' },
            error: null
        };
        vi.mocked(endpoints.createAuthUri).mockResolvedValue(response);
        const options = { addScopes: ['email'] };
        const result = await auth.createProviderAuthorization(
            'apple.com',
            options
        );
        expect(result).toEqual(response);
        expect(endpoints.createAuthUri).toHaveBeenCalledWith(
            'https://app/callback',
            'key',
            'tenant',
            fetchFn,
            'apple.com',
            options
        );
    });
    it.each([
        { requestUri: 'https://app/callback?code=code', sessionId: 'session' },
        { requestUri: 'https://app/callback', pendingToken: 'pending' }
    ])(
        'delegates callback and pending linking credentials: %j',
        async (callback) => {
            vi.mocked(endpoints.executeProviderSignIn).mockResolvedValue({
                data: { idToken: 'firebase' },
                error: null
            });
            const result = await auth.signInWithProviderCallback(
                callback,
                'existing'
            );
            expect(result.data?.idToken).toBe('firebase');
            expect(endpoints.executeProviderSignIn).toHaveBeenCalledWith(
                { callback, idToken: 'existing' },
                'key',
                'tenant',
                fetchFn
            );
        }
    );
    it('returns endpoint errors and catches transport exceptions', async () => {
        const error = new Error('network');
        vi.mocked(endpoints.createAuthUri).mockRejectedValue(error);
        vi.mocked(endpoints.executeProviderSignIn).mockRejectedValue(error);
        const start = await auth.createProviderAuthorization('facebook');
        const finish = await auth.signInWithProviderCallback({
            requestUri: 'https://app',
            sessionId: 'session'
        });
        expect(start.error).toBe(error);
        expect(finish.error).toBe(error);
    });
    it('forwards structured credentials for sign-in and linking', async () => {
        const credential = { accessToken: 'twitter', secret: 'secret' };
        vi.mocked(endpoints.signInWithIdp).mockResolvedValue({
            data: { idToken: 'id' },
            error: null
        });
        vi.mocked(endpoints.linkWithOAuthCredential).mockResolvedValue({
            data: { idToken: 'id' },
            error: null
        });
        await auth.signInWithProvider(credential, 'twitter.com');
        await auth.linkWithCredential('existing', credential, 'twitter.com');
        expect(endpoints.signInWithIdp).toHaveBeenCalledWith(
            credential,
            'https://app/callback',
            'twitter.com',
            'key',
            'tenant',
            fetchFn
        );
        expect(endpoints.linkWithOAuthCredential).toHaveBeenCalledWith(
            'existing',
            credential,
            'https://app/callback',
            'twitter.com',
            'key',
            'tenant',
            fetchFn
        );
    });
});

describe('email account actions', () => {
    beforeEach(() => vi.resetAllMocks());
    it.each(['reset-email', 'change-email', 'reset', 'apply'])(
        'delegates %s with project, tenant, fetch and returns failures',
        async (operation) => {
            const fetchFn = vi.fn();
            const auth = new FirebaseAuth(
                { apiKey: 'key' } as ConstructorParameters<
                    typeof FirebaseAuth
                >[0],
                'https://app/callback',
                { tenantId: 'tenant', fetch: fetchFn }
            );
            const failure = {
                data: null,
                error: new FirebaseEdgeError({
                    code: 'auth/invalid-action-code',
                    message: 'Invalid'
                })
            };
            vi.mocked(endpoints.sendOobCode).mockResolvedValue(failure);
            vi.mocked(endpoints.confirmPasswordReset).mockResolvedValue(
                failure
            );
            vi.mocked(endpoints.applyActionCode).mockResolvedValue(failure);
            const result =
                operation === 'reset-email'
                    ? await auth.sendPasswordResetEmail(
                          'a@b.com',
                          undefined,
                          'fr'
                      )
                    : operation === 'change-email'
                      ? await auth.verifyBeforeUpdateEmail(
                            'id',
                            'new@b.com',
                            undefined,
                            'fr'
                        )
                      : operation === 'reset'
                        ? await auth.confirmPasswordReset('code', 'password')
                        : await auth.applyActionCode('code');
            expect(result).toBe(failure);
            if (operation === 'reset-email')
                expect(endpoints.sendOobCode).toHaveBeenCalledWith(
                    'PASSWORD_RESET',
                    'key',
                    {
                        email: 'a@b.com',
                        continueUrl: 'https://app/callback',
                        locale: 'fr'
                    },
                    'tenant',
                    fetchFn
                );
            if (operation === 'change-email')
                expect(endpoints.sendOobCode).toHaveBeenCalledWith(
                    'VERIFY_AND_CHANGE_EMAIL',
                    'key',
                    {
                        idToken: 'id',
                        newEmail: 'new@b.com',
                        continueUrl: 'https://app/callback',
                        locale: 'fr'
                    },
                    'tenant',
                    fetchFn
                );
            if (operation === 'reset')
                expect(endpoints.confirmPasswordReset).toHaveBeenCalledWith(
                    'code',
                    'password',
                    'key',
                    'tenant',
                    fetchFn
                );
            if (operation === 'apply')
                expect(endpoints.applyActionCode).toHaveBeenCalledWith(
                    'code',
                    'key',
                    'tenant',
                    fetchFn
                );
        }
    );
    it.each(['reset-email', 'change-email', 'reset', 'apply'])(
        'catches network exceptions for %s',
        async (operation) => {
            const auth = new FirebaseAuth(
                { apiKey: 'key' } as ConstructorParameters<
                    typeof FirebaseAuth
                >[0],
                'https://app'
            );
            const error = new Error('Offline');
            vi.mocked(endpoints.sendOobCode).mockRejectedValue(error);
            vi.mocked(endpoints.confirmPasswordReset).mockRejectedValue(error);
            vi.mocked(endpoints.applyActionCode).mockRejectedValue(error);
            const result =
                operation === 'reset-email'
                    ? await auth.sendPasswordResetEmail('a@b.com')
                    : operation === 'change-email'
                      ? await auth.verifyBeforeUpdateEmail('id', 'new@b.com')
                      : operation === 'reset'
                        ? await auth.confirmPasswordReset('code', 'password')
                        : await auth.applyActionCode('code');
            expect(result.error).toBe(error);
        }
    );
});
