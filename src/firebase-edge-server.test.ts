import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import {
    createFirebaseEdgeServer,
    OFFICIAL_FIREBASE_OAUTH_PROVIDERS
} from './firebase-edge-server.js';
import type { ServiceAccount, FirebaseConfig } from './auth/firebase-types.js';
import { FirebaseEdgeError } from './auth/errors.js';
import { FirebaseEdgeServerErrorInfo } from './firebase-edge-errors.js';
import { AppCheck } from './app-check/app-check.js';
import { Storage } from './storage/storage.js';
import { Identity } from './auth/identity.js';

// Mock dependencies
vi.mock('./auth/firebase-admin-auth.js');
vi.mock('./db/firestore.js');
vi.mock('./app-check/app-check.js');
vi.mock('./storage/storage.js');
vi.mock('./auth/identity.js');
vi.mock('./auth/firebase-auth.js');
vi.mock('./auth/firebase-jwt.js');

// Import the mocked classes to verify constructor calls
const { FirebaseAdminAuth } = await import('./auth/firebase-admin-auth.js');
const { FirebaseAuth } = await import('./auth/firebase-auth.js');
const { Firestore } = await import('./db/firestore.js');

const mockServiceAccount: ServiceAccount = {
    type: 'service_account',
    project_id: 'test-project',
    private_key_id: 'key-id',
    private_key: 'private-key',
    client_email: 'test@test-project.iam.gserviceaccount.com',
    client_id: 'client-id',
    auth_uri: 'https://accounts.google.com/o/oauth2/auth',
    token_uri: 'https://oauth2.googleapis.com/token',
    auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
    client_x509_cert_url:
        'https://www.googleapis.com/robot/v1/metadata/x509/test%40test-project.iam.gserviceaccount.com'
};

const mockFirebaseConfig: FirebaseConfig = {
    apiKey: 'test-api-key',
    authDomain: 'test-project.firebaseapp.com',
    projectId: 'test-project',
    storageBucket: 'test-project.appspot.com',
    messagingSenderId: '123456789',
    appId: 'test-app-id'
};

describe('createFirebaseEdgeServer', () => {
    let mockGetSession: Mock;
    let mockSaveSession: Mock;
    let server: ReturnType<typeof createFirebaseEdgeServer>;

    beforeEach(() => {
        vi.clearAllMocks();
        mockGetSession = vi.fn();
        mockSaveSession = vi.fn();

        server = createFirebaseEdgeServer({
            serviceAccount: mockServiceAccount,
            firebaseConfig: mockFirebaseConfig,
            cookies: {
                getSession: mockGetSession,
                saveSession: mockSaveSession
            },
            redirectUri: 'http://localhost'
        });
    });

    it('exposes App Check with the configured service account', () => {
        expect(server.appCheck).toBeInstanceOf(AppCheck);
        expect(AppCheck).toHaveBeenCalledWith(mockServiceAccount, {
            fetch: globalThis.fetch,
            cache: undefined,
            cacheName: undefined
        });
    });

    it('exposes Identity with tenant, cache, fetch and emulator configuration', () => {
        const fetchFn = vi.fn();
        const cache = { getCache: vi.fn(), setCache: vi.fn() };
        const configured = createFirebaseEdgeServer({
            serviceAccount: mockServiceAccount,
            firebaseConfig: mockFirebaseConfig,
            cookies: {
                getSession: mockGetSession,
                saveSession: mockSaveSession
            },
            redirectUri: 'http://localhost',
            tenantId: 'tenant',
            fetch: fetchFn,
            cache,
            cacheName: 'custom',
            authEmulatorHost: 'localhost:9099'
        });
        expect(configured.identity).toBeInstanceOf(Identity);
        expect(Identity).toHaveBeenLastCalledWith(mockServiceAccount, {
            tenantId: 'tenant',
            fetch: fetchFn,
            cache,
            cacheName: 'custom',
            emulatorHost: 'localhost:9099'
        });
    });

    it('exposes Storage with the configured bucket, fetch and cache', () => {
        const customFetch = vi.fn();
        const cache = { getCache: vi.fn(), setCache: vi.fn() };
        const configured = createFirebaseEdgeServer({
            serviceAccount: mockServiceAccount,
            firebaseConfig: mockFirebaseConfig,
            cookies: {
                getSession: mockGetSession,
                saveSession: mockSaveSession
            },
            redirectUri: 'http://localhost',
            fetch: customFetch,
            cache,
            cacheName: 'custom'
        });
        expect(configured.storage).toBeInstanceOf(Storage);
        expect(Storage).toHaveBeenLastCalledWith(mockServiceAccount, {
            bucketName: mockFirebaseConfig.storageBucket,
            fetch: customFetch,
            cache,
            cacheName: 'custom'
        });
    });

    describe('shared callback handling', () => {
        it.each([
            'signIn',
            'resetPassword',
            'verifyAndChangeEmail',
            'verifyEmail',
            'recoverEmail'
        ])('describes %s without exposing codes or consuming them', (mode) => {
            const result = server.getCallbackAction(
                new URL(`https://app/callback?mode=${mode}&oobCode=secret`)
            );
            expect(result).toEqual({
                data: { actionMode: mode, hasLink: true },
                error: null
            });
            expect(server.auth.confirmPasswordReset).not.toHaveBeenCalled();
            expect(server.auth.applyActionCode).not.toHaveBeenCalled();
            expect(server.auth.signInWithEmailLink).not.toHaveBeenCalled();
        });
        it('distinguishes provider callbacks and invalid links', () => {
            expect(
                server.getCallbackAction(
                    new URL('https://app/callback?code=oauth')
                )
            ).toEqual({ data: null, error: null });
            expect(
                server.getCallbackAction(
                    new URL('https://app/callback?mode=unknown')
                ).error
            ).toBeTruthy();
        });
        it.each([
            'resetPassword',
            'verifyAndChangeEmail',
            'verifyEmail',
            'recoverEmail'
        ])('dispatches a wrapped %s callback', async (mode) => {
            vi.mocked(server.auth.confirmPasswordReset).mockResolvedValue({
                data: { email: 'a@b.com' },
                error: null
            });
            vi.mocked(server.auth.applyActionCode).mockResolvedValue({
                data: { email: 'a@b.com' },
                error: null
            });
            const url = new URL('https://app/link');
            url.searchParams.set(
                'link',
                `https://app/callback?mode=${mode}&oobCode=code`
            );
            const result = await server.handleCallback(url, {
                newPassword: ' password ',
                confirmPassword: ' password '
            });
            expect(result).toMatchObject({
                data: { type: 'complete' },
                error: null
            });
            if (mode === 'resetPassword')
                expect(server.auth.confirmPasswordReset).toHaveBeenCalledWith(
                    'code',
                    ' password '
                );
            else
                expect(server.auth.applyActionCode).toHaveBeenCalledWith(
                    'code'
                );
            expect(mockSaveSession).toHaveBeenCalledWith(
                '__session',
                '',
                expect.objectContaining({ maxAge: 0 })
            );
        });
        it.each([
            'missing-code',
            'mismatch',
            'unknown',
            'wrong-project',
            'endpoint'
        ])('returns callback errors for %s', async (failure) => {
            const error = new FirebaseEdgeError({
                code: 'auth/expired-action-code',
                message: 'Expired'
            });
            vi.mocked(server.auth.confirmPasswordReset).mockResolvedValue({
                data: null,
                error
            });
            const url = new URL(
                `https://app/callback?mode=${failure === 'unknown' ? 'unknown' : 'resetPassword'}`
            );
            if (failure !== 'missing-code')
                url.searchParams.set('oobCode', 'code');
            if (failure === 'wrong-project')
                url.searchParams.set('apiKey', 'wrong');
            const result = await server.handleCallback(url, {
                newPassword: 'password',
                confirmPassword: failure === 'mismatch' ? 'other' : 'password'
            });
            expect(result.error).toBeTruthy();
            expect(mockSaveSession).not.toHaveBeenCalled();
            if (failure !== 'endpoint')
                expect(server.auth.confirmPasswordReset).not.toHaveBeenCalled();
        });
        it('preserves provider callback options and results', async () => {
            mockGetSession.mockResolvedValue(
                JSON.stringify({
                    sessionId: 'flow',
                    next: '/dashboard',
                    intent: 'signin'
                })
            );
            vi.mocked(server.auth.signInWithProviderCallback).mockResolvedValue(
                { data: { idToken: 'firebase' }, error: null }
            );
            vi.mocked(server.adminAuth.createSessionCookie).mockResolvedValue({
                data: 'session',
                error: null
            });
            const url = new URL('https://app/callback?code=oauth');
            const result = await server.handleCallback(url, {
                postBody: 'code=oauth',
                expiresInMs: 3600000
            });
            expect(result).toEqual({
                data: { type: 'redirect', url: '/dashboard' },
                error: null
            });
            expect(server.auth.signInWithProviderCallback).toHaveBeenCalledWith(
                {
                    requestUri: url.toString(),
                    sessionId: 'flow',
                    postBody: 'code=oauth'
                },
                undefined
            );
            expect(server.adminAuth.createSessionCookie).toHaveBeenCalledWith(
                'firebase',
                { expiresIn: 3600000 }
            );
            expect(server.auth.confirmPasswordReset).not.toHaveBeenCalled();
        });
    });

    describe('email account actions', () => {
        it('sends reset emails through the configured callback', async () => {
            vi.mocked(server.auth.sendPasswordResetEmail).mockResolvedValue({
                data: { email: 'a@b.com' },
                error: null
            });
            const result = await server.sendPasswordResetEmail('a@b.com', 'fr');
            expect(result.error).toBeNull();
            expect(server.auth.sendPasswordResetEmail).toHaveBeenCalledWith(
                'a@b.com',
                'http://localhost',
                'fr'
            );
        });
        it.each(['reset', 'apply'])(
            'clears the session only on successful %s',
            async (operation) => {
                const method =
                    operation === 'reset'
                        ? server.auth.confirmPasswordReset
                        : server.auth.applyActionCode;
                const error = new FirebaseEdgeError({
                    code: 'auth/expired-action-code',
                    message: 'Expired'
                });
                vi.mocked(method)
                    .mockResolvedValueOnce({ data: null, error })
                    .mockResolvedValueOnce({
                        data: { email: 'new@b.com' },
                        error: null
                    });
                const failed =
                    operation === 'reset'
                        ? await server.confirmPasswordReset('code', 'password')
                        : await server.applyActionCode('code');
                expect(failed.error).toBe(error);
                expect(mockSaveSession).not.toHaveBeenCalled();
                const success =
                    operation === 'reset'
                        ? await server.confirmPasswordReset('code', 'password')
                        : await server.applyActionCode('code');
                expect(success.error).toBeNull();
                expect(mockSaveSession).toHaveBeenCalledWith(
                    '__session',
                    '',
                    expect.objectContaining({ maxAge: 0 })
                );
            }
        );
        it.each([
            'missing',
            'stale',
            'invalid-time',
            'revoked',
            'token-error',
            'missing-token',
            'success'
        ])('checks email-change authorization: %s', async (state) => {
            mockGetSession.mockReturnValue(
                state === 'missing' ? null : 'session'
            );
            const error = new FirebaseEdgeError({
                code: 'auth/session-cookie-revoked',
                message: 'Revoked'
            });
            vi.mocked(server.adminAuth.verifySessionCookie).mockResolvedValue({
                data:
                    state === 'revoked'
                        ? null
                        : ({
                              sub: 'uid',
                              auth_time:
                                  state === 'invalid-time'
                                      ? NaN
                                      : Date.now() / 1000 -
                                        (state === 'stale' ? 301 : 30)
                          } as any),
                error: state === 'revoked' ? error : null
            });
            vi.mocked(server.adminAuth.createCustomToken).mockResolvedValue({
                data: 'custom',
                error: null
            });
            vi.mocked(server.auth.signInWithCustomToken).mockResolvedValue(
                state === 'token-error'
                    ? { data: null, error }
                    : {
                          data:
                              state === 'missing-token'
                                  ? {}
                                  : { idToken: 'id' },
                          error: null
                      }
            );
            vi.mocked(server.auth.verifyBeforeUpdateEmail).mockResolvedValue({
                data: { email: 'new@b.com' },
                error: null
            });
            const result = await server.verifyBeforeUpdateEmail(
                'new@b.com',
                'fr'
            );
            if (state !== 'success') {
                expect(result.error).toBeTruthy();
                expect(
                    server.auth.verifyBeforeUpdateEmail
                ).not.toHaveBeenCalled();
                return;
            }
            expect(result.error).toBeNull();
            expect(server.adminAuth.verifySessionCookie).toHaveBeenCalledWith(
                'session',
                true
            );
            expect(server.auth.verifyBeforeUpdateEmail).toHaveBeenCalledWith(
                'id',
                'new@b.com',
                'http://localhost',
                'fr'
            );
        });
    });

    describe('magic links', () => {
        beforeEach(() => {
            vi.mocked(server.auth.sendSignInLinkToEmail).mockResolvedValue({
                data: { email: 'a@b.com' },
                error: null
            });
            vi.mocked(server.auth.signInWithEmailLink).mockResolvedValue({
                data: { idToken: 'email-id' },
                error: null
            });
            vi.mocked(server.adminAuth.createSessionCookie).mockResolvedValue({
                data: 'email-session',
                error: null
            });
        });
        it.each([false, true])(
            'completes magic links with includeEmailInLink=%s without cookies',
            async (includeEmailInLink) => {
                const sent = await server.sendSignInLinkToEmail(
                    'a@b.com',
                    '/dashboard',
                    {
                        includeEmailInLink,
                        callbackUrl: 'https://app/auth/email',
                        locale: 'en'
                    }
                );
                expect(sent.error).toBeNull();
                const args = vi.mocked(server.auth.sendSignInLinkToEmail).mock
                    .calls[0]!;
                expect(args[0]).toBe('a@b.com');
                expect(args[2]).toBe('en');
                const url = new URL(args[1]);
                expect(url.toString()).not.toContain('a%40b.com');
                url.searchParams.set('mode', 'signIn');
                url.searchParams.set('oobCode', 'one-time');
                const result = await server.handleCallback(url, {
                    ...(includeEmailInLink ? {} : { email: 'a@b.com' }),
                    expiresInMs: 3600000
                });
                expect(result).toEqual({
                    data: { type: 'redirect', url: '/dashboard' },
                    error: null
                });
                expect(server.auth.signInWithEmailLink).toHaveBeenCalledWith(
                    'a@b.com',
                    'one-time'
                );
                expect(
                    server.adminAuth.createSessionCookie
                ).toHaveBeenCalledWith('email-id', { expiresIn: 3600000 });
                expect(mockSaveSession).toHaveBeenCalledWith(
                    '__session',
                    'email-session',
                    expect.any(Object)
                );
                expect(mockGetSession).not.toHaveBeenCalled();
            }
        );
        it.each([
            'missing-email',
            'mismatch',
            'invalid-link',
            'exchange',
            'missing-token',
            'session'
        ])('rejects failed magic-link completion: %s', async (failure) => {
            await server.sendSignInLinkToEmail('a@b.com', '/', {
                includeEmailInLink: failure !== 'missing-email'
            });
            const url = new URL(
                vi.mocked(server.auth.sendSignInLinkToEmail).mock.calls[0]![1]
            );
            url.searchParams.set('mode', 'signIn');
            url.searchParams.set('oobCode', 'code');
            if (failure === 'invalid-link')
                url.searchParams.set('emailLinkState', 'tampered');
            if (failure === 'exchange')
                vi.mocked(server.auth.signInWithEmailLink).mockResolvedValue({
                    data: null,
                    error: new Error('expired')
                });
            if (failure === 'missing-token')
                vi.mocked(server.auth.signInWithEmailLink).mockResolvedValue({
                    data: {},
                    error: null
                });
            if (failure === 'session')
                vi.mocked(
                    server.adminAuth.createSessionCookie
                ).mockResolvedValue({
                    data: null,
                    error: new FirebaseEdgeError({
                        code: 'auth/internal-error',
                        message: 'failed'
                    })
                });
            const result = await server.signInWithCallback(
                url,
                failure === 'mismatch' ? { email: 'other@example.com' } : {}
            );
            expect(result.error).toBeTruthy();
            expect(mockSaveSession).not.toHaveBeenCalled();
        });
        it.each(['direct-number', 'continueUrl', 'wrapper'])(
            'dispatches magic links through the common callback: %s',
            async (kind) => {
                await server.sendSignInLinkToEmail('a@b.com', '/dashboard', {
                    includeEmailInLink: true
                });
                const continuation = new URL(
                    vi.mocked(
                        server.auth.sendSignInLinkToEmail
                    ).mock.calls[0]![1]
                );
                const action = new URL(
                    'https://app/action?mode=signIn&oobCode=code'
                );
                if (kind === 'direct-number')
                    action.searchParams.set(
                        'emailLinkState',
                        continuation.searchParams.get('emailLinkState')!
                    );
                else
                    action.searchParams.set(
                        'continueUrl',
                        continuation.toString()
                    );
                const wrapper = new URL('https://app/link');
                wrapper.searchParams.set('link', action.toString());
                const result = await server.signInWithCallback(
                    kind === 'wrapper' ? wrapper : action,
                    3600000
                );
                expect(result).toEqual({ data: '/dashboard', error: null });
                expect(
                    server.adminAuth.createSessionCookie
                ).toHaveBeenCalledWith('email-id', { expiresIn: 3600000 });
                expect(
                    server.auth.signInWithProviderCallback
                ).not.toHaveBeenCalled();
            }
        );
        it.each([
            ['bad', '/'],
            ['a@b.com', '//evil.com']
        ])('rejects invalid send inputs', async (email, next) => {
            const result = await server.sendSignInLinkToEmail(email!, next!);
            expect(result.error).toBeTruthy();
            expect(server.auth.sendSignInLinkToEmail).not.toHaveBeenCalled();
        });
        it('propagates mail delivery failures without changing sessions', async () => {
            const error = new Error('delivery failed');
            vi.mocked(server.auth.sendSignInLinkToEmail).mockResolvedValue({
                data: null,
                error
            });
            const result = await server.sendSignInLinkToEmail('a@b.com');
            expect(result.error).toBe(error);
            expect(mockSaveSession).not.toHaveBeenCalled();
        });
    });

    describe('additional providers', () => {
        const names = [
            'Google',
            'GitHub',
            'Facebook',
            'Apple',
            'Twitter',
            'Microsoft',
            'Yahoo'
        ] as const;
        beforeEach(() => {
            mockGetSession.mockReset();
            vi.mocked(
                server.auth.createProviderAuthorization
            ).mockResolvedValue({
                data: {
                    authUri: 'https://provider/authorize',
                    sessionId: 'flow-session'
                },
                error: null
            });
        });
        it.each(names)(
            'starts %s sign-in and linking with the correct provider',
            async (name) => {
                const options = {
                    addScopes: ['email'],
                    customParameters: { prompt: 'consent' }
                };
                const login = await server[`get${name}LoginURL`](
                    '/dashboard',
                    options
                );
                expect(login).toBe('https://provider/authorize');
                expect(
                    server.auth.createProviderAuthorization
                ).toHaveBeenLastCalledWith(
                    name.toLowerCase() + '.com',
                    options
                );
                expect(mockSaveSession).toHaveBeenCalledWith(
                    '__session_oauth',
                    JSON.stringify({
                        sessionId: 'flow-session',
                        next: '/dashboard',
                        intent: 'signin'
                    }),
                    expect.objectContaining({
                        httpOnly: true,
                        secure: true,
                        sameSite: 'none',
                        maxAge: 600
                    })
                );
                mockSaveSession.mockClear();
                mockGetSession.mockResolvedValue('session-cookie');
                vi.mocked(
                    server.adminAuth.verifySessionCookie
                ).mockResolvedValue({
                    data: { user_id: 'uid' } as never,
                    error: null
                });
                const link = await server[`get${name}LinkURL`](
                    '/account',
                    options
                );
                expect(link).toBe('https://provider/authorize');
                expect(
                    server.auth.createProviderAuthorization
                ).toHaveBeenLastCalledWith(
                    name.toLowerCase() + '.com',
                    options
                );
                expect(mockSaveSession).toHaveBeenCalledTimes(1);
                expect(mockSaveSession).toHaveBeenCalledWith(
                    '__session_oauth',
                    JSON.stringify({
                        sessionId: 'flow-session',
                        next: '/account',
                        intent: 'link'
                    }),
                    expect.any(Object)
                );
            }
        );
        it.each(['oidc.company', 'saml.company', 'google', 'github'])(
            'supports generic authorization for %s',
            async (provider) => {
                const result = await server.getProviderLoginURL(provider, '/');
                expect(result).toBe('https://provider/authorize');
            }
        );
        it.each(names)(
            'propagates %s authorization failures without clearing sessions',
            async (name) => {
                vi.mocked(
                    server.auth.createProviderAuthorization
                ).mockResolvedValue({
                    data: null,
                    error: new Error('disabled')
                });
                const request = server[`get${name}LoginURL`]('/');
                await expect(request).rejects.toThrow('disabled');
                expect(mockSaveSession).not.toHaveBeenCalled();
            }
        );
        it.each(names)(
            'requires authentication before linking %s',
            async (name) => {
                const request = server[`get${name}LinkURL`]('/');
                await expect(request).rejects.toThrow('Sign in before linking');
                expect(
                    server.auth.createProviderAuthorization
                ).not.toHaveBeenCalled();
            }
        );
        it.each(['//evil.example', 'https://evil.example', '/\\evil.example'])(
            'rejects unsafe next paths: %s',
            async (next) => {
                const request = server.getProviderLoginURL('facebook', next);
                await expect(request).rejects.toThrow('local absolute path');
                expect(
                    server.auth.createProviderAuthorization
                ).not.toHaveBeenCalled();
            }
        );
        it.each(['unknown', 'playgames'])(
            'rejects unsupported browser provider %s',
            async (provider) => {
                const request = server.getProviderLoginURL(provider, '/');
                await expect(request).rejects.toThrow();
                expect(
                    server.auth.createProviderAuthorization
                ).not.toHaveBeenCalled();
            }
        );
        it('rejects incomplete authorization responses', async () => {
            vi.mocked(
                server.auth.createProviderAuthorization
            ).mockResolvedValue({
                data: { authUri: 'https://provider' },
                error: null
            });
            const request = server.getFacebookLoginURL('/');
            await expect(request).rejects.toThrow('incomplete');
        });
        it.each([
            'facebook',
            'apple',
            'twitter',
            'microsoft',
            'yahoo',
            'playgames',
            'oidc.company'
        ])(
            'routes %s credentials instead of falling back to GitHub',
            async (provider) => {
                const credential = { idToken: 'token' };
                vi.mocked(server.auth.signInWithProvider).mockResolvedValue({
                    data: { idToken: 'firebase' },
                    error: null
                });
                const result = await server.signInWithProviderToken(
                    provider,
                    credential
                );
                expect(result.error).toBeNull();
                const expected =
                    provider === 'playgames'
                        ? 'playgames.google.com'
                        : provider.startsWith('oidc.')
                          ? provider
                          : provider + '.com';
                expect(server.auth.signInWithProvider).toHaveBeenCalledWith(
                    credential,
                    expected
                );
            }
        );
        it('rejects unknown token providers without invoking auth', async () => {
            const result = await server.signInWithProviderToken(
                'unknown',
                'token'
            );
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(server.auth.signInWithProvider).not.toHaveBeenCalled();
        });
        it.each([undefined, 'not-json', '{}', 'null'])(
            'rejects missing or corrupt callback sessions (%s)',
            async (stored) => {
                mockGetSession.mockResolvedValue(stored);
                const result = await server.signInWithProviderCallback(
                    new URL('https://app/callback')
                );
                expect(result.error).toBeInstanceOf(FirebaseEdgeError);
                expect(
                    server.auth.signInWithProviderCallback
                ).not.toHaveBeenCalled();
            }
        );
        it.each([false, true])(
            'completes GET/form POST callbacks and saves sessions (POST=%s)',
            async (post) => {
                mockGetSession.mockResolvedValue(
                    JSON.stringify({
                        sessionId: 'flow-session',
                        next: '/dashboard',
                        intent: 'signin'
                    })
                );
                vi.mocked(
                    server.auth.signInWithProviderCallback
                ).mockResolvedValue({
                    data: { idToken: 'firebase' },
                    error: null
                });
                vi.mocked(
                    server.adminAuth.createSessionCookie
                ).mockResolvedValue({ data: 'new-session', error: null });
                const url = new URL(
                    'https://app/callback?state=provider-state'
                );
                const body = post
                    ? 'code=apple-code&state=provider-state'
                    : undefined;
                const result = post
                    ? await server.signInWithCallback(url, {
                          postBody: body,
                          expiresInMs: 3600000
                      })
                    : await server.signInWithCallback(url, 3600000);
                expect(result).toEqual({ data: '/dashboard', error: null });
                expect(
                    server.auth.signInWithProviderCallback
                ).toHaveBeenCalledWith(
                    {
                        requestUri: url.toString(),
                        sessionId: 'flow-session',
                        postBody: body
                    },
                    undefined
                );
                expect(
                    server.adminAuth.createSessionCookie
                ).toHaveBeenCalledWith('firebase', { expiresIn: 3600000 });
                expect(mockSaveSession).toHaveBeenCalledWith(
                    '__session_oauth',
                    '',
                    expect.objectContaining({ maxAge: 0 })
                );
                expect(mockSaveSession).toHaveBeenCalledWith(
                    '__session',
                    'new-session',
                    expect.any(Object)
                );
            }
        );
        it('links callbacks to the authenticated Firebase account', async () => {
            mockGetSession.mockImplementation((name) =>
                name === '__session_oauth'
                    ? JSON.stringify({
                          sessionId: 'flow-session',
                          next: '/account',
                          intent: 'link'
                      })
                    : 'current-session'
            );
            vi.mocked(server.adminAuth.verifySessionCookie).mockResolvedValue({
                data: { user_id: 'uid' } as never,
                error: null
            });
            vi.mocked(server.adminAuth.createCustomToken).mockResolvedValue({
                data: 'custom',
                error: null
            });
            vi.mocked(server.auth.signInWithCustomToken).mockResolvedValue({
                data: { idToken: 'existing' },
                error: null
            });
            vi.mocked(server.auth.signInWithProviderCallback).mockResolvedValue(
                { data: { idToken: 'linked' }, error: null }
            );
            vi.mocked(server.adminAuth.createSessionCookie).mockResolvedValue({
                data: 'session',
                error: null
            });
            const result = await server.signInWithProviderCallback(
                new URL('https://app/callback')
            );
            expect(result.error).toBeNull();
            expect(server.auth.signInWithProviderCallback).toHaveBeenCalledWith(
                expect.objectContaining({ sessionId: 'flow-session' }),
                'existing'
            );
        });
        it('does not create a session when callback exchange fails', async () => {
            mockGetSession.mockResolvedValue(
                JSON.stringify({ sessionId: 's', next: '/', intent: 'signin' })
            );
            const error = new Error('bad code');
            vi.mocked(server.auth.signInWithProviderCallback).mockResolvedValue(
                { data: null, error }
            );
            const result = await server.signInWithProviderCallback(
                new URL('https://app/callback')
            );
            expect(result.error).toBe(error);
            expect(server.adminAuth.createSessionCookie).not.toHaveBeenCalled();
        });
    });

    describe('automatic provider linking', () => {
        beforeEach(() => {
            server = createFirebaseEdgeServer({
                serviceAccount: mockServiceAccount,
                firebaseConfig: mockFirebaseConfig,
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession
                },
                redirectUri: 'https://app/callback',
                autoLinkProviders: true
            });
            mockGetSession.mockResolvedValue(
                JSON.stringify({
                    sessionId: 'flow',
                    next: '/dashboard',
                    intent: 'signin'
                })
            );
            vi.mocked(server.auth.signInWithProviderCallback)
                .mockResolvedValueOnce({
                    data: {
                        needConfirmation: true,
                        email: 'user@example.com',
                        pendingToken: 'pending'
                    },
                    error: null
                })
                .mockResolvedValue({
                    data: { idToken: 'linked' },
                    error: null
                });
            vi.mocked(server.adminAuth.getUserByEmail).mockResolvedValue({
                data: { localId: 'existing' },
                error: null
            });
            vi.mocked(server.adminAuth.createCustomToken).mockResolvedValue({
                data: 'custom',
                error: null
            });
            vi.mocked(server.auth.signInWithCustomToken).mockResolvedValue({
                data: { idToken: 'existing-id-token' },
                error: null
            });
            vi.mocked(server.adminAuth.createSessionCookie).mockResolvedValue({
                data: 'session',
                error: null
            });
        });

        it.each([false, true])(
            'auto-links managed callbacks, including POST=%s',
            async (post) => {
                const url = new URL('https://app/callback?code=one-time');
                const result = post
                    ? await server.signInWithProviderCallback(
                          url,
                          'code=one-time',
                          3600000
                      )
                    : await server.signInWithCallback(url, 3600000);
                expect(result).toEqual({ data: '/dashboard', error: null });
                expect(server.adminAuth.getUserByEmail).toHaveBeenCalledWith(
                    'user@example.com'
                );
                expect(server.adminAuth.createCustomToken).toHaveBeenCalledWith(
                    'existing'
                );
                expect(
                    server.auth.signInWithProviderCallback
                ).toHaveBeenLastCalledWith(
                    { requestUri: url.toString(), pendingToken: 'pending' },
                    'existing-id-token'
                );
                expect(
                    server.adminAuth.createSessionCookie
                ).toHaveBeenCalledWith('linked', { expiresIn: 3600000 });
            }
        );

        it.each([false, true])(
            'auto-links returned GitHub access tokens without a pending token (POST=%s)',
            async (post) => {
                vi.mocked(server.auth.signInWithProviderCallback)
                    .mockReset()
                    .mockResolvedValue({
                        data: {
                            needConfirmation: true,
                            email: 'user@example.com',
                            providerId: 'github.com',
                            oauthAccessToken: 'github-access'
                        },
                        error: null
                    });
                vi.mocked(server.auth.linkWithCredential).mockResolvedValue({
                    data: { idToken: 'linked' },
                    error: null
                });
                const url = new URL('https://app/callback?code=one-time');
                const result = post
                    ? await server.signInWithProviderCallback(
                          url,
                          'code=one-time',
                          3600000
                      )
                    : await server.signInWithCallback(url, 3600000);
                expect(result).toEqual({ data: '/dashboard', error: null });
                expect(server.auth.linkWithCredential).toHaveBeenCalledWith(
                    'existing-id-token',
                    {
                        idToken: undefined,
                        accessToken: 'github-access',
                        secret: undefined
                    },
                    'github.com'
                );
                expect(
                    server.auth.signInWithProviderCallback
                ).toHaveBeenCalledTimes(1);
                expect(
                    server.adminAuth.createSessionCookie
                ).toHaveBeenCalledWith('linked', { expiresIn: 3600000 });
            }
        );

        it('does not save a session when returned-credential linking fails', async () => {
            vi.mocked(server.auth.signInWithProviderCallback)
                .mockReset()
                .mockResolvedValue({
                    data: {
                        needConfirmation: true,
                        email: 'user@example.com',
                        providerId: 'github.com',
                        oauthAccessToken: 'github-access'
                    },
                    error: null
                });
            const failure = new FirebaseEdgeError({
                code: 'auth/invalid-credential',
                message: 'Rejected credential'
            });
            vi.mocked(server.auth.linkWithCredential).mockResolvedValue({
                data: null,
                error: failure
            });
            const result = await server.signInWithCallback(
                new URL('https://app/callback')
            );
            expect(result.error).toBe(failure);
            expect(server.adminAuth.createSessionCookie).not.toHaveBeenCalled();
        });

        it.each([
            { providerId: 'google.com', oauthIdToken: 'google-id' },
            { providerId: 'facebook.com', oauthAccessToken: 'facebook-access' },
            {
                providerId: 'apple.com',
                oauthIdToken: 'apple-id',
                nonce: 'apple-nonce'
            },
            {
                providerId: 'twitter.com',
                oauthAccessToken: 'twitter-access',
                oauthTokenSecret: 'twitter-secret'
            },
            {
                providerId: 'microsoft.com',
                oauthIdToken: 'microsoft-id',
                nonce: 'microsoft-nonce'
            },
            {
                providerId: 'yahoo.com',
                oauthIdToken: 'yahoo-id',
                nonce: 'yahoo-nonce'
            },
            {
                providerId: 'oidc.company',
                oauthIdToken: 'oidc-id',
                nonce: 'oidc-nonce'
            }
        ])(
            'auto-links returned credentials for $providerId',
            async (response) => {
                vi.mocked(server.auth.signInWithProviderCallback)
                    .mockReset()
                    .mockResolvedValue({
                        data: {
                            ...response,
                            needConfirmation: true,
                            email: 'user@example.com'
                        },
                        error: null
                    });
                vi.mocked(server.auth.linkWithCredential).mockResolvedValue({
                    data: { idToken: 'linked' },
                    error: null
                });
                const result = await server.signInWithProviderCallback(
                    new URL('https://app/callback'),
                    'provider-response'
                );
                expect(result).toEqual({ data: '/dashboard', error: null });
                expect(server.auth.linkWithCredential).toHaveBeenCalledWith(
                    'existing-id-token',
                    {
                        idToken:
                            'oauthIdToken' in response
                                ? response.oauthIdToken
                                : undefined,
                        accessToken:
                            'oauthAccessToken' in response
                                ? response.oauthAccessToken
                                : undefined,
                        secret:
                            'oauthTokenSecret' in response
                                ? response.oauthTokenSecret
                                : undefined,
                        rawNonce:
                            'nonce' in response ? response.nonce : undefined
                    },
                    response.providerId
                );
                expect(
                    server.auth.signInWithProviderCallback
                ).toHaveBeenCalledTimes(1);
            }
        );

        it.each([
            'google.com',
            'github.com',
            'facebook.com',
            'apple.com',
            'twitter.com',
            'microsoft.com',
            'yahoo.com',
            'oidc.company',
            'saml.company'
        ])(
            'prefers pending credentials for %s over raw provider tokens',
            async (providerId) => {
                vi.mocked(server.auth.signInWithProviderCallback)
                    .mockReset()
                    .mockResolvedValueOnce({
                        data: {
                            providerId,
                            needConfirmation: true,
                            email: 'user@example.com',
                            pendingToken: 'pending',
                            oauthAccessToken: 'unused'
                        },
                        error: null
                    })
                    .mockResolvedValue({
                        data: { idToken: 'linked' },
                        error: null
                    });
                const result = await server.signInWithProviderCallback(
                    new URL('https://app/callback'),
                    'response'
                );
                expect(result.error).toBeNull();
                expect(
                    server.auth.signInWithProviderCallback
                ).toHaveBeenLastCalledWith(
                    {
                        requestUri: 'https://app/callback',
                        pendingToken: 'pending'
                    },
                    'existing-id-token'
                );
                expect(server.auth.linkWithCredential).not.toHaveBeenCalled();
            }
        );

        it('retains automatic linking for directly supplied credentials', async () => {
            vi.mocked(server.auth.signInWithProvider).mockResolvedValue({
                data: { needConfirmation: true, email: 'user@example.com' },
                error: null
            });
            vi.mocked(server.auth.linkWithCredential).mockResolvedValue({
                data: { idToken: 'linked' },
                error: null
            });
            const credential = { accessToken: 'github-token' };
            const result = await server.signInWithProviderToken(
                'github',
                credential
            );
            expect(result.data?.idToken).toBe('linked');
            expect(server.auth.linkWithCredential).toHaveBeenCalledWith(
                'existing-id-token',
                credential,
                'github.com'
            );
            expect(server.adminAuth.createSessionCookie).not.toHaveBeenCalled();
        });

        it.each([true, false])(
            'rejects managed collisions when automatic linking is disabled (pending=%s)',
            async (pending) => {
                const disabled = createFirebaseEdgeServer({
                    serviceAccount: mockServiceAccount,
                    firebaseConfig: mockFirebaseConfig,
                    cookies: {
                        getSession: mockGetSession,
                        saveSession: mockSaveSession
                    },
                    redirectUri: 'https://app/callback',
                    autoLinkProviders: false
                });
                vi.mocked(
                    disabled.auth.signInWithProviderCallback
                ).mockResolvedValue({
                    data: {
                        needConfirmation: true,
                        email: 'user@example.com',
                        ...(pending
                            ? { pendingToken: 'pending' }
                            : {
                                  providerId: 'github.com',
                                  oauthAccessToken: 'github-access'
                              })
                    },
                    error: null
                });
                const result = await disabled.signInWithProviderCallback(
                    new URL('https://app/callback')
                );
                expect(result.error).toMatchObject({
                    code: FirebaseEdgeServerErrorInfo
                        .EDGE_ACCOUNT_EXISTS_DIFFERENT_METHOD.code
                });
                expect(
                    disabled.adminAuth.getUserByEmail
                ).not.toHaveBeenCalled();
                expect(disabled.auth.linkWithCredential).not.toHaveBeenCalled();
                expect(
                    disabled.adminAuth.createSessionCookie
                ).not.toHaveBeenCalled();
            }
        );

        it.each([
            'email',
            'pending',
            'user',
            'lookup',
            'custom',
            'custom-empty',
            'signin',
            'id-token',
            'link',
            'linked-id-token'
        ])(
            'does not save sessions after auto-link failure: %s',
            async (stage) => {
                const failure = new FirebaseEdgeError({
                    code: 'auth/internal-error',
                    message: 'link failed'
                });
                if (stage === 'email' || stage === 'pending') {
                    vi.mocked(server.auth.signInWithProviderCallback)
                        .mockReset()
                        .mockResolvedValue({
                            data: {
                                needConfirmation: true,
                                email:
                                    stage === 'email'
                                        ? undefined
                                        : 'user@example.com',
                                pendingToken:
                                    stage === 'pending' ? undefined : 'pending'
                            },
                            error: null
                        });
                }
                if (stage === 'user' || stage === 'lookup')
                    vi.mocked(
                        server.adminAuth.getUserByEmail
                    ).mockResolvedValue(
                        stage === 'lookup'
                            ? { data: null, error: failure }
                            : { data: { localId: '' }, error: null }
                    );
                if (stage === 'custom' || stage === 'custom-empty')
                    vi.mocked(
                        server.adminAuth.createCustomToken
                    ).mockResolvedValue(
                        stage === 'custom'
                            ? { data: null, error: failure }
                            : { data: '', error: null }
                    );
                if (stage === 'signin' || stage === 'id-token')
                    vi.mocked(
                        server.auth.signInWithCustomToken
                    ).mockResolvedValue(
                        stage === 'signin'
                            ? { data: null, error: failure }
                            : { data: {}, error: null }
                    );
                if (stage === 'link' || stage === 'linked-id-token')
                    vi.mocked(
                        server.auth.signInWithProviderCallback
                    ).mockResolvedValue({
                        data: null,
                        error: stage === 'link' ? failure : null
                    });
                const result = await server.signInWithProviderCallback(
                    new URL('https://app/callback')
                );
                expect(result.error).toBeTruthy();
                expect(
                    server.adminAuth.createSessionCookie
                ).not.toHaveBeenCalled();
                expect(mockSaveSession).not.toHaveBeenCalledWith(
                    '__session',
                    expect.anything(),
                    expect.anything()
                );
            }
        );
    });

    describe('factory function', () => {
        it('passes explicit emulator settings only to auth instances', () => {
            const fetchFn = vi.fn();
            createFirebaseEdgeServer({
                serviceAccount: mockServiceAccount,
                firebaseConfig: mockFirebaseConfig,
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession
                },
                redirectUri: 'http://localhost',
                fetch: fetchFn,
                authEmulatorHost: 'localhost:9099'
            });
            expect(FirebaseAuth).toHaveBeenLastCalledWith(
                mockFirebaseConfig,
                'http://localhost',
                {
                    tenantId: undefined,
                    fetch: fetchFn,
                    emulatorHost: 'localhost:9099'
                }
            );
            expect(FirebaseAdminAuth).toHaveBeenLastCalledWith(
                mockServiceAccount,
                {
                    tenantId: undefined,
                    fetch: fetchFn,
                    cache: undefined,
                    cacheName: undefined,
                    emulatorHost: 'localhost:9099'
                }
            );
            expect(Firestore).toHaveBeenLastCalledWith(mockServiceAccount, {
                fetch: fetchFn,
                cache: undefined,
                cacheName: undefined
            });
        });
        it('initializes firestore with the shared service account, fetch and cache', () => {
            const fetchFn = vi.fn();
            const cache = { getCache: vi.fn(), setCache: vi.fn() };
            const result = createFirebaseEdgeServer({
                serviceAccount: mockServiceAccount,
                firebaseConfig: mockFirebaseConfig,
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession
                },
                redirectUri: 'http://localhost',
                fetch: fetchFn,
                cache,
                cacheName: 'shared-token',
                tenantId: 'auth-only'
            });
            expect(Firestore).toHaveBeenLastCalledWith(mockServiceAccount, {
                fetch: fetchFn,
                cache,
                cacheName: 'shared-token'
            });
            expect(result.firestore).toBeInstanceOf(Firestore);
        });

        it('creates server with all required methods', () => {
            expect(server).toHaveProperty('auth');
            expect(server).toHaveProperty('adminAuth');
            expect(server).toHaveProperty('signOut');
            expect(server).toHaveProperty('getUser');
            expect(server).toHaveProperty('getGoogleLoginURL');
            expect(server).toHaveProperty('getGitHubLoginURL');
            expect(server).toHaveProperty('signInWithCallback');
            expect(server).toHaveProperty('getToken');
        });

        it('uses custom cookie name when provided', () => {
            const customServer = createFirebaseEdgeServer({
                serviceAccount: mockServiceAccount,
                firebaseConfig: mockFirebaseConfig,
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession
                },
                cookieName: 'custom-session',
                redirectUri: 'http://localhost'
            });

            customServer.signOut();

            expect(mockSaveSession).toHaveBeenCalledWith(
                'custom-session',
                '',
                expect.objectContaining({ maxAge: 0 })
            );
        });

        it('uses default session name "__session"', () => {
            server.signOut();

            expect(mockSaveSession).toHaveBeenCalledWith(
                '__session',
                '',
                expect.objectContaining({ maxAge: 0 })
            );
        });

        it('accepts custom fetch function', () => {
            const mockFetch = vi.fn();
            const customServer = createFirebaseEdgeServer({
                serviceAccount: mockServiceAccount,
                firebaseConfig: mockFirebaseConfig,
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession
                },
                redirectUri: 'http://localhost',
                fetch: mockFetch
            });

            expect(customServer).toBeDefined();
        });

        it('accepts tenant ID parameter', () => {
            const serverWithTenant = createFirebaseEdgeServer({
                serviceAccount: mockServiceAccount,
                firebaseConfig: mockFirebaseConfig,
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession
                },
                tenantId: 'test-tenant',
                redirectUri: 'http://localhost'
            });

            expect(serverWithTenant).toBeDefined();
        });

        it('passes tenant ID to auth constructors', () => {
            vi.clearAllMocks();

            createFirebaseEdgeServer({
                serviceAccount: mockServiceAccount,
                firebaseConfig: mockFirebaseConfig,
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession
                },
                tenantId: 'test-tenant-id',
                redirectUri: 'http://localhost'
            });

            expect(vi.mocked(FirebaseAuth)).toHaveBeenCalledWith(
                mockFirebaseConfig,
                'http://localhost',
                {
                    tenantId: 'test-tenant-id',
                    fetch: globalThis.fetch,
                    emulatorHost: null
                }
            );
            expect(vi.mocked(FirebaseAdminAuth)).toHaveBeenCalledWith(
                mockServiceAccount,
                {
                    tenantId: 'test-tenant-id',
                    fetch: globalThis.fetch,
                    cache: undefined,
                    cacheName: undefined,
                    emulatorHost: null
                }
            );
        });

        it('passes undefined tenant ID when not provided', () => {
            vi.clearAllMocks();

            createFirebaseEdgeServer({
                serviceAccount: mockServiceAccount,
                firebaseConfig: mockFirebaseConfig,
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession
                },
                redirectUri: 'http://localhost'
            });

            expect(vi.mocked(FirebaseAuth)).toHaveBeenCalledWith(
                mockFirebaseConfig,
                'http://localhost',
                {
                    tenantId: undefined,
                    fetch: globalThis.fetch,
                    emulatorHost: null
                }
            );
            expect(vi.mocked(FirebaseAdminAuth)).toHaveBeenCalledWith(
                mockServiceAccount,
                {
                    tenantId: undefined,
                    fetch: globalThis.fetch,
                    cache: undefined,
                    cacheName: undefined,
                    emulatorHost: null
                }
            );
        });
    });

    describe('managed callback alias', () => {
        it('rejects old code/state callbacks without the bound flow cookie', async () => {
            mockGetSession.mockResolvedValue(undefined);
            const url = new URL('https://app/callback?code=old-code');
            url.searchParams.set(
                'state',
                JSON.stringify({ provider: 'github', next: '/dashboard' })
            );
            const result = await server.signInWithCallback(url);
            expect(result.error).toMatchObject({
                code: 'auth/invalid-credential'
            });
            expect(
                server.auth.signInWithProviderCallback
            ).not.toHaveBeenCalled();
            expect(server.adminAuth.createSessionCookie).not.toHaveBeenCalled();
        });
    });

    describe('getToken', () => {
        it('refreshes client tokens through the configured admin auth instance', async () => {
            mockGetSession.mockResolvedValue('session');
            vi.mocked(server.adminAuth.verifySessionCookie).mockResolvedValue({
                data: { sub: 'user' } as never,
                error: null
            });
            vi.mocked(server.adminAuth.createCustomToken).mockResolvedValue({
                data: 'emulator-custom-token',
                error: null
            });
            vi.mocked(server.auth.signInWithCustomToken).mockResolvedValue({
                data: { idToken: 'id', refreshToken: 'refresh' },
                error: null
            });
            const result = await server.getToken();
            expect(server.adminAuth.createCustomToken).toHaveBeenCalledWith(
                'user'
            );
            expect(server.auth.signInWithCustomToken).toHaveBeenCalledWith(
                'emulator-custom-token'
            );
            expect(result).toEqual({
                data: { idToken: 'id', refreshToken: 'refresh' },
                error: null
            });
        });
    });

    describe('signOut', () => {
        it('clears session cookie with proper options', () => {
            server.signOut();

            expect(mockSaveSession).toHaveBeenCalledWith('__session', '', {
                httpOnly: true,
                secure: true,
                sameSite: 'lax',
                path: '/',
                maxAge: 0
            });
        });
    });

    describe('getUser', () => {
        it('returns null data when no session exists', async () => {
            mockGetSession.mockResolvedValue(null);

            const result = await server.getUser();

            expect(result).toEqual({
                data: null,
                error: null
            });
            expect(mockGetSession).toHaveBeenCalledWith('__session');
        });
    });

    describe('getToken', () => {
        it('returns null when no verified token', async () => {
            mockGetSession.mockResolvedValue(null);

            const result = await server.getToken();

            expect(result).toEqual({
                data: null,
                error: null
            });
        });
    });

    describe('OFFICIAL_FIREBASE_OAUTH_PROVIDERS', () => {
        it('contains all supported OAuth providers', () => {
            expect(OFFICIAL_FIREBASE_OAUTH_PROVIDERS).toEqual([
                'google',
                'facebook',
                'apple',
                'twitter',
                'github',
                'microsoft',
                'yahoo',
                'playgames'
            ]);
        });
    });
});
