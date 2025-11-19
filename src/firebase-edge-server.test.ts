import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import {
    createFirebaseEdgeServer,
    OFFICIAL_FIREBASE_OAUTH_PROVIDERS
} from './firebase-edge-server.js';
import type { ServiceAccount, FirebaseConfig } from './auth/firebase-types.js';
import { FirebaseEdgeError } from './auth/errors.js';
import { FirebaseEdgeServerErrorInfo } from './firebase-edge-errors.js';

// Mock dependencies
vi.mock('./auth/firebase-admin-auth.js');
vi.mock('./auth/firebase-auth.js');
vi.mock('./auth/firebase-jwt.js');
vi.mock('./auth/oauth.js');
vi.mock('./auth/google-oauth.js');
vi.mock('./auth/github-oauth.js');

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

const mockProviders = {
    google: {
        client_id: 'google-client-id',
        client_secret: 'google-client-secret'
    },
    github: {
        client_id: 'github-client-id',
        client_secret: 'github-client-secret'
    }
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
            providers: mockProviders,
            cookies: {
                getSession: mockGetSession,
                saveSession: mockSaveSession
            }
        });
    });

    describe('factory function', () => {
        it('creates server with all required methods', () => {
            expect(server).toHaveProperty('auth');
            expect(server).toHaveProperty('adminAuth');
            expect(server).toHaveProperty('signOut');
            expect(server).toHaveProperty('getUser');
            expect(server).toHaveProperty('getGoogleLoginURL');
            expect(server).toHaveProperty('getGitHubLoginURL');
            expect(server).toHaveProperty('signInWithCode');
            expect(server).toHaveProperty('getToken');
        });

        it('uses custom session name when provided', () => {
            const customServer = createFirebaseEdgeServer({
                serviceAccount: mockServiceAccount,
                firebaseConfig: mockFirebaseConfig,
                providers: mockProviders,
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession,
                    sessionName: 'custom-session'
                }
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
                providers: mockProviders,
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession
                },
                fetch: mockFetch
            });

            expect(customServer).toBeDefined();
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

    describe('getGoogleLoginURL', () => {
        it('throws error when Google provider not configured', async () => {
            const serverWithoutGoogle = createFirebaseEdgeServer({
                serviceAccount: mockServiceAccount,
                firebaseConfig: mockFirebaseConfig,
                providers: {},
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession
                }
            });

            await expect(
                serverWithoutGoogle.getGoogleLoginURL(
                    'http://localhost',
                    '/dashboard'
                )
            ).rejects.toThrow(
                new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_GOOGLE_PROVIDER_NOT_CONFIGURED
                )
            );
        });

        it('calls deleteSession before generating URL', async () => {
            const { createGoogleOAuthLoginUrl } = await import(
                './auth/oauth.js'
            );
            vi.mocked(createGoogleOAuthLoginUrl).mockReturnValue(
                'http://oauth-url'
            );

            await server.getGoogleLoginURL('http://localhost', '/dashboard');

            expect(mockSaveSession).toHaveBeenCalledWith(
                '__session',
                '',
                expect.objectContaining({ maxAge: 0 })
            );
        });
    });

    describe('getGitHubLoginURL', () => {
        it('throws error when GitHub provider not configured', async () => {
            const serverWithoutGitHub = createFirebaseEdgeServer({
                serviceAccount: mockServiceAccount,
                firebaseConfig: mockFirebaseConfig,
                providers: {},
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession
                }
            });

            await expect(
                serverWithoutGitHub.getGitHubLoginURL(
                    'http://localhost',
                    '/dashboard'
                )
            ).rejects.toThrow(
                new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_GITHUB_PROVIDER_NOT_CONFIGURED
                )
            );
        });

        it('calls deleteSession before generating URL', async () => {
            const { createGitHubOAuthLoginUrl } = await import(
                './auth/oauth.js'
            );
            vi.mocked(createGitHubOAuthLoginUrl).mockReturnValue(
                'http://github-oauth-url'
            );

            await server.getGitHubLoginURL('http://localhost', '/dashboard');

            expect(mockSaveSession).toHaveBeenCalledWith(
                '__session',
                '',
                expect.objectContaining({ maxAge: 0 })
            );
        });
    });

    describe('signInWithCode', () => {
        it('returns error when no provider specified in state', async () => {
            const result = await server.signInWithCode(
                'auth-code',
                'http://localhost',
                null
            );

            expect(result).toEqual({
                error: expect.any(FirebaseEdgeError)
            });
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect((result.error as FirebaseEdgeError).code).toBe(
                FirebaseEdgeServerErrorInfo.EDGE_NO_PROVIDER_IN_STATE.code
            );
        });

        it('handles invalid JSON state gracefully', async () => {
            // We expect this to throw during JSON.parse, which is the current behavior
            await expect(
                server.signInWithCode(
                    'auth-code',
                    'http://localhost',
                    'invalid-json'
                )
            ).rejects.toThrow();
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
