import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import {
    createFirebaseEdgeServer,
    OFFICIAL_FIREBASE_OAUTH_PROVIDERS,
} from './firebase-edge-server.js';
import type { ServiceAccount, FirebaseConfig } from './auth/firebase-types.js';

// Mock dependencies
vi.mock('./auth/firebase-admin-auth.js');
vi.mock('./auth/firebase-auth.js');
vi.mock('./auth/firebase-jwt.js');
vi.mock('./auth/google-oauth.js');

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
        'https://www.googleapis.com/robot/v1/metadata/x509/test%40test-project.iam.gserviceaccount.com',
};

const mockFirebaseConfig: FirebaseConfig = {
    apiKey: 'test-api-key',
    authDomain: 'test-project.firebaseapp.com',
    projectId: 'test-project',
    storageBucket: 'test-project.appspot.com',
    messagingSenderId: '123456789',
    appId: 'test-app-id',
};

const mockProviders = {
    google: {
        client_id: 'google-client-id',
        client_secret: 'google-client-secret',
    },
    facebook: { client_id: 'fb-id', client_secret: 'fb-secret' },
    apple: { client_id: 'apple-id', client_secret: 'apple-secret' },
    twitter: { client_id: 'twitter-id', client_secret: 'twitter-secret' },
    github: { client_id: 'github-id', client_secret: 'github-secret' },
    microsoft: { client_id: 'ms-id', client_secret: 'ms-secret' },
    yahoo: { client_id: 'yahoo-id', client_secret: 'yahoo-secret' },
    playgames: { client_id: 'pg-id', client_secret: 'pg-secret' },
};

describe('createFirebaseEdgeServer', () => {
    let mockGetSession: Mock;
    let mockSaveSession: Mock;
    let mockFetch: Mock;

    beforeEach(() => {
        vi.clearAllMocks();
        mockGetSession = vi.fn();
        mockSaveSession = vi.fn();
        mockFetch = vi.fn();
    });

    it('should create server with all required methods', () => {
        const server = createFirebaseEdgeServer({
            serviceAccount: mockServiceAccount,
            firebaseConfig: mockFirebaseConfig,
            providers: mockProviders,
            cookies: {
                getSession: mockGetSession,
                saveSession: mockSaveSession,
            },
        });

        expect(server).toHaveProperty('auth');
        expect(server).toHaveProperty('adminAuth');
        expect(server).toHaveProperty('signOut');
        expect(server).toHaveProperty('getUser');
        expect(server).toHaveProperty('getGoogleLoginURL');
        expect(server).toHaveProperty('signInWithGoogleWithCode');
        expect(server).toHaveProperty('getToken');
    });

    it('should use custom session name when provided', () => {
        const server = createFirebaseEdgeServer({
            serviceAccount: mockServiceAccount,
            firebaseConfig: mockFirebaseConfig,
            providers: mockProviders,
            cookies: {
                getSession: mockGetSession,
                saveSession: mockSaveSession,
                sessionName: 'custom-session',
            },
        });

        server.signOut();

        expect(mockSaveSession).toHaveBeenCalledWith(
            'custom-session',
            '',
            expect.objectContaining({ maxAge: 0 }),
        );
    });

    it('should use default session name "__session"', () => {
        const server = createFirebaseEdgeServer({
            serviceAccount: mockServiceAccount,
            firebaseConfig: mockFirebaseConfig,
            providers: mockProviders,
            cookies: {
                getSession: mockGetSession,
                saveSession: mockSaveSession,
            },
        });

        server.signOut();

        expect(mockSaveSession).toHaveBeenCalledWith(
            '__session',
            '',
            expect.objectContaining({ maxAge: 0 }),
        );
    });

    it('should accept custom fetch function', () => {
        createFirebaseEdgeServer({
            serviceAccount: mockServiceAccount,
            firebaseConfig: mockFirebaseConfig,
            providers: mockProviders,
            cookies: {
                getSession: mockGetSession,
                saveSession: mockSaveSession,
            },
            fetch: mockFetch,
        });

        expect(mockFetch).toBeDefined();
    });

    describe('signOut', () => {
        it('should clear session cookie with proper options', () => {
            const server = createFirebaseEdgeServer({
                serviceAccount: mockServiceAccount,
                firebaseConfig: mockFirebaseConfig,
                providers: mockProviders,
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession,
                },
            });

            server.signOut();

            expect(mockSaveSession).toHaveBeenCalledWith('__session', '', {
                httpOnly: true,
                secure: true,
                sameSite: 'lax',
                path: '/',
                maxAge: 0,
            });
        });
    });

    describe('getUser', () => {
        it('should return null when no session exists', async () => {
            mockGetSession.mockResolvedValue(null);

            const server = createFirebaseEdgeServer({
                serviceAccount: mockServiceAccount,
                firebaseConfig: mockFirebaseConfig,
                providers: mockProviders,
                cookies: {
                    getSession: mockGetSession,
                    saveSession: mockSaveSession,
                },
            });

            const result = await server.getUser();

            expect(result).toEqual({
                data: null,
                error: null,
            });
        });
    });

    describe('OFFICIAL_FIREBASE_OAUTH_PROVIDERS', () => {
        it('should contain all supported OAuth providers', () => {
            expect(OFFICIAL_FIREBASE_OAUTH_PROVIDERS).toEqual([
                'google',
                'facebook',
                'apple',
                'twitter',
                'github',
                'microsoft',
                'yahoo',
                'playgames',
            ]);
        });
    });
});
