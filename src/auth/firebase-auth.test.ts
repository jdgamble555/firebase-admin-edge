import { describe, it, expect, vi, beforeEach } from 'vitest';
import { FirebaseAuth } from './firebase-auth.js';
import * as endpoints from './firebase-auth-endpoints.js';

vi.mock('./firebase-auth-endpoints.js');

describe('FirebaseAuth', () => {
    const mockConfig = {
        apiKey: 'test-api-key',
        authDomain: 'test-project.firebaseapp.com',
        projectId: 'test-project'
    };

    let firebaseAuth: FirebaseAuth;
    let mockFetch: typeof globalThis.fetch;

    beforeEach(() => {
        vi.clearAllMocks();
        mockFetch = vi.fn() as any;
        firebaseAuth = new FirebaseAuth(mockConfig, mockFetch);
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
                'http://localhost',
                'google.com'
            );

            expect(result.data).toEqual(mockData);
            expect(result.error).toBeNull();
            expect(endpoints.signInWithIdp).toHaveBeenCalledWith(
                'idToken',
                'http://localhost',
                'google.com',
                'test-api-key',
                mockFetch
            );
        });

        it('should return error on failed sign in', async () => {
            const mockError = { code: 400, message: 'Authentication failed' };
            vi.mocked(endpoints.signInWithIdp).mockResolvedValue({
                data: null,
                error: mockError
            });

            const result = await firebaseAuth.signInWithProvider(
                'idToken',
                'http://localhost'
            );

            expect(result.data).toBeNull();
            expect(result.error).toEqual(
                new Error(
                    'Failed to sign in with provider: Authentication failed'
                )
            );
        });

        it('should return null data and error when no data returned', async () => {
            vi.mocked(endpoints.signInWithIdp).mockResolvedValue({
                data: null,
                error: null
            });

            const result = await firebaseAuth.signInWithProvider(
                'idToken',
                'http://localhost'
            );

            expect(result.data).toBeNull();
            expect(result.error).toBeNull();
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
                mockFetch
            );
        });

        it('should return error on failed sign in', async () => {
            const mockError = { code: 400, message: 'Invalid custom token' };
            vi.mocked(endpoints.signInWithCustomToken).mockResolvedValue({
                data: null,
                error: mockError
            });

            const result =
                await firebaseAuth.signInWithCustomToken('customToken');

            expect(result.data).toBeNull();
            expect(result.error).toEqual(
                new Error(
                    'Failed to sign in with custom token: Invalid custom token'
                )
            );
        });

        it('should return null data and error when no data returned', async () => {
            vi.mocked(endpoints.signInWithCustomToken).mockResolvedValue({
                data: null,
                error: null
            });

            const result =
                await firebaseAuth.signInWithCustomToken('customToken');

            expect(result.data).toBeNull();
            expect(result.error).toBeNull();
        });
    });
});
