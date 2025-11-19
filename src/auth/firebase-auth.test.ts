import { describe, it, expect, beforeEach, vi } from 'vitest';
import { FirebaseAuth } from './firebase-auth.js';
import * as endpoints from './firebase-auth-endpoints.js';
import { FirebaseEdgeError } from './errors.js';
import { mapFirebaseError } from './auth-endpoint-errors.js';
import { FirebaseAuthErrorInfo } from './auth-error-codes.js';

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
        mockFetch = vi.fn() as unknown as typeof globalThis.fetch;
        firebaseAuth = new FirebaseAuth(mockConfig, undefined, mockFetch);
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

            const result = await firebaseAuth.signInWithProvider(
                'idToken',
                'http://localhost'
            );

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

            const result = await firebaseAuth.signInWithProvider(
                'idToken',
                'http://localhost'
            );

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
});
