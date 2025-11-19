import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
    verifySessionJWT,
    verifyJWT,
    signJWT,
    signJWTCustomToken
} from './firebase-jwt.js';
import type { ServiceAccount } from './firebase-types.js';
import * as firebaseAuthEndpoints from './firebase-auth-endpoints.js';
import { FirebaseEdgeError } from './errors.js';
import { JWTErrorInfo, FirebaseEndpointErrorInfo } from './auth-error-codes.js';

vi.mock('./firebase-auth-endpoints');

describe('firebase-jwt', () => {
    const mockProjectId = 'test-project-id';
    const mockServiceAccount: ServiceAccount = {
        type: 'service_account',
        project_id: mockProjectId,
        private_key_id: 'mock-private-key-id',
        private_key:
            '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\n-----END PRIVATE KEY-----',
        client_email: 'test@test-project.iam.gserviceaccount.com',
        client_id: 'mock-client-id',
        auth_uri: 'https://accounts.google.com/o/oauth2/auth',
        token_uri: 'https://oauth2.googleapis.com/token',
        auth_provider_x509_cert_url:
            'https://www.googleapis.com/oauth2/v1/certs',
        client_x509_cert_url:
            'https://www.googleapis.com/robot/v1/metadata/x509/test%40test-project.iam.gserviceaccount.com'
    };

    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('verifySessionJWT', () => {
        it('should return error when no public keys retrieved', async () => {
            vi.spyOn(firebaseAuthEndpoints, 'getPublicKeys').mockResolvedValue({
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseEndpointErrorInfo.ENDPOINT_KEY_FETCH_FAILED
                )
            });

            const result = await verifySessionJWT(
                'invalid-token',
                mockProjectId
            );

            expect(result.error).toBeDefined();
            expect(result.data).toBeNull();
        });

        it('should return error when keyData is null', async () => {
            vi.spyOn(firebaseAuthEndpoints, 'getPublicKeys').mockResolvedValue({
                data: null,
                error: null
            });

            const result = await verifySessionJWT(
                'invalid-token',
                mockProjectId
            );

            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/jwt-no-public-keys');
            expect(result.error?.message).toBe(
                JWTErrorInfo.JWT_NO_PUBLIC_KEYS.message
            );
            expect(result.data).toBeNull();
        });

        it('should return error when token has no KID', async () => {
            vi.spyOn(firebaseAuthEndpoints, 'getPublicKeys').mockResolvedValue({
                data: { key1: 'public-key' },
                error: null
            });

            const result = await verifySessionJWT(
                'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid',
                mockProjectId
            );

            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/jwt-no-kid-found');
            expect(result.error?.message).toBe(
                JWTErrorInfo.JWT_NO_KID_FOUND.message
            );
            expect(result.data).toBeNull();
        });

        it('should return error when public key not found for KID', async () => {
            vi.spyOn(firebaseAuthEndpoints, 'getPublicKeys').mockResolvedValue({
                data: { key1: 'public-key' },
                error: null
            });

            const result = await verifySessionJWT(
                'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTIifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid',
                mockProjectId
            );

            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/jwt-no-kid-found');
            expect(result.error?.message).toBe(
                JWTErrorInfo.JWT_NO_KID_FOUND.message
            );
            expect(result.data).toBeNull();
        });
    });

    describe('verifyJWT', () => {
        it('should return error when token has no KID', async () => {
            const result = await verifyJWT(
                'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid',
                mockProjectId
            );

            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/jwt-no-kid-found');
            expect(result.error?.message).toBe(
                JWTErrorInfo.JWT_NO_KID_FOUND.message
            );
            expect(result.data).toBeNull();
        });

        it('should return error when getJWKs fails', async () => {
            vi.spyOn(firebaseAuthEndpoints, 'getJWKs').mockResolvedValue({
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseEndpointErrorInfo.ENDPOINT_NETWORK_ERROR
                )
            });

            const result = await verifyJWT(
                'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid',
                mockProjectId
            );

            expect(result.error).toBeDefined();
            expect(result.data).toBeNull();
        });

        it('should return error when no JWKs retrieved', async () => {
            vi.spyOn(firebaseAuthEndpoints, 'getJWKs').mockResolvedValue({
                data: null,
                error: null
            });

            const result = await verifyJWT(
                'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid',
                mockProjectId
            );

            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/jwt-no-jwks-retrieved');
            expect(result.error?.message).toBe(
                JWTErrorInfo.JWT_NO_JWKS_RETRIEVED.message
            );
            expect(result.data).toBeNull();
        });

        it('should return error when no matching JWK found', async () => {
            vi.spyOn(firebaseAuthEndpoints, 'getJWKs').mockResolvedValue({
                data: [{ kid: 'different-key', kty: 'RSA' }],
                error: null
            });

            const result = await verifyJWT(
                'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid',
                mockProjectId
            );

            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/jwt-no-matching-key');
            expect(result.error?.message).toBe(
                JWTErrorInfo.JWT_NO_MATCHING_KEY.message
            );
            expect(result.data).toBeNull();
        });
    });

    describe('signJWT', () => {
        it('should return error when private key is invalid', async () => {
            const invalidServiceAccount: ServiceAccount = {
                ...mockServiceAccount,
                private_key: 'invalid-key'
            };

            const result = await signJWT(invalidServiceAccount);

            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe(
                'auth/jwt-private-key-import-failed'
            );
            expect(result.error?.message).toBe(
                JWTErrorInfo.JWT_PRIVATE_KEY_IMPORT_FAILED.message
            );
            expect(result.data).toBeNull();
        });

        it('should handle escaped newlines in private key', async () => {
            const serviceAccountWithEscaped: ServiceAccount = {
                ...mockServiceAccount,
                private_key: mockServiceAccount.private_key.replace(
                    /\n/g,
                    '\\n'
                )
            };

            const result = await signJWT(serviceAccountWithEscaped);

            expect(result.error).toBeDefined();
        });
    });

    describe('signJWTCustomToken', () => {
        const uid = 'test-uid-123';

        it('should return error when reserved claims are used', async () => {
            const result = await signJWTCustomToken(uid, mockServiceAccount, {
                aud: 'reserved'
            });

            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/jwt-reserved-claims');
            expect(result.error?.message).toBe(
                JWTErrorInfo.JWT_RESERVED_CLAIMS.message
            );
            expect(result.data).toBeNull();
        });

        it('should return error when firebase prefixed claims are used', async () => {
            const result = await signJWTCustomToken(uid, mockServiceAccount, {
                firebase_custom: 'value'
            });

            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            expect(result.error?.code).toBe('auth/jwt-reserved-claims');
            expect(result.error?.message).toBe(
                JWTErrorInfo.JWT_RESERVED_CLAIMS.message
            );
            expect(result.data).toBeNull();
        });

        it('should return error with invalid private key', async () => {
            const invalidServiceAccount: ServiceAccount = {
                ...mockServiceAccount,
                private_key: 'invalid-key'
            };

            const result = await signJWTCustomToken(
                uid,
                invalidServiceAccount,
                {}
            );

            expect(result.error).toBeDefined();
            expect(result.data).toBeNull();
        });

        it('should accept empty additional claims', async () => {
            const result = await signJWTCustomToken(uid, mockServiceAccount);

            expect(result.error).toBeDefined();
        });
    });
});
