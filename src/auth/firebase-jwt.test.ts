import { describe, it, expect, vi, beforeEach, beforeAll } from 'vitest';
import {
    generateKeyPair,
    exportJWK,
    exportSPKI,
    SignJWT,
    exportPKCS8,
    jwtVerify,
    UnsecuredJWT,
    decodeProtectedHeader
} from 'jose';
import {
    verifyAuthBlockingJWT,
    verifySessionJWT,
    verifyJWT,
    signJWT,
    signJWTCustomToken
} from './firebase-jwt.js';
import type { JWTPayload } from 'jose';
import type { ServiceAccount } from './firebase-types.js';
import * as firebaseAuthEndpoints from './firebase-auth-endpoints.js';
import { FirebaseEdgeError } from './errors.js';
import { JWTErrorInfo, FirebaseEndpointErrorInfo } from './auth-error-codes.js';

vi.mock('./firebase-auth-endpoints');

describe('Auth blocking token verification', () => {
    let keys: Awaited<ReturnType<typeof generateKeyPair>>;
    let publicJwk: import('node:crypto').JsonWebKey & { kid: string };
    const projectId = 'blocking-project';
    let claims: JWTPayload;
    beforeAll(async () => {
        keys = await generateKeyPair('RS256');
        const jwk = await exportJWK(keys.publicKey);
        publicJwk = { ...jwk, kid: 'blocking-key' };
    });
    beforeEach(() => {
        vi.resetAllMocks();
        const now = Math.floor(Date.now() / 1000);
        claims = {
            iss: `https://securetoken.google.com/${projectId}`,
            aud: `https://us-central1-${projectId}.cloudfunctions.net/beforeSignIn`,
            sub: 'user',
            iat: now,
            exp: now + 60,
            event_type: 'beforeSignIn',
            event_id: 'event',
            tenant_id: 'tenant-a',
            user_record: { uid: 'user', email: 'user@example.com' }
        };
        vi.mocked(firebaseAuthEndpoints.getJWKs).mockResolvedValue({
            data: [publicJwk],
            error: null
        });
    });

    it('verifies a real signature, preserves event data, and derives uid', async () => {
        const token = await new SignJWT(claims)
            .setProtectedHeader({ alg: 'RS256', kid: 'blocking-key' })
            .sign(keys.privateKey);
        const fetchFn = vi.fn();
        const result = await verifyAuthBlockingJWT(
            token,
            projectId,
            undefined,
            fetchFn
        );
        expect(result).toEqual({
            data: { ...claims, uid: 'user' },
            error: null
        });
        expect(firebaseAuthEndpoints.getJWKs).toHaveBeenCalledWith(fetchFn);
        const idResult = await verifyJWT(token, projectId, fetchFn);
        expect(idResult.error).toBeInstanceOf(FirebaseEdgeError);
    });

    it('supports the SDK audience override for Cloud Run and specific endpoints', async () => {
        claims.aud = 'https://hook-123.run.app/';
        const token = await new SignJWT(claims)
            .setProtectedHeader({ alg: 'RS256', kid: 'blocking-key' })
            .sign(keys.privateKey);
        for (const audience of ['run.app', 'https://hook-123.run.app/']) {
            const result = await verifyAuthBlockingJWT(
                token,
                projectId,
                audience
            );
            expect(result.error).toBeNull();
        }
        const wrong = await verifyAuthBlockingJWT(token, projectId);
        expect(wrong.error?.code).toBe('auth/jwt-claim-validation-failed');
    });

    it.each([
        { aud: 'other-project' },
        { aud: ['blocking-project.cloudfunctions.net/'] },
        { iss: 'https://securetoken.google.com/other' },
        { sub: '' },
        { sub: undefined },
        { sub: 'x'.repeat(129) },
        { iat: undefined },
        { iat: 9999999999 },
        { exp: undefined },
        { event_type: undefined },
        { event_id: '' }
    ])('rejects invalid signed claims %j', async (overrides) => {
        const token = await new SignJWT({ ...claims, ...overrides })
            .setProtectedHeader({ alg: 'RS256', kid: 'blocking-key' })
            .sign(keys.privateKey);
        const result = await verifyAuthBlockingJWT(token, projectId);
        expect(result.data).toBeNull();
        expect(result.error?.code).toBe('auth/jwt-claim-validation-failed');
    });

    it.each(['beforeSendEmail', 'beforeSendSms'])(
        'allows %s without a user subject',
        async (event_type) => {
            const { sub: _sub, user_record: _user, ...event } = claims;
            const token = await new SignJWT({ ...event, event_type })
                .setProtectedHeader({ alg: 'RS256', kid: 'blocking-key' })
                .sign(keys.privateKey);
            const result = await verifyAuthBlockingJWT(token, projectId);
            expect(result.error).toBeNull();
            expect(result.data?.uid).toBeUndefined();
        }
    );

    it('returns a specific error for expired blocking tokens', async () => {
        const token = await new SignJWT({ ...claims, exp: 1 })
            .setProtectedHeader({ alg: 'RS256', kid: 'blocking-key' })
            .sign(keys.privateKey);
        const result = await verifyAuthBlockingJWT(token, projectId);
        expect(result.error?.code).toBe('auth/auth-blocking-token-expired');
    });

    it('rejects forged signatures, unknown keys, and unsupported algorithms', async () => {
        const otherKeys = await generateKeyPair('RS256');
        const forged = await new SignJWT(claims)
            .setProtectedHeader({ alg: 'RS256', kid: 'blocking-key' })
            .sign(otherKeys.privateKey);
        const unknown = await new SignJWT(claims)
            .setProtectedHeader({ alg: 'RS256', kid: 'unknown' })
            .sign(keys.privateKey);
        const wrongAlgorithm = await new SignJWT(claims)
            .setProtectedHeader({ alg: 'HS256', kid: 'blocking-key' })
            .sign(new Uint8Array(32));
        for (const token of [forged, unknown, wrongAlgorithm, 'not-a-jwt']) {
            const result = await verifyAuthBlockingJWT(token, projectId);
            expect(result.data).toBeNull();
            expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        }
    });

    it('returns key fetch failures, empty keysets, and network errors', async () => {
        const token = await new SignJWT(claims)
            .setProtectedHeader({ alg: 'RS256', kid: 'blocking-key' })
            .sign(keys.privateKey);
        const error = new FirebaseEdgeError({
            code: 'auth/test',
            message: 'Unavailable'
        });
        vi.mocked(firebaseAuthEndpoints.getJWKs)
            .mockResolvedValueOnce({ data: null, error })
            .mockResolvedValueOnce({ data: [], error: null })
            .mockRejectedValueOnce(new Error('offline'));
        const unavailable = await verifyAuthBlockingJWT(token, projectId);
        const empty = await verifyAuthBlockingJWT(token, projectId);
        const network = await verifyAuthBlockingJWT(token, projectId);
        expect(unavailable.error).toBe(error);
        expect(empty.error?.code).toBe('auth/jwt-no-jwks-retrieved');
        expect(network.error?.cause).toMatchObject({ message: 'offline' });
    });

    it('accepts unsigned tokens only in emulator mode and retains claim validation', async () => {
        const token = new UnsecuredJWT(claims).encode();
        const emulator = await verifyAuthBlockingJWT(
            token,
            projectId,
            undefined,
            undefined,
            true
        );
        expect(emulator.error).toBeNull();
        expect(firebaseAuthEndpoints.getJWKs).not.toHaveBeenCalled();
        const production = await verifyAuthBlockingJWT(token, projectId);
        expect(production.error).toBeInstanceOf(FirebaseEdgeError);
        const invalid = new UnsecuredJWT({
            ...claims,
            aud: projectId
        }).encode();
        const wrongAudience = await verifyAuthBlockingJWT(
            invalid,
            projectId,
            undefined,
            undefined,
            true
        );
        expect(wrongAudience.error).toBeInstanceOf(FirebaseEdgeError);
    });

    it.each([
        ['', projectId, undefined],
        [null, projectId, undefined],
        ['token', '', undefined],
        ['token', projectId, ''],
        ['token', projectId, '   '],
        ['token', projectId, 123]
    ])('guards invalid arguments %j', async (token, project, audience) => {
        const result = await verifyAuthBlockingJWT(
            token as string,
            project as string,
            audience as string | undefined
        );
        expect(result.error?.code).toBe('auth/invalid-argument');
        expect(firebaseAuthEndpoints.getJWKs).not.toHaveBeenCalled();
    });
});

describe.each(['id', 'session'] as const)(
    'signed %s token validation',
    (kind) => {
        let keys: Awaited<ReturnType<typeof generateKeyPair>>;
        let publicJwk: Awaited<ReturnType<typeof exportJWK>>;
        let publicPem: string;
        const verify = kind === 'id' ? verifyJWT : verifySessionJWT;
        const issuer =
            kind === 'id'
                ? 'https://securetoken.google.com/audit-project'
                : 'https://session.firebase.google.com/audit-project';

        beforeAll(async () => {
            keys = await generateKeyPair('RS256', { extractable: true });
            publicJwk = await exportJWK(keys.publicKey);
            publicPem = await exportSPKI(keys.publicKey);
        });
        beforeEach(() => {
            vi.mocked(firebaseAuthEndpoints.getJWKs).mockResolvedValue({
                data: [{ ...publicJwk, kid: 'audit-key' }],
                error: null
            });
            vi.mocked(firebaseAuthEndpoints.getPublicKeys).mockResolvedValue({
                data: { 'audit-key': publicPem },
                error: null
            });
        });

        it.each([
            { sub: undefined },
            { sub: '' },
            { sub: 'x'.repeat(129) },
            { exp: undefined },
            { exp: 1 },
            { iat: undefined },
            { iat: 9999999999 },
            { auth_time: undefined },
            { auth_time: 'now' },
            { auth_time: -1 },
            { auth_time: 9999999999 },
            { aud: ['audit-project'] },
            { aud: 'wrong-project' },
            { iss: 'wrong-issuer' }
        ])(
            'rejects correctly signed tokens with invalid claims %j',
            async (overrides) => {
                const now = Math.floor(Date.now() / 1000);
                const token = await new SignJWT({
                    iss: issuer,
                    aud: 'audit-project',
                    sub: 'user',
                    iat: now,
                    exp: now + 3600,
                    auth_time: now,
                    ...overrides
                } as JWTPayload)
                    .setProtectedHeader({ alg: 'RS256', kid: 'audit-key' })
                    .sign(keys.privateKey);
                const result = await verify(token, 'audit-project');
                expect(result.data).toBeNull();
                expect(result.error).toBeInstanceOf(FirebaseEdgeError);
                expect(result.error?.cause).toMatchObject({
                    claim: Object.keys(overrides)[0]
                });
            }
        );

        it.each([
            ['iat', 1],
            ['iat', 5],
            ['iat', 6],
            ['auth_time', 1],
            ['auth_time', 5],
            ['auth_time', 6]
        ] as const)(
            'checks bounded clock skew for %s at +%i seconds',
            async (claim, offset) => {
                const now = Math.floor(Date.now() / 1000);
                const clock = vi.spyOn(Date, 'now').mockReturnValue(now * 1000);
                try {
                    const token = await new SignJWT({
                        iss: issuer,
                        aud: 'audit-project',
                        sub: 'user',
                        iat: now,
                        auth_time: now,
                        exp: now + 3600,
                        [claim]: now + offset
                    })
                        .setProtectedHeader({ alg: 'RS256', kid: 'audit-key' })
                        .sign(keys.privateKey);
                    const result = await verify(token, 'audit-project');
                    if (offset <= 5) {
                        expect(result.error).toBeNull();
                        expect(result.data?.sub).toBe('user');
                        return;
                    }
                    expect(result.data).toBeNull();
                    expect(result.error?.cause).toMatchObject({
                        claim,
                        reason: 'check_failed',
                        message: expect.stringContaining('6 seconds ahead')
                    });
                } finally {
                    clock.mockRestore();
                }
            }
        );

        it('still rejects a token that just expired', async () => {
            const now = Math.floor(Date.now() / 1000);
            const token = await new SignJWT({
                iss: issuer,
                aud: 'audit-project',
                sub: 'user',
                iat: now - 3600,
                auth_time: now - 3600,
                exp: now - 1
            })
                .setProtectedHeader({ alg: 'RS256', kid: 'audit-key' })
                .sign(keys.privateKey);
            const result = await verify(token, 'audit-project');
            expect(result.data).toBeNull();
            expect(result.error?.code).toBe(JWTErrorInfo.JWT_EXPIRED.code);
        });

        it('sets uid from the verified subject and preserves tenant/custom claims', async () => {
            const now = Math.floor(Date.now() / 1000);
            const token = await new SignJWT({
                iss: issuer,
                aud: 'audit-project',
                sub: 'user',
                uid: 'untrusted-alias',
                iat: now,
                exp: now + 3600,
                auth_time: now,
                firebase: { tenant: 'tenant-a' },
                role: 'editor'
            })
                .setProtectedHeader({ alg: 'RS256', kid: 'audit-key' })
                .sign(keys.privateKey);
            const result = await verify(token, 'audit-project');
            expect(result.error).toBeNull();
            expect(result.data).toMatchObject({
                uid: 'user',
                sub: 'user',
                role: 'editor',
                firebase: { tenant: 'tenant-a' }
            });
        });

        it('rejects a signature from a different key', async () => {
            const otherKeys = await generateKeyPair('RS256');
            const now = Math.floor(Date.now() / 1000);
            const token = await new SignJWT({
                iss: issuer,
                aud: 'audit-project',
                sub: 'user',
                iat: now,
                exp: now + 3600,
                auth_time: now
            })
                .setProtectedHeader({ alg: 'RS256', kid: 'audit-key' })
                .sign(otherKeys.privateKey);
            const result = await verify(token, 'audit-project');
            expect(result.data).toBeNull();
            expect(result.error?.code).toBe(
                JWTErrorInfo.JWT_INVALID_SIGNATURE.code
            );
        });
    }
);

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

    describe.each(['id', 'session'] as const)(
        'emulator %s token verification',
        (kind) => {
            const verify = kind === 'id' ? verifyJWT : verifySessionJWT;
            const issuer =
                kind === 'id'
                    ? 'https://securetoken.google.com/test-project-id'
                    : 'https://session.firebase.google.com/test-project-id';

            it('accepts unsigned emulator tokens without downloading public keys', async () => {
                const now = Math.floor(Date.now() / 1000);
                const token = new UnsecuredJWT({
                    iss: issuer,
                    aud: mockProjectId,
                    sub: 'user',
                    iat: now,
                    exp: now + 3600,
                    auth_time: now,
                    firebase: { tenant: 'tenant-a' }
                }).encode();
                const fetchFn = vi.fn();
                const result = await verify(
                    token,
                    mockProjectId,
                    fetchFn,
                    true
                );
                expect(result.error).toBeNull();
                expect(result.data).toMatchObject({
                    sub: 'user',
                    uid: 'user',
                    firebase: { tenant: 'tenant-a' }
                });
                expect(fetchFn).not.toHaveBeenCalled();
                expect(
                    firebaseAuthEndpoints.getPublicKeys
                ).not.toHaveBeenCalled();
                expect(firebaseAuthEndpoints.getJWKs).not.toHaveBeenCalled();
            });

            it.each([
                { aud: 'other-project' },
                { aud: ['test-project-id'] },
                { iss: 'https://wrong.example.com' },
                { sub: '' },
                { sub: 42 },
                { sub: 'x'.repeat(129) },
                { sub: undefined },
                { exp: 1 },
                { exp: undefined },
                { iat: undefined },
                { iat: 9999999999 },
                { auth_time: undefined },
                { auth_time: 'now' },
                { auth_time: -1 },
                { auth_time: 9999999999 },
                { nbf: 9999999999 }
            ])('rejects invalid claims %j', async (overrides) => {
                const now = Math.floor(Date.now() / 1000);
                const token = new UnsecuredJWT({
                    iss: issuer,
                    aud: mockProjectId,
                    sub: 'user',
                    iat: now,
                    exp: now + 3600,
                    auth_time: now,
                    ...overrides
                } as never).encode();
                const result = await verify(
                    token,
                    mockProjectId,
                    vi.fn(),
                    true
                );
                expect(result.data).toBeNull();
                expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            });

            it('rejects malformed tokens and tokens with a signature', async () => {
                for (const token of [
                    'bad',
                    'a.b.c',
                    new UnsecuredJWT({}).encode() + 'signature'
                ]) {
                    const result = await verify(
                        token,
                        mockProjectId,
                        vi.fn(),
                        true
                    );
                    expect(result.error).toBeInstanceOf(FirebaseEdgeError);
                }
            });

            it('rejects unsigned tokens in production mode', async () => {
                const now = Math.floor(Date.now() / 1000);
                const token = new UnsecuredJWT({
                    iss: issuer,
                    aud: mockProjectId,
                    sub: 'user',
                    iat: now,
                    exp: now + 3600,
                    auth_time: now
                }).encode();
                vi.mocked(
                    firebaseAuthEndpoints.getPublicKeys
                ).mockResolvedValue({ data: { key: 'unused' }, error: null });
                const result = await verify(token, mockProjectId, vi.fn());
                expect(result.data).toBeNull();
                expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            });
        }
    );

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
        it('requests the cloud-platform scope required by App Check', async () => {
            const keys = await generateKeyPair('RS256', { extractable: true });
            const privateKey = await exportPKCS8(keys.privateKey);
            const { error, data } = await signJWT({
                ...mockServiceAccount,
                private_key: privateKey
            });
            expect(error).toBeNull();
            const { payload } = await jwtVerify(data!, keys.publicKey);
            expect(String(payload.scope).split(' ')).toContain(
                'https://www.googleapis.com/auth/cloud-platform'
            );
        });
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
        it.each([undefined, 'tenant-a'])(
            'creates unsigned custom tokens without a private key in emulator mode (%s)',
            async (tenantId) => {
                const account = {
                    ...mockServiceAccount,
                    private_key: '',
                    client_email: ''
                };
                const result = await signJWTCustomToken(
                    uid,
                    account,
                    { role: 'editor' },
                    tenantId,
                    true
                );
                expect(result.error).toBeNull();
                if (!result.data)
                    throw new Error('Expected an emulator custom token.');
                const { payload } = UnsecuredJWT.decode(result.data);
                expect(payload).toMatchObject({
                    uid,
                    claims: { role: 'editor' }
                });
                expect(payload.tenant_id).toBe(tenantId);
                expect(decodeProtectedHeader(result.data).alg).toBe('none');
                const production = await signJWTCustomToken(
                    uid,
                    account,
                    {},
                    tenantId
                );
                expect(production.error).toBeInstanceOf(FirebaseEdgeError);
            }
        );

        it.each(['', 'x'.repeat(129), null, 42])(
            'rejects invalid custom token UID %j',
            async (invalidUid) => {
                const result = await signJWTCustomToken(
                    invalidUid as string,
                    mockServiceAccount,
                    {},
                    undefined,
                    true
                );
                expect(result.data).toBeNull();
                expect(result.error).toBeInstanceOf(FirebaseEdgeError);
            }
        );
        it.each([null, [], 'claims', 42])(
            'returns an error for invalid developer claims %j',
            async (claims) => {
                const result = await signJWTCustomToken(
                    uid,
                    mockServiceAccount,
                    claims as object,
                    undefined,
                    true
                );
                expect(result.data).toBeNull();
                expect(result.error?.code).toBe('auth/invalid-argument');
            }
        );

        it('keeps reserved claim validation in emulator mode', async () => {
            const result = await signJWTCustomToken(
                uid,
                mockServiceAccount,
                { aud: 'override' },
                undefined,
                true
            );
            expect(result.error?.code).toBe('auth/jwt-reserved-claims');
        });
        let signingAccount: ServiceAccount;
        let publicKey: Awaited<ReturnType<typeof generateKeyPair>>['publicKey'];

        beforeAll(async () => {
            const keys = await generateKeyPair('RS256', { extractable: true });
            const privateKey = await exportPKCS8(keys.privateKey);
            publicKey = keys.publicKey;
            signingAccount = { ...mockServiceAccount, private_key: privateKey };
        });

        it.each([
            { tenantId: 'tenant-a', claims: { role: 'admin' } },
            { tenantId: 'tenant-a', claims: {} },
            { tenantId: undefined, claims: { role: 'admin' } },
            { tenantId: undefined, claims: {} },
            { tenantId: 'tenant-a', claims: { tenant_id: 'developer-value' } }
        ])(
            'signs tenant scope separately from custom claims: %j',
            async ({ tenantId, claims }) => {
                Object.freeze(claims);
                const result = await signJWTCustomToken(
                    uid,
                    signingAccount,
                    claims,
                    tenantId
                );
                expect(result.error).toBeNull();
                if (!result.data)
                    throw new Error('Expected a signed custom token.');
                const { payload } = await jwtVerify(result.data, publicKey, {
                    algorithms: ['RS256'],
                    issuer: signingAccount.client_email,
                    subject: signingAccount.client_email,
                    audience:
                        'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit'
                });
                expect(payload.uid).toBe(uid);
                expect(payload.tenant_id).toBe(tenantId);
                expect(Object.hasOwn(payload, 'tenant_id')).toBe(
                    tenantId !== undefined
                );
                expect(payload.claims).toEqual(
                    Object.keys(claims).length ? claims : undefined
                );
            }
        );

        it('accepts escaped newlines in service account keys', async () => {
            const result = await signJWTCustomToken(uid, {
                ...signingAccount,
                private_key: signingAccount.private_key.replace(/\n/g, '\\n')
            });
            expect(result.error).toBeNull();
            expect(result.data).toEqual(expect.any(String));
        });

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
