import { describe, expect, it } from 'vitest';
import {
    buildImportHashOptions,
    buildImportUser,
    prepareUserImport,
    type HashAlgorithmType,
    type UserImportOptions,
    type UserImportRecord
} from './user-import.js';

describe('buildImportHashOptions', () => {
    it('supports bcrypt and all HMAC variants', () => {
        expect(
            buildImportHashOptions({ hash: { algorithm: 'BCRYPT' } })
        ).toEqual({ hashAlgorithm: 'BCRYPT' });
        for (const algorithm of [
            'HMAC_SHA512',
            'HMAC_SHA256',
            'HMAC_SHA1',
            'HMAC_MD5'
        ] as const) {
            expect(
                buildImportHashOptions({
                    hash: { algorithm, key: new Uint8Array([251, 255]) }
                })
            ).toEqual({ hashAlgorithm: algorithm, signerKey: '-_8=' });
        }
    });
    it.each(['MD5', 'SHA1', 'SHA256', 'SHA512', 'PBKDF_SHA1', 'PBKDF2_SHA256'])(
        'maps rounds for %s',
        (algorithm) => {
            expect(
                buildImportHashOptions({
                    hash: {
                        algorithm: algorithm as HashAlgorithmType,
                        rounds: 2
                    }
                })
            ).toEqual({ hashAlgorithm: algorithm, rounds: 2 });
        }
    );
    it('maps Firebase SCRYPT parameters with default or explicit salt separators', () => {
        const hash: UserImportOptions['hash'] = {
            algorithm: 'SCRYPT',
            key: new Uint8Array([1]),
            rounds: 8,
            memoryCost: 14
        };
        expect(buildImportHashOptions({ hash })).toEqual({
            hashAlgorithm: 'SCRYPT',
            signerKey: 'AQ==',
            rounds: 8,
            memoryCost: 14,
            saltSeparator: ''
        });
        expect(
            buildImportHashOptions({
                hash: { ...hash, saltSeparator: new Uint8Array([2]) }
            }).saltSeparator
        ).toBe('Ag==');
    });
    it('maps standard scrypt fields', () => {
        expect(
            buildImportHashOptions({
                hash: {
                    algorithm: 'STANDARD_SCRYPT',
                    memoryCost: 16384,
                    parallelization: 1,
                    blockSize: 8,
                    derivedKeyLength: 64
                }
            })
        ).toEqual({
            hashAlgorithm: 'STANDARD_SCRYPT',
            cpuMemCost: 16384,
            parallelization: 1,
            blockSize: 8,
            dkLen: 64
        });
    });
    it.each([
        undefined,
        {},
        { hash: {} },
        { hash: { algorithm: 'UNKNOWN' } },
        { hash: { algorithm: 'HMAC_SHA1' } },
        { hash: { algorithm: 'HMAC_SHA1', key: 'secret' } },
        { hash: { algorithm: 'MD5', rounds: -1 } },
        { hash: { algorithm: 'SHA1', rounds: 0 } },
        { hash: { algorithm: 'SHA256', rounds: 8193 } },
        { hash: { algorithm: 'PBKDF_SHA1', rounds: 120001 } },
        { hash: { algorithm: 'SHA512', rounds: 1.5 } },
        { hash: { algorithm: 'SCRYPT', rounds: 9 } },
        { hash: { algorithm: 'SCRYPT', rounds: 8, memoryCost: 15 } },
        { hash: { algorithm: 'SCRYPT', rounds: 8, memoryCost: 14 } },
        { hash: { algorithm: 'STANDARD_SCRYPT' } }
    ])('rejects invalid hash settings %j', (options) => {
        expect(() =>
            buildImportHashOptions(options as UserImportOptions)
        ).toThrow();
    });
});

describe('buildImportUser', () => {
    it('translates profile, dates, claims, providers, bytes, and MFA without mutation', () => {
        const user: UserImportRecord = {
            uid: 'uid',
            email: 'user@example.com',
            emailVerified: true,
            disabled: false,
            photoURL: 'https://example.com/photo',
            phoneNumber: '+15555550100',
            tenantId: 'tenant',
            metadata: {
                creationTime: 'Wed, 01 Jan 2025 00:00:00 GMT',
                lastSignInTime: 'Thu, 02 Jan 2025 00:00:00 GMT'
            },
            customClaims: { role: 'editor' },
            passwordHash: new Uint8Array([251, 255]),
            passwordSalt: new Uint8Array([1]),
            providerData: [
                {
                    uid: 'external',
                    providerId: 'google.com',
                    email: 'user@example.com'
                }
            ],
            multiFactor: {
                enrolledFactors: [
                    {
                        factorId: 'phone',
                        phoneNumber: '+15555550101',
                        uid: 'factor'
                    }
                ]
            }
        };
        const snapshot = structuredClone(user);
        expect(buildImportUser(user, 'tenant')).toMatchObject({
            localId: 'uid',
            email: user.email,
            emailVerified: true,
            disabled: false,
            photoUrl: user.photoURL,
            tenantId: 'tenant',
            createdAt: 1735689600000,
            lastLoginAt: 1735776000000,
            customAttributes: '{"role":"editor"}',
            passwordHash: '-_8=',
            salt: 'AQ==',
            providerUserInfo: [
                {
                    rawId: 'external',
                    providerId: 'google.com',
                    email: user.email
                }
            ],
            mfaInfo: [{ phoneInfo: '+15555550101', mfaEnrollmentId: 'factor' }]
        });
        expect(user).toEqual(snapshot);
    });
    it('accepts Node Buffer as well as Uint8Array and handles empty bytes', () => {
        expect(
            buildImportUser({
                uid: 'uid',
                passwordHash: Buffer.from([1]),
                passwordSalt: new Uint8Array()
            })
        ).toMatchObject({ passwordHash: 'AQ==', salt: '' });
    });
    it('omits empty optional collections', () => {
        expect(
            buildImportUser({
                uid: 'uid',
                providerData: [],
                multiFactor: { enrolledFactors: [] }
            })
        ).toEqual({ localId: 'uid' });
    });
    it.each([
        null,
        {},
        { uid: '' },
        { uid: 'uid', email: 'invalid' },
        { uid: 'uid', passwordHash: 'not bytes' },
        { uid: 'uid', passwordSalt: 'not bytes' },
        { uid: 'uid', metadata: null },
        { uid: 'uid', metadata: { creationTime: 'invalid' } },
        { uid: 'uid', customClaims: [] },
        { uid: 'uid', customClaims: { sub: 'reserved' } },
        { uid: 'uid', customClaims: { claim: 'x'.repeat(1001) } },
        { uid: 'uid', providerData: 'invalid' },
        { uid: 'uid', providerData: [{}] },
        { uid: 'uid', multiFactor: { enrolledFactors: [{}] } },
        { uid: 'uid', tenantId: '' }
    ])('rejects invalid user %j', (user) => {
        expect(() => buildImportUser(user as UserImportRecord)).toThrow();
    });
    it('rejects mismatched tenants and circular claims', () => {
        expect(() =>
            buildImportUser({ uid: 'uid', tenantId: 'other' }, 'tenant')
        ).toThrow();
        const claims: Record<string, unknown> = {};
        claims.self = claims;
        expect(() =>
            buildImportUser({ uid: 'uid', customClaims: claims })
        ).toThrow();
    });
});

describe('prepareUserImport', () => {
    it('skips invalid users and preserves original indices for valid records', () => {
        const result = prepareUserImport([
            { uid: 'one' },
            { uid: '' },
            { uid: 'three' }
        ]);
        expect(result.error).toBeNull();
        expect(result.data?.indices).toEqual([0, 2]);
        expect(result.data?.body.users).toEqual([
            { localId: 'one' },
            { localId: 'three' }
        ]);
        expect(result.data?.errors).toMatchObject([{ index: 1 }]);
    });
    it('requires hash settings only when a valid record has a password hash', () => {
        expect(
            prepareUserImport([
                { uid: 'uid', passwordHash: new Uint8Array([1]) }
            ]).error
        ).not.toBeNull();
        expect(
            prepareUserImport([{ uid: '', passwordHash: new Uint8Array([1]) }])
                .error
        ).toBeNull();
        expect(
            prepareUserImport([{ uid: 'uid' }], {} as UserImportOptions).data
                ?.body
        ).toEqual({ users: [{ localId: 'uid' }] });
        expect(
            prepareUserImport(
                [{ uid: 'uid', passwordHash: new Uint8Array([1]) }],
                { hash: { algorithm: 'BCRYPT' } }
            ).data?.body.hashAlgorithm
        ).toBe('BCRYPT');
    });
    it('handles empty input and all-invalid records locally', () => {
        expect(prepareUserImport([]).data).toEqual({
            body: { users: [] },
            indices: [],
            errors: []
        });
        expect(prepareUserImport([{ uid: '' }]).data?.indices).toEqual([]);
    });
    it('accepts 1000 records and rejects oversized or non-array input', () => {
        expect(
            prepareUserImport(Array(1000).fill({ uid: 'uid' })).error
        ).toBeNull();
        expect(
            prepareUserImport(Array(1001).fill({ uid: 'uid' })).error
        ).not.toBeNull();
        expect(
            prepareUserImport(null as unknown as UserImportRecord[]).error
        ).not.toBeNull();
    });
});
