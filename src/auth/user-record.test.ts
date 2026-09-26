import { describe, expect, it } from 'vitest';
import { createUserRecord, createGetUsersResult } from './user-record.js';

describe('createGetUsersResult', () => {
    it('matches primary identifiers and provider UIDs independently of result order', () => {
        const missing = { uid: 'missing' };
        const ids = [
            { uid: 'one' },
            { email: 'user@example.com' },
            { phoneNumber: '+15555550100' },
            { providerId: 'google.com', providerUid: 'external' },
            missing
        ];
        const result = createGetUsersResult(ids, {
            users: [
                { localId: 'two', phoneNumber: '+15555550100' },
                {
                    localId: 'one',
                    email: 'user@example.com',
                    providerUserInfo: [
                        { providerId: 'google.com', rawId: 'external' }
                    ]
                }
            ]
        });
        expect(result.users.map((user) => user.uid)).toEqual(['two', 'one']);
        expect(result.notFound).toEqual([missing]);
        expect(result.notFound[0]).toBe(missing);
        expect(result.users[0]?.toJSON()).toMatchObject({ uid: 'two' });
    });
    it('keeps unmatched duplicates and does not match provider emails as primary emails', () => {
        const ids = [
            { email: 'linked@example.com' },
            { uid: 'missing' },
            { uid: 'missing' },
            { providerId: 'github.com', providerUid: 'external' },
            { providerId: 'google.com', providerUid: 'wrong' }
        ];
        const result = createGetUsersResult(ids, {
            users: [
                {
                    localId: 'one',
                    providerUserInfo: [
                        {
                            providerId: 'google.com',
                            rawId: 'external',
                            email: 'linked@example.com'
                        }
                    ]
                }
            ]
        });
        expect(result.notFound).toEqual(ids);
    });
    it('marks all identifiers missing when users are omitted', () => {
        const ids = [{ uid: 'missing' }];
        expect(createGetUsersResult(ids, {})).toEqual({
            users: [],
            notFound: ids
        });
        expect(createGetUsersResult([], {})).toEqual({
            users: [],
            notFound: []
        });
    });
    it('does not duplicate a returned record for repeated identifiers', () => {
        expect(
            createGetUsersResult([{ uid: 'one' }, { uid: 'one' }], {
                users: [{ localId: 'one' }]
            }).users
        ).toHaveLength(1);
    });
});

describe('createUserRecord', () => {
    it('maps profile, metadata, providers, claims, password fields, and MFA', () => {
        const user = createUserRecord({
            localId: 'uid',
            email: 'user@example.com',
            emailVerified: true,
            displayName: 'User',
            photoUrl: 'https://example.com/photo',
            phoneNumber: '+15555550100',
            disabled: true,
            createdAt: '1000',
            lastLoginAt: '2000',
            lastRefreshAt: '2025-01-01T00:00:00Z',
            validSince: '3',
            passwordHash: 'hash',
            salt: 'salt',
            customAttributes: '{"roles":["admin"]}',
            tenantId: 'tenant',
            providerUserInfo: [
                {
                    rawId: 'provider-uid',
                    providerId: 'google.com',
                    photoUrl: 'https://example.com/provider'
                }
            ],
            mfaInfo: [
                {
                    mfaEnrollmentId: 'phone',
                    phoneInfo: '+15555550100',
                    enrolledAt: '2025-01-01T00:00:00Z',
                    displayName: 'Phone'
                },
                { mfaEnrollmentId: 'totp', totpInfo: {} },
                { mfaEnrollmentId: 'unsupported' },
                { mfaEnrollmentId: '', phoneInfo: '+15555550100' },
                {
                    mfaEnrollmentId: 'invalid-date',
                    phoneInfo: '+15555550100',
                    enrolledAt: 'invalid'
                }
            ]
        });
        expect(user).toMatchObject({
            uid: 'uid',
            email: 'user@example.com',
            emailVerified: true,
            displayName: 'User',
            photoURL: 'https://example.com/photo',
            phoneNumber: '+15555550100',
            disabled: true,
            passwordHash: 'hash',
            passwordSalt: 'salt',
            tenantId: 'tenant',
            customClaims: { roles: ['admin'] },
            tokensValidAfterTime: 'Thu, 01 Jan 1970 00:00:03 GMT'
        });
        expect(user.metadata.toJSON()).toEqual({
            creationTime: 'Thu, 01 Jan 1970 00:00:01 GMT',
            lastSignInTime: 'Thu, 01 Jan 1970 00:00:02 GMT',
            lastRefreshTime: 'Wed, 01 Jan 2025 00:00:00 GMT'
        });
        expect(user.providerData[0]?.toJSON()).toMatchObject({
            uid: 'provider-uid',
            providerId: 'google.com',
            photoURL: 'https://example.com/provider'
        });
        expect(user.multiFactor?.enrolledFactors).toHaveLength(3);
        expect(user.multiFactor?.enrolledFactors[0]?.toJSON()).toMatchObject({
            uid: 'phone',
            factorId: 'phone',
            phoneNumber: '+15555550100',
            enrollmentTime: 'Wed, 01 Jan 2025 00:00:00 GMT'
        });
        expect(user.multiFactor?.enrolledFactors[1]?.toJSON()).toMatchObject({
            uid: 'totp',
            factorId: 'totp',
            totpInfo: {},
            enrollmentTime: null
        });
        expect(user.multiFactor?.enrolledFactors[2]?.enrollmentTime).toBe(
            'Invalid Date'
        );
        expect(user.multiFactor?.toJSON()).toEqual({
            enrolledFactors: user.multiFactor?.enrolledFactors.map((factor) =>
                factor.toJSON()
            )
        });
        const json = user.toJSON() as Record<string, any>;
        expect(json).not.toHaveProperty('toJSON');
        expect(json.metadata).not.toHaveProperty('toJSON');
        json.customClaims.roles.push('editor');
        expect(user.customClaims?.roles).toEqual(['admin']);
        expect(JSON.parse(JSON.stringify(user))).toMatchObject({
            uid: 'uid',
            providerData: [{ uid: 'provider-uid' }]
        });
    });

    it('normalizes missing and invalid dates and hides redacted password hashes', () => {
        const user = createUserRecord({
            localId: 'uid',
            createdAt: 'invalid',
            validSince: 'invalid',
            passwordHash: 'UkVEQUNURUQ='
        });
        expect(user.metadata.toJSON()).toEqual({
            creationTime: null,
            lastSignInTime: null,
            lastRefreshTime: null
        });
        expect(user.tokensValidAfterTime).toBeUndefined();
        expect(user.passwordHash).toBeUndefined();
        expect(user).not.toHaveProperty('multiFactor');
        expect(user.providerData).toEqual([]);
    });

    it('preserves empty password hash and salt for imported accounts', () => {
        const user = createUserRecord({
            localId: 'uid',
            passwordHash: '',
            salt: ''
        });
        expect(user.passwordHash).toBe('');
        expect(user.passwordSalt).toBe('');
    });

    it.each([
        { localId: '' },
        { localId: 'uid', providerUserInfo: [{ providerId: 'google.com' }] },
        { localId: 'uid', providerUserInfo: [{ rawId: 'provider-uid' }] }
    ])('rejects malformed user/provider records', (user) => {
        expect(() => createUserRecord(user)).toThrow();
    });
});
