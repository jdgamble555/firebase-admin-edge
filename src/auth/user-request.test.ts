import { describe, expect, it } from 'vitest';
import {
    buildUsersLookupRequest,
    type UserIdentifier,
    buildUserRequest,
    validateUserUid,
    type CreateRequest,
    type UpdateRequest
} from './user-request.js';

describe('buildUsersLookupRequest', () => {
    it('groups all four identifier types without mutating them', () => {
        const ids = [
            { uid: 'one' },
            { email: 'user@example.com' },
            { phoneNumber: '+15555550100' },
            { providerId: 'google.com', providerUid: 'external' },
            { uid: 'two' }
        ];
        const original = structuredClone(ids);
        expect(buildUsersLookupRequest(ids)).toEqual({
            data: {
                localId: ['one', 'two'],
                email: ['user@example.com'],
                phoneNumber: ['+15555550100'],
                federatedUserId: [
                    { providerId: 'google.com', rawId: 'external' }
                ]
            },
            error: null
        });
        expect(ids).toEqual(original);
    });
    it('accepts empty batches and the 100-identifier boundary', () => {
        expect(buildUsersLookupRequest([])).toEqual({ data: {}, error: null });
        expect(
            buildUsersLookupRequest(
                Array.from({ length: 100 }, (_, i) => ({ uid: String(i) }))
            ).error
        ).toBeNull();
    });
    it.each([
        null,
        {},
        'uid',
        [null],
        [[]],
        [{}],
        [{ uid: '' }],
        [{ uid: 'x'.repeat(129) }],
        [{ email: 'invalid' }],
        [{ phoneNumber: '555' }],
        [{ providerId: 'google.com' }],
        [{ providerUid: 'external' }],
        [{ providerId: '', providerUid: 'external' }],
        [{ providerId: 'google.com', providerUid: 1 }],
        Array(101).fill({ uid: 'uid' })
    ])('rejects invalid identifiers %j', (ids) => {
        const result = buildUsersLookupRequest(ids as UserIdentifier[]);
        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(Error);
    });
});

describe('validateUserUid', () => {
    it.each(['uid', 'a'.repeat(128)])('accepts valid UIDs', (uid) => {
        expect(validateUserUid(uid)).toBeNull();
    });
    it.each(['', null, 1, 'a'.repeat(129)])('rejects invalid UID %s', (uid) => {
        expect(validateUserUid(uid as string)).toBeInstanceOf(Error);
    });
});

describe('buildUserRequest', () => {
    it('maps create properties without mutating the caller', () => {
        const properties = Object.freeze({
            uid: 'uid',
            email: 'user@example.com',
            emailVerified: false,
            password: 'secret123',
            displayName: 'User',
            photoURL: 'https://example.com/photo',
            phoneNumber: '+15555550100',
            disabled: false
        });
        expect(buildUserRequest(properties, 'create')).toEqual({
            data: {
                localId: 'uid',
                email: 'user@example.com',
                emailVerified: false,
                password: 'secret123',
                displayName: 'User',
                photoUrl: 'https://example.com/photo',
                phoneNumber: '+15555550100',
                disabled: false
            },
            error: null
        });
    });
    it('supports generated UIDs and empty updates', () => {
        expect(buildUserRequest({}, 'create')).toEqual({
            data: {},
            error: null
        });
        expect(buildUserRequest({}, 'update')).toEqual({
            data: {},
            error: null
        });
    });
    it('maps update nulls, disabling, and provider unlinking', () => {
        const properties = Object.freeze({
            displayName: null,
            photoURL: null,
            phoneNumber: null,
            disabled: true,
            providersToUnlink: ['google.com']
        });
        expect(buildUserRequest(properties, 'update')).toEqual({
            data: {
                deleteAttribute: ['DISPLAY_NAME', 'PHOTO_URL'],
                deleteProvider: ['phone', 'google.com'],
                disableUser: true
            },
            error: null
        });
        expect(properties.providersToUnlink).toEqual(['google.com']);
    });
    it('preserves empty profile strings and explicit false values', () => {
        expect(
            buildUserRequest(
                {
                    displayName: '',
                    photoURL: '',
                    disabled: false,
                    emailVerified: false
                },
                'update'
            ).data
        ).toEqual({
            displayName: '',
            photoUrl: '',
            disableUser: false,
            emailVerified: false
        });
    });
    it('translates a linked provider without mutating it', () => {
        const provider = Object.freeze({
            uid: 'external',
            providerId: 'google.com',
            photoURL: 'https://example.com/photo'
        });
        const result = buildUserRequest({ providerToLink: provider }, 'update');
        expect(result.data?.linkProviderUserInfo).toMatchObject({
            rawId: 'external',
            providerId: 'google.com',
            photoUrl: provider.photoURL
        });
        expect(result.data?.linkProviderUserInfo).not.toHaveProperty('uid');
    });
    it('maps new phone MFA enrollment', () => {
        expect(
            buildUserRequest(
                {
                    multiFactor: {
                        enrolledFactors: [
                            {
                                factorId: 'phone',
                                phoneNumber: '+15555550100',
                                displayName: 'Phone'
                            }
                        ]
                    }
                },
                'create'
            ).data
        ).toEqual({
            mfaInfo: [{ phoneInfo: '+15555550100', displayName: 'Phone' }]
        });
    });
    it('maps existing MFA identifiers and UTC enrollment dates', () => {
        expect(
            buildUserRequest(
                {
                    multiFactor: {
                        enrolledFactors: [
                            {
                                factorId: 'phone',
                                phoneNumber: '+15555550100',
                                uid: 'factor',
                                enrollmentTime: 'Wed, 01 Jan 2025 00:00:00 GMT'
                            }
                        ]
                    }
                },
                'update'
            ).data
        ).toEqual({
            mfa: {
                enrollments: [
                    {
                        phoneInfo: '+15555550100',
                        mfaEnrollmentId: 'factor',
                        enrolledAt: '2025-01-01T00:00:00.000Z'
                    }
                ]
            }
        });
    });
    it.each([null, []])('clears MFA with %j', (enrolledFactors) => {
        expect(
            buildUserRequest({ multiFactor: { enrolledFactors } }, 'update')
        ).toEqual({ data: { mfa: {} }, error: null });
    });
    it('omits empty MFA on create', () => {
        expect(
            buildUserRequest({ multiFactor: { enrolledFactors: [] } }, 'create')
                .data
        ).toEqual({});
    });
    it.each([
        null,
        [],
        'invalid',
        { email: 'invalid' },
        { email: null },
        { password: 'short' },
        { disabled: 'yes' },
        { emailVerified: 1 },
        { displayName: 1 },
        { photoURL: 'invalid' },
        { phoneNumber: '555' },
        { providersToUnlink: 'google.com' },
        { providersToUnlink: [''] },
        { providerToLink: {} },
        { providerToLink: null },
        { multiFactor: null },
        { multiFactor: {} },
        { multiFactor: { enrolledFactors: [{}] } },
        {
            multiFactor: {
                enrolledFactors: [{ factorId: 'phone', phoneNumber: 'invalid' }]
            }
        },
        {
            multiFactor: {
                enrolledFactors: [
                    {
                        factorId: 'phone',
                        phoneNumber: '+15555550100',
                        enrollmentTime: 'invalid'
                    }
                ]
            }
        },
        { tenantId: 'other' },
        { customAttributes: '{}' },
        { validSince: '1' }
    ])('returns a validation error for %j', (properties) => {
        const result = buildUserRequest(properties as UpdateRequest, 'update');
        expect(result.data).toBeNull();
        expect(result.error?.code).toBe('auth/admin-api-invalid-argument');
    });
    it.each([
        { uid: '' },
        { displayName: null },
        { photoURL: null },
        { phoneNumber: null },
        { multiFactor: { enrolledFactors: null } },
        {
            multiFactor: {
                enrolledFactors: [
                    {
                        factorId: 'phone',
                        phoneNumber: '+15555550100',
                        uid: 'factor'
                    }
                ]
            }
        },
        {
            multiFactor: {
                enrolledFactors: [
                    {
                        factorId: 'phone',
                        phoneNumber: '+15555550100',
                        enrollmentTime: 'Wed, 01 Jan 2025 00:00:00 GMT'
                    }
                ]
            }
        }
    ])('rejects invalid create properties %j', (properties) => {
        expect(
            buildUserRequest(properties as CreateRequest, 'create').error
        ).toBeInstanceOf(Error);
    });
    it('does not forward raw API fields or a replacement UID during update', () => {
        expect(
            buildUserRequest(
                {
                    localId: 'other',
                    uid: 'other',
                    deleteAttribute: ['PASSWORD']
                } as UpdateRequest,
                'update'
            ).data
        ).toEqual({});
    });
});
