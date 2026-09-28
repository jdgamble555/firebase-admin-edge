import { expect, it } from 'vitest';
import {
    buildIdentityWriteRequest,
    buildIdentityMetadataRequest
} from './identity-write.js';

it('validates and serializes optional creation claims without mutating input', () => {
    for (const customClaims of [{ role: 'editor' }, {}, null, undefined]) {
        const input = { email: 'a@example.com', customClaims };
        const original = structuredClone(input);
        const { error, data } = buildIdentityWriteRequest(input, 'create');
        expect(error).toBeNull();
        expect(data).toEqual({
            email: 'a@example.com',
            ...(customClaims !== undefined && {
                customAttributes: JSON.stringify(customClaims ?? {})
            })
        });
        expect(input).toEqual(original);
    }
});

it('combines profile changes, replacement claims, and metadata without mutating input', () => {
    const input = {
        displayName: 'Sam',
        customClaims: { role: 'editor' },
        metadata: { creationTime: '2020-01-01T00:00:00Z' }
    };
    const original = structuredClone(input);
    expect(buildIdentityWriteRequest(input, 'update')).toEqual({
        error: null,
        data: {
            displayName: 'Sam',
            customAttributes: '{"role":"editor"}',
            createdAt: '1577836800000'
        }
    });
    expect(input).toEqual(original);
    expect(buildIdentityWriteRequest({ customClaims: null }, 'update')).toEqual(
        { error: null, data: { customAttributes: '{}' } }
    );
    expect(
        buildIdentityWriteRequest(
            { customClaims: undefined, metadata: undefined },
            'update'
        )
    ).toEqual({ error: null, data: {} });
    for (const input of [
        { customClaims: { sub: 'reserved' } },
        { metadata: { creationTime: 'bad' } },
        { metadata: null },
        { claims: {} }
    ]) {
        const { error, data } = buildIdentityWriteRequest(
            input as never,
            'update'
        );
        expect(error).not.toBeNull();
        expect(data).toBeNull();
    }
});

it('resets omitted or null set claims and timestamps, including partially supplied metadata', () => {
    const defaults = buildIdentityWriteRequest({}, 'set');
    expect(
        buildIdentityWriteRequest({ customClaims: null, metadata: null }, 'set')
    ).toEqual(defaults);
    expect(
        buildIdentityWriteRequest(
            { metadata: { creationTime: null, lastSignInTime: null } },
            'set'
        )
    ).toEqual(defaults);
    const { error, data } = buildIdentityWriteRequest(
        {
            customClaims: { role: 'editor' },
            metadata: { creationTime: '2020-01-01T00:00:00Z' }
        },
        'set'
    );
    expect(error).toBeNull();
    expect(data).toMatchObject({
        customAttributes: '{"role":"editor"}',
        createdAt: '1577836800000',
        lastLoginAt: '0'
    });
    for (const metadata of [
        [],
        'invalid',
        { creationTime: 'bad' },
        { lastRefreshTime: '2020-01-01' }
    ]) {
        expect(
            buildIdentityWriteRequest({ metadata } as never, 'set').error
        ).not.toBeNull();
    }
});

it('builds create requests with optional UID and native updates', () => {
    expect(
        buildIdentityWriteRequest(
            { uid: 'one', email: 'a@example.com' },
            'create'
        )
    ).toEqual({
        error: null,
        data: { localId: 'one', email: 'a@example.com' }
    });
    expect(buildIdentityWriteRequest({}, 'create')).toEqual({
        error: null,
        data: {}
    });
    expect(buildIdentityWriteRequest({ disabled: true }, 'update')).toEqual({
        error: null,
        data: { disableUser: true }
    });
    expect(buildIdentityWriteRequest({ displayName: null }, 'update')).toEqual({
        error: null,
        data: { deleteAttribute: ['DISPLAY_NAME'] }
    });
});

it('rejects invalid payloads and unsupported fields before writes', () => {
    for (const [data, operation] of [
        [null, 'update'],
        [{ password: 'bad' }, 'create'],
        [{ uid: 'different' }, 'update'],
        [{ customClaims: { sub: 'reserved' } }, 'create'],
        [{ customClaims: [] }, 'create'],
        [{ customClaims: { long: 'x'.repeat(1001) } }, 'create'],
        [{ customClaims: { sub: 'reserved' } }, 'update'],
        [{ customClaims: [] }, 'update'],
        [{ claims: {} }, 'set'],
        [{ unknown: true }, 'update']
    ] as const) {
        const { error, data: body } = buildIdentityWriteRequest(
            data as never,
            operation
        );
        expect(error).not.toBeNull();
        expect(body).toBeNull();
    }
});

it('replaces the complete profile schema while preserving credentials', () => {
    const { error, data } = buildIdentityWriteRequest(
        { displayName: 'Sam' },
        'set'
    );
    expect(error).toBeNull();
    expect(data).toEqual({
        displayName: 'Sam',
        disableUser: false,
        emailVerified: false,
        deleteAttribute: ['PHOTO_URL', 'EMAIL'],
        deleteProvider: ['phone'],
        customAttributes: '{}',
        createdAt: '0',
        lastLoginAt: '0'
    });
    expect(data).not.toHaveProperty('password');
    expect(data).not.toHaveProperty('mfa');
    const complete = buildIdentityWriteRequest(
        {
            email: 'a@example.com',
            emailVerified: true,
            disabled: true,
            displayName: 'Sam',
            photoURL: 'https://example.com/photo.jpg',
            phoneNumber: '+15555550100'
        },
        'set'
    );
    expect(complete).toEqual({
        error: null,
        data: {
            email: 'a@example.com',
            emailVerified: true,
            disableUser: true,
            displayName: 'Sam',
            photoUrl: 'https://example.com/photo.jpg',
            phoneNumber: '+15555550100',
            customAttributes: '{}',
            createdAt: '0',
            lastLoginAt: '0'
        }
    });
    const cleared = buildIdentityWriteRequest({ email: null }, 'set');
    expect(cleared.data?.deleteAttribute).toEqual([
        'DISPLAY_NAME',
        'PHOTO_URL',
        'EMAIL'
    ]);
    expect(cleared.data?.customAttributes).toBe('{}');
});

it('rejects credential fields and inconsistent replacement data', () => {
    for (const data of [
        { password: 'password' },
        { multiFactor: { enrolledFactors: [] } },
        { providersToUnlink: ['google.com'] },
        { emailVerified: true },
        { disabled: null }
    ]) {
        const { error } = buildIdentityWriteRequest(data as never, 'set');
        expect(error).not.toBeNull();
    }
});

it('treats omitted and undefined nullable set fields as explicit nulls', () => {
    const omitted = buildIdentityWriteRequest({}, 'set');
    const undefinedFields = buildIdentityWriteRequest(
        {
            email: undefined,
            displayName: undefined,
            photoURL: undefined,
            phoneNumber: undefined
        },
        'set'
    );
    const explicitNulls = buildIdentityWriteRequest(
        {
            email: null,
            displayName: null,
            photoURL: null,
            phoneNumber: null
        },
        'set'
    );
    expect(omitted).toEqual(explicitNulls);
    expect(undefinedFields).toEqual(explicitNulls);
    expect(omitted.data).toEqual({
        disableUser: false,
        emailVerified: false,
        deleteAttribute: ['DISPLAY_NAME', 'PHOTO_URL', 'EMAIL'],
        deleteProvider: ['phone'],
        customAttributes: '{}',
        createdAt: '0',
        lastLoginAt: '0'
    });
    expect(buildIdentityWriteRequest({}, 'update')).toEqual({
        error: null,
        data: {}
    });
    const invalid = buildIdentityWriteRequest(
        // @ts-expect-error Claims require a dedicated method.
        { claims: { admin: true } },
        'update'
    );
    expect(invalid.error).not.toBeNull();
});

it('clears passwords while rejecting metadata in profile writes', () => {
    expect(
        buildIdentityWriteRequest(
            { password: null, displayName: null },
            'update'
        )
    ).toEqual({
        error: null,
        data: { deleteAttribute: ['DISPLAY_NAME', 'PASSWORD'] }
    });
    expect(
        buildIdentityWriteRequest({ password: 'new-password' }, 'update').data
    ).toEqual({ password: 'new-password' });
    for (const operation of ['create'] as const) {
        expect(
            buildIdentityWriteRequest({ metadata: {} } as never, operation)
                .error
        ).not.toBeNull();
    }
});

it('serializes only supplied metadata timestamps without mutating input', () => {
    const input = {
        creationTime: '2020-01-01T00:00:00Z',
        lastSignInTime: '2024-01-01T00:00:00Z'
    };
    const original = { ...input };
    expect(buildIdentityMetadataRequest(input)).toEqual({
        error: null,
        data: { createdAt: '1577836800000', lastLoginAt: '1704067200000' }
    });
    expect(input).toEqual(original);
    expect(
        buildIdentityMetadataRequest({ creationTime: '1970-01-01T00:00:00Z' })
            .data
    ).toEqual({ createdAt: '0' });
    expect(
        buildIdentityMetadataRequest({ lastSignInTime: '2024-01-01T00:00:00Z' })
            .data
    ).toEqual({ lastLoginAt: '1704067200000' });
    expect(buildIdentityMetadataRequest({})).toEqual({ error: null, data: {} });
    for (const metadata of [
        null,
        [],
        { creationTime: 'bad' },
        { creationTime: null },
        { lastSignInTime: 42 },
        { lastRefreshTime: '2020-01-01' }
    ]) {
        expect(
            buildIdentityMetadataRequest(metadata as never).error
        ).not.toBeNull();
    }
});
