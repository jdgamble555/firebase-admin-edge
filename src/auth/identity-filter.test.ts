import { expect, it } from 'vitest';
import {
    identityLookupIdentifiers,
    identityOrIdentifiers,
    validateIdentityQueryOptions
} from './identity-filter.js';
import type { IdentityFilterField } from './identity-types.js';

it('validates all supported query shapes without excluding endpoint capabilities', () => {
    for (const options of [
        {},
        { filter: { field: 'uid', value: 'one' } },
        {
            filter: {
                field: 'email',
                operator: '==',
                value: 'User@example.com'
            }
        },
        { filter: { field: 'phoneNumber', value: '+15555550100' } },
        { filter: { field: 'initialEmail', value: 'old@example.com' } },
        {
            filter: {
                field: 'provider',
                operator: 'in',
                value: [{ providerId: 'oidc.example', providerUid: 'external' }]
            }
        },
        { identifiers: [{ uid: 'one' }, { email: 'a@example.com' }] },
        { offset: Number.MAX_SAFE_INTEGER, limit: 1000 }
    ]) {
        expect(() =>
            validateIdentityQueryOptions(options as never)
        ).not.toThrow();
    }
    for (const field of [
        'uid',
        'email',
        'displayName',
        'createdAt',
        'lastLoginAt'
    ]) {
        for (const direction of ['asc', 'desc']) {
            expect(() =>
                validateIdentityQueryOptions({
                    orderBy: { field, direction }
                } as never)
            ).not.toThrow();
        }
    }
});

it('rejects malformed and unrecognized direct query options', () => {
    for (const options of [
        null,
        [],
        { expression: [] },
        { filter: null },
        { filter: [] },
        { filter: { field: 'disabled', value: 'false' } },
        { filter: { field: 'uid', operator: '!=', value: 'one' } },
        { filter: { field: 'email', value: 'prefix' } },
        { filter: { field: 'phoneNumber', value: 'invalid' } },
        { filter: { field: 'uid', value: 'x'.repeat(129) } },
        { filter: { field: 'provider', value: 'google.com' } },
        { filter: { field: 'uid', value: 'one', and: [] } },
        {
            filter: { field: 'uid', value: 'one' },
            identifiers: [{ uid: 'two' }]
        },
        { orderBy: null },
        { orderBy: [] },
        { orderBy: { field: 'disabled', direction: 'asc' } },
        { orderBy: { field: 'uid', direction: 'up' } },
        { orderBy: { field: 'uid', direction: 'asc', extra: true } },
        { offset: -1 },
        { offset: 0.5 },
        { offset: Infinity },
        { limit: 0 },
        { limit: 1001 },
        { limit: 1.5 }
    ]) {
        expect(() => validateIdentityQueryOptions(options as never)).toThrow();
    }
});

it('snapshots mixed OR identifiers and rejects unsupported conjunctions', () => {
    const uid = { uid: 'one' };
    const provider = { providerId: 'google.com', providerUid: 'external' };
    const identifiers = [uid, { email: 'one@example.com' }, provider];
    const copy = identityOrIdentifiers(identifiers);
    expect(copy).toEqual(identifiers);
    uid.uid = 'changed';
    provider.providerUid = 'changed';
    expect(copy[0]).toEqual({ uid: 'one' });
    expect(copy[2]).toEqual({
        providerId: 'google.com',
        providerUid: 'external'
    });
    expect(identityOrIdentifiers(Array(100).fill({ uid: 'one' }))).toHaveLength(
        100
    );
    for (const invalid of [
        null,
        [],
        Array(101).fill({ uid: 'one' }),
        [null],
        [{}],
        [{ uid: '' }],
        [{ email: 'invalid' }],
        [{ disabled: true }],
        [{ providerId: 'google.com' }],
        [{ uid: 'one', email: 'one@example.com' }],
        [{ providerId: 'google.com', providerUid: 'one', uid: 'one' }]
    ]) {
        expect(() => identityOrIdentifiers(invalid as never)).toThrow();
    }
});

it.each([
    ['uid', ['one', 'two']],
    ['email', ['one@example.com', 'two@example.com']],
    ['phoneNumber', ['+15555550100', '+15555550101']],
    ['initialEmail', ['old@example.com']]
] as const)(
    'maps %s identifiers without changing their values',
    (field, values) => {
        expect(identityLookupIdentifiers(field, values)).toEqual(
            values.map((value) => ({ [field]: value }))
        );
    }
);

it('enforces one batch of 1 through 100 valid identifiers', () => {
    expect(
        identityLookupIdentifiers('uid', Array(100).fill('uid'))
    ).toHaveLength(100);
    for (const values of [
        [],
        Array(101).fill('uid'),
        [''],
        [42],
        new Array(2),
        null,
        'uid'
    ]) {
        expect(() =>
            identityLookupIdentifiers('uid', values as readonly string[])
        ).toThrow();
    }
    expect(() =>
        identityLookupIdentifiers('disabled' as IdentityFilterField, ['false'])
    ).toThrow();
    expect(() => identityLookupIdentifiers('email', ['invalid'])).toThrow();
    expect(() =>
        identityLookupIdentifiers('phoneNumber', ['invalid'])
    ).toThrow();
    expect(() =>
        identityLookupIdentifiers('initialEmail', ['invalid'])
    ).toThrow();
});

it('validates provider pairs and copies only the provider identity fields', () => {
    const pair = {
        providerId: 'google.com',
        providerUid: 'external',
        uid: 'unrelated'
    };
    expect(identityLookupIdentifiers('provider', [pair])).toEqual([
        { providerId: 'google.com', providerUid: 'external' }
    ]);
    expect(
        identityLookupIdentifiers('provider', Array(100).fill(pair))
    ).toHaveLength(100);
    for (const value of [
        null,
        'google.com',
        {},
        { uid: 'uid' },
        { providerId: 'google.com' },
        { providerId: '', providerUid: 'external' },
        { providerId: 'google.com', providerUid: 42 }
    ]) {
        expect(() =>
            identityLookupIdentifiers('provider', [value] as never)
        ).toThrow();
    }
    expect(() => identityLookupIdentifiers('provider', [])).toThrow();
    expect(() =>
        identityLookupIdentifiers('provider', Array(101).fill(pair))
    ).toThrow();
});
