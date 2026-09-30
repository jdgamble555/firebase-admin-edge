import { beforeEach, expect, expectTypeOf, it, vi } from 'vitest';
import {
    Identity,
    IdentityQuery,
    IdentityCountQuery,
    type IdentityFilterField,
    type IdentityOrderField
} from './identity.js';
import { FirebaseAdminAuth } from './firebase-admin-auth.js';
import type { ServiceAccount } from './firebase-types.js';
import { createUserRecord } from './user-record.js';
import { ProjectConfigManager } from './project-config-manager.js';
import { TenantManager } from './tenant-manager.js';
import { FirebaseEdgeError } from './errors.js';

vi.mock('./firebase-admin-auth.js');
const account = { project_id: 'project' } as ServiceAccount;
const queryUsers = vi.mocked(FirebaseAdminAuth.prototype._queryUsers);
const listUsers = vi.mocked(FirebaseAdminAuth.prototype.listUsers);
const getUsers = vi.mocked(FirebaseAdminAuth.prototype.getUsers);

it('reads parent project configuration through identity.config.get()', async () => {
    const execute = vi.fn().mockResolvedValue({
        error: null,
        data: { passwordPolicyConfig: { enforcementState: 'ENFORCE' } }
    });
    const manager = new ProjectConfigManager(execute);
    vi.mocked(FirebaseAdminAuth.prototype.projectConfigManager).mockReturnValue(
        manager
    );
    const identity = new Identity(account, { tenantId: 'tenant' });

    expect(execute).not.toHaveBeenCalled();
    const { error, data } = await identity.config.get();
    expect(error).toBeNull();
    expect(data).toEqual({
        passwordPolicyConfig: { enforcementState: 'ENFORCE' }
    });
    expect(execute).toHaveBeenCalledExactlyOnceWith({
        resource: 'project',
        action: 'get'
    });
});

it('reads single tenant pages with explicit pagination', async () => {
    const execute = vi.fn().mockResolvedValue({
        error: null,
        data: { tenants: [{ tenantId: 'one' }], pageToken: 'next' }
    });
    const manager = new TenantManager(execute, vi.fn());
    vi.mocked(FirebaseAdminAuth.prototype.tenantManager).mockReturnValue(
        manager
    );
    const identity = new Identity(account, { tenantId: 'tenant' });

    expect(execute).not.toHaveBeenCalled();
    const first = await identity.tenants.limit(1000).get();
    expect(first).toEqual({
        error: null,
        data: { tenants: [{ tenantId: 'one' }], pageToken: 'next' }
    });
    expect(execute).toHaveBeenLastCalledWith({
        resource: 'tenant',
        action: 'list',
        maxResults: 1000,
        pageToken: undefined
    });

    execute.mockResolvedValueOnce({ error: null, data: { tenants: [] } });
    const last = await identity.tenants.limit(25).pageToken('next').get();
    expect(last).toEqual({ error: null, data: { tenants: [] } });
    expect(execute).toHaveBeenLastCalledWith({
        resource: 'tenant',
        action: 'list',
        maxResults: 25,
        pageToken: 'next'
    });
    execute.mockClear();
    await identity.tenants.pageToken('next').get();
    expect(execute).toHaveBeenCalledExactlyOnceWith({
        resource: 'tenant',
        action: 'list',
        maxResults: 1000,
        pageToken: 'next'
    });
});

it('collects all tenants across pages, including empty intermediate pages', async () => {
    const execute = vi
        .fn()
        .mockResolvedValueOnce({
            error: null,
            data: { tenants: [{ tenantId: 'one' }], pageToken: 'a' }
        })
        .mockResolvedValueOnce({
            error: null,
            data: { tenants: [], pageToken: 'b' }
        })
        .mockResolvedValueOnce({
            error: null,
            data: { tenants: [{ tenantId: 'two' }] }
        });
    vi.mocked(FirebaseAdminAuth.prototype.tenantManager).mockReturnValue(
        new TenantManager(execute, vi.fn())
    );
    const identity = new Identity(account);
    const result = await identity.tenants.get();
    expect(result).toEqual({
        error: null,
        data: { tenants: [{ tenantId: 'one' }, { tenantId: 'two' }] }
    });
    for (const [index, pageToken] of [undefined, 'a', 'b'].entries()) {
        expect(execute).toHaveBeenNthCalledWith(index + 1, {
            resource: 'tenant',
            action: 'list',
            maxResults: 1000,
            pageToken
        });
    }
    expect(execute).toHaveBeenCalledTimes(3);
    execute.mockResolvedValue({ error: null, data: { tenants: [] } });
    const empty = await identity.tenants.get();
    expect(empty).toEqual({ error: null, data: { tenants: [] } });
});

it('discards partial tenants on later-page errors and stops repeated tokens', async () => {
    const error = new FirebaseEdgeError({
        code: 'auth/internal-error',
        message: 'Failed page'
    });
    const execute = vi
        .fn()
        .mockResolvedValueOnce({
            error: null,
            data: { tenants: [{ tenantId: 'one' }], pageToken: 'a' }
        })
        .mockResolvedValueOnce({ error, data: null });
    vi.mocked(FirebaseAdminAuth.prototype.tenantManager).mockReturnValue(
        new TenantManager(execute, vi.fn())
    );
    const identity = new Identity(account);
    const failed = await identity.tenants.get();
    expect(failed).toEqual({ error, data: null });
    execute.mockClear().mockResolvedValue({
        error: null,
        data: { tenants: [], pageToken: 'same' }
    });
    const repeated = await identity.tenants.get();
    expect(repeated).toMatchObject({
        data: null,
        error: { code: 'auth/internal-error' }
    });
    expect(execute).toHaveBeenCalledTimes(2);
});

it('keeps tenant query branches immutable and replaces pagination settings', async () => {
    const execute = vi
        .fn()
        .mockResolvedValue({ error: null, data: { tenants: [] } });
    vi.mocked(FirebaseAdminAuth.prototype.tenantManager).mockReturnValue(
        new TenantManager(execute, vi.fn())
    );
    const identity = new Identity(account);
    const base = identity.tenants;
    const limited = base.limit(10);
    const paged = limited.pageToken('first');
    const replaced = paged.pageToken('second').limit(20);

    expect(execute).not.toHaveBeenCalled();
    expect(base).not.toHaveProperty('offset');
    for (const [query, maxResults, pageToken] of [
        [replaced, 20, 'second'],
        [paged, 10, 'first'],
        [limited, 10, undefined],
        [base, 1000, undefined],
        [base.pageToken('next').limit(1), 1, 'next']
    ] as const) {
        await query.get();
        expect(execute).toHaveBeenLastCalledWith({
            resource: 'tenant',
            action: 'list',
            maxResults,
            pageToken
        });
    }
});

it.each([0, -1, 1001, 1.5, NaN, Infinity, undefined, null, '10'])(
    'rejects invalid tenant limits before requesting tenants: %s',
    (value) => {
        const identity = new Identity(account);
        expect(() => identity.tenants.limit(value as number)).toThrow(
            'Tenant limit'
        );
        expect(
            FirebaseAdminAuth.prototype.tenantManager
        ).not.toHaveBeenCalled();
    }
);

it.each(['', undefined, null, 123])(
    'rejects invalid tenant page tokens before requesting tenants: %s',
    (value) => {
        const identity = new Identity(account);
        expect(() => identity.tenants.pageToken(value as string)).toThrow(
            'pageToken'
        );
        expect(
            FirebaseAdminAuth.prototype.tenantManager
        ).not.toHaveBeenCalled();
    }
);

it('preserves configuration and tenant errors from the existing managers', async () => {
    const error = new FirebaseEdgeError({
        code: 'auth/invalid-argument',
        message: 'Invalid request.'
    });
    const execute = vi.fn().mockResolvedValue({ error, data: null });
    vi.mocked(FirebaseAdminAuth.prototype.projectConfigManager).mockReturnValue(
        new ProjectConfigManager(execute)
    );
    vi.mocked(FirebaseAdminAuth.prototype.tenantManager).mockReturnValue(
        new TenantManager(execute, vi.fn())
    );
    const identity = new Identity(account);

    const config = await identity.config.get();
    const tenants = await identity.tenants.get();
    expect(config).toEqual({ error, data: null });
    expect(tenants).toEqual({ error, data: null });
    expect(execute).toHaveBeenLastCalledWith({
        resource: 'tenant',
        action: 'list',
        maxResults: 1000,
        pageToken: undefined
    });
});

it('exposes provider discovery on identity.providers.get()', async () => {
    const identity = new Identity(account, { tenantId: 'tenant' });
    vi.mocked(FirebaseAdminAuth.prototype._getProviders).mockResolvedValue({
        data: [],
        error: null
    });
    const result = await identity.providers.get();
    expect(result).toEqual({ data: [], error: null });
    expect(FirebaseAdminAuth.prototype._getProviders).toHaveBeenCalledOnce();
});

interface TestClaims {
    role: 'viewer' | 'editor';
    subscribed: boolean;
    quota?: number | null;
}

it('carries a claims schema through references, reads, queries, and writes', async () => {
    const identity = new Identity<TestClaims>(account);
    const user = identity.users().byUid('one');
    getUsers.mockResolvedValue({
        error: null,
        data: {
            users: [
                createUserRecord({
                    localId: 'one',
                    customAttributes: '{"role":"editor"}'
                })
            ],
            notFound: []
        }
    });
    const { error, data } = await user.claims.byKey('role').get();
    if (!error) {
        expectTypeOf(data).toEqualTypeOf<'viewer' | 'editor' | undefined>();
        expect(data).toBe('editor');
    }
    const { error: claimsError, data: claims } = await user.claims.get();
    if (!claimsError) {
        expectTypeOf(claims).toEqualTypeOf<Partial<TestClaims>>();
    }
    const { error: userError, data: record } = await user.get();
    if (!userError && record) {
        expectTypeOf(record.customClaims).toEqualTypeOf<
            Partial<TestClaims> | undefined
        >();
    }
    const builders = [
        identity.users().limit(2),
        identity.users().orderBy('email').offset(1).limitToLast(1),
        identity.users().where('uid', '==', 'one'),
        identity.users().where('uid', 'in', ['one']),
        identity.users().or('uid', '==', 'one'),
        identity.users().pageToken('token')
    ];
    for (const builder of builders) {
        type Result = NonNullable<
            Awaited<ReturnType<typeof builder.get>>['data']
        >;
        expectTypeOf<Result['users'][number]['customClaims']>().toEqualTypeOf<
            Partial<TestClaims> | undefined
        >();
    }
    const scoped = new Identity(account).users<TestClaims>().byUid('one');
    const specific = new Identity(account).users().byUid<TestClaims>('one');
    expectTypeOf(scoped).toEqualTypeOf<typeof user>();
    expectTypeOf(specific).toEqualTypeOf<typeof user>();
    if (false) {
        identity.users().add({ customClaims: { role: 'editor' } });
        // @ts-expect-error Creation claims follow the schema.
        identity.users().add({ customClaims: { role: 'admin' } });
        user.claims.set({ role: 'editor' });
        user.claims.update({ subscribed: true });
        user.claims.byKey('quota').set(null);
        user.claims.byKey('role').update('viewer');
        user.update({ customClaims: { role: 'editor' } });
        user.set({ customClaims: { subscribed: false } });
        // @ts-expect-error Unknown schema key.
        user.claims.byKey('typo');
        // @ts-expect-error Wrong value for this key.
        user.claims.byKey('role').set(true);
        // @ts-expect-error Null is allowed only by nullable schema fields.
        user.claims.byKey('role').update(null);
        // @ts-expect-error Deletion uses delete(), not undefined.
        user.claims.byKey('quota').set(undefined);
        // @ts-expect-error Claims patch values follow the schema.
        user.claims.update({ subscribed: 'yes' });
        // @ts-expect-error Whole claims replacement follows the schema.
        user.claims.set({ role: 'admin' });
        // @ts-expect-error Combined writes follow the same schema.
        user.update({ customClaims: { role: 42 } });
        // @ts-expect-error Replacement writes follow the same schema.
        user.set({ customClaims: { typo: true } });
        identity.users().import([
            // @ts-expect-error Typed imports follow the same schema.
            { uid: 'one', customClaims: { role: 'admin' } }
        ]);
    }
});

beforeEach(() => {
    vi.resetAllMocks();
    queryUsers.mockResolvedValue({ data: [], error: null });
    listUsers.mockResolvedValue({ data: { users: [] }, error: null });
    getUsers.mockResolvedValue({
        data: { users: [], notFound: [] },
        error: null
    });
});

it('looks up an OR of mixed identifiers in one request without mutating the base', async () => {
    const base = new Identity(account).users();
    const provider = { providerId: 'google.com', providerUid: 'external' };
    const first = base.or('uid', '==', 'one');
    const query = first
        .or('email', '==', 'one@example.com')
        .or('phoneNumber', '==', '+15555550100')
        .or('initialEmail', '==', 'old@example.com')
        .or('provider', '==', provider);
    provider.providerUid = 'changed';
    const { error, data } = await query.get();
    expect(error).toBeNull();
    expect(data).toEqual({ users: [], nextOffset: null, nextPageToken: null });
    expect(getUsers).toHaveBeenCalledExactlyOnceWith([
        { uid: 'one' },
        { email: 'one@example.com' },
        { phoneNumber: '+15555550100' },
        { initialEmail: 'old@example.com' },
        { providerId: 'google.com', providerUid: 'external' }
    ]);
    expect(queryUsers).not.toHaveBeenCalled();
    await base.get();
    expect(listUsers).toHaveBeenCalledOnce();
    expectTypeOf(query).not.toHaveProperty('count');
    expectTypeOf(query).not.toHaveProperty('where');
    expectTypeOf(query).toHaveProperty('or');
    expectTypeOf(query).not.toHaveProperty('delete');
    expectTypeOf(query).not.toHaveProperty('and');
    await first.get();
    expect(getUsers).toHaveBeenLastCalledWith([{ uid: 'one' }]);
});

it('rejects OR modifiers and invalid branches before I/O', () => {
    const base = new IdentityQuery(new FirebaseAdminAuth(account));
    const query = base.or('uid', '==', 'one') as unknown as IdentityQuery;
    for (const action of [
        // @ts-expect-error A clause requires field, operator, and value.
        () => base.or(),
        () => {
            // @ts-expect-error OR branches cannot contain an implicit AND.
            return base.or({ uid: 'one', email: 'a@example.com' });
        },
        () => query.where('uid', '==', 'two'),
        () => query.count(),
        () => query.limit(1),
        () => query.orderBy('uid'),
        () => query.offset(0),
        () => query.pageToken('token'),
        () => query.byUid('two'),
        () => query.delete(),
        () => (base.limit(1) as unknown as IdentityQuery).or('uid', '==', 'one')
    ]) {
        expect(action).toThrow();
    }
    expect(getUsers).not.toHaveBeenCalled();
    expect(queryUsers).not.toHaveBeenCalled();
    expect(listUsers).not.toHaveBeenCalled();
});

it('returns OR lookup errors without fallback', async () => {
    const failure = new Error('lookup failed');
    getUsers.mockResolvedValue({ error: failure, data: null });
    const { error, data } = await new Identity(account)
        .users()
        .or('uid', '==', 'one')
        .get();
    expect(error).toBe(failure);
    expect(data).toBeNull();
    expect(getUsers).toHaveBeenCalledOnce();
    expect(listUsers).not.toHaveBeenCalled();
    expect(queryUsers).not.toHaveBeenCalled();
});

it('appends in clauses immutably and enforces a shared 100-identifier budget', async () => {
    const values = ['one', 'two'];
    const providers = [{ providerId: 'google.com', providerUid: 'external' }];
    const base = new Identity(account).users().or('uid', 'in', values);
    const query = base
        .or('provider', 'in', providers)
        .or('email', 'in', ['a@example.com']);
    values[0] = 'changed';
    providers[0]!.providerUid = 'changed';
    await query.get();
    expect(getUsers).toHaveBeenLastCalledWith([
        { uid: 'one' },
        { uid: 'two' },
        { providerId: 'google.com', providerUid: 'external' },
        { email: 'a@example.com' }
    ]);
    await base.get();
    expect(getUsers).toHaveBeenLastCalledWith([{ uid: 'one' }, { uid: 'two' }]);
    const full = base.or('uid', 'in', Array(98).fill('another'));
    await full.get();
    expect(getUsers.mock.lastCall?.[0]).toHaveLength(100);
    expect(() => full.or('email', '==', 'b@example.com')).toThrow();
    expect(() => base.or('uid', 'in', Array(99).fill('another'))).toThrow();
});

it('rejects mixing OR and where in either order at compile time and runtime', () => {
    const users = new Identity(account).users();
    const alternatives = users.or('uid', '==', 'one');
    // @ts-expect-error OR and where cannot be combined.
    expect(() => alternatives.where('email', '==', 'a@example.com')).toThrow();
    for (const query of [
        users.where('uid', '==', 'one'),
        users.where('uid', 'in', ['one']),
        users.where('initialEmail', '==', 'a@example.com'),
        users.limit(1),
        users.offset(0),
        users.orderBy('uid'),
        users.pageToken('token')
    ]) {
        // @ts-expect-error OR requires a fresh builder or an existing OR query.
        expect(() => query.or('email', '==', 'a@example.com')).toThrow();
    }
    expectTypeOf(alternatives).not.toHaveProperty('limit');
    expectTypeOf(alternatives).not.toHaveProperty('orderBy');
    expectTypeOf(alternatives).not.toHaveProperty('pageToken');
    expectTypeOf(alternatives).not.toHaveProperty('add');
    expectTypeOf(alternatives).not.toHaveProperty('import');
    expect(getUsers).not.toHaveBeenCalled();
});

it('rejects unsupported OR fields, operators, and values', () => {
    const users = new Identity(account).users();
    // @ts-expect-error Use phoneNumber, not phone.
    expect(() => users.or('phone', '==', '+15555550100')).toThrow();
    // @ts-expect-error Unsupported operator.
    expect(() => users.or('email', '!=', 'a@example.com')).toThrow();
    // @ts-expect-error Equality requires a string, not an array.
    expect(() => users.or('email', '==', ['a@example.com'])).toThrow();
    // @ts-expect-error in requires an array.
    expect(() => users.or('uid', 'in', 'one')).toThrow();
    expect(() =>
        // @ts-expect-error Provider equality requires a complete pair.
        users.or('provider', '==', { providerId: 'google.com' })
    ).toThrow();
    // @ts-expect-error Provider in requires pairs.
    expect(() => users.or('provider', 'in', ['google.com'])).toThrow();
    expect(() => users.or('uid', 'in', [])).toThrow();
    expect(() => users.or('uid', 'in', Array(101).fill('one'))).toThrow();
    expect(() => users.or('email', '==', 'invalid')).toThrow();
    expect(() => users.or('phoneNumber', '==', 'invalid')).toThrow();
    expect(() => users.or('initialEmail', '==', 'invalid')).toThrow();
    expect(getUsers).not.toHaveBeenCalled();
});

it.each([
    ['email', 'prefix'],
    ['email', ''],
    ['phoneNumber', 'invalid'],
    ['initialEmail', 'prefix'],
    ['uid', 'x'.repeat(129)]
] as const)('rejects invalid %s equality values before I/O', (field, value) => {
    expect(() =>
        new Identity(account).users().where(field, '==', value)
    ).toThrow();
    expect(getUsers).not.toHaveBeenCalled();
    expect(queryUsers).not.toHaveBeenCalled();
});

it('rejects chained where clauses rather than silently ignoring the second', () => {
    const query = new Identity(account).users().where('uid', '==', 'one');
    // @ts-expect-error The backend does not combine multiple conditions.
    expect(() => query.where('email', '==', 'a@example.com')).toThrow(
        'ignores additional'
    );
    expect(queryUsers).not.toHaveBeenCalled();
});

it('forwards client configuration and creates independent queries', () => {
    const options = {
        tenantId: 'tenant',
        emulatorHost: null,
        fetch: vi.fn(),
        cacheName: 'cache'
    };
    const identity = new Identity(account, options);
    expect(FirebaseAdminAuth).toHaveBeenCalledWith(account, options);
    expect(identity.users()).toBeInstanceOf(IdentityQuery);
    expect(identity.users()).not.toBe(identity.users());
});

it('supports native count without downloading users or mutating the base query', async () => {
    const countUsers = vi.mocked(FirebaseAdminAuth.prototype._countUsers);
    countUsers.mockResolvedValue({ data: 30, error: null });
    const query = new Identity(account)
        .users()
        .where('email', '==', 'a@example.com');
    const count = query.offset(5).limit(10).count();
    expect(count).toBeInstanceOf(IdentityCountQuery);
    const { error, data } = await count.get();
    expect(error).toBeNull();
    expect(data).toEqual({ count: 10 });
    expect(countUsers).toHaveBeenCalledExactlyOnceWith({
        field: 'email',
        value: 'a@example.com'
    });
    expect(queryUsers).not.toHaveBeenCalled();
    expect(listUsers).not.toHaveBeenCalled();
    expect(getUsers).not.toHaveBeenCalled();
    await query.get();
    expect(queryUsers).toHaveBeenLastCalledWith({
        filter: { field: 'email', value: 'a@example.com' },
        orderBy: { field: 'uid', direction: 'asc' }
    });
});

it('allows 1000 only for token listings regardless of builder order', async () => {
    const base = new Identity(account).users().limit(1000);
    const { error } = await base.get();
    expect(error).toBeNull();
    expect(listUsers).toHaveBeenCalledExactlyOnceWith(1000, undefined);
    const { error: sortedError } = await base.orderBy('createdAt').get();
    const { error: filteredError } = await base.where('uid', '==', 'a').get();
    const { error: offsetError } = await base.offset(1).get();
    expect(sortedError).toMatchObject({ code: 'auth/invalid-argument' });
    expect(filteredError).toMatchObject({ code: 'auth/invalid-argument' });
    expect(offsetError).toMatchObject({ code: 'auth/invalid-argument' });
    expect(queryUsers).not.toHaveBeenCalled();
    expect(() => base.limitToLast(501)).toThrow();
});

it('rejects locally combined filters that cannot use the same server count', () => {
    const base = new Identity(account)
        .users()
        .where('email', '==', 'a@example.com');
    // @ts-expect-error A query supports only one filter.
    expect(() => base.where('uid', '==', 'a')).toThrow();
    // @ts-expect-error A query supports only one filter.
    expect(() => base.where('email', '==', 'a@example.com')).toThrow();
});

it('keeps query branches immutable and sends native order, offset and limit in one call', async () => {
    const base = new Identity(account).users();
    await base
        .where('email', '==', 'a@example.com')
        .orderBy('createdAt', 'desc')
        .offset(20)
        .limit(10)
        .get();
    expect(queryUsers).toHaveBeenCalledExactlyOnceWith({
        filter: { field: 'email', value: 'a@example.com' },
        orderBy: { field: 'createdAt', direction: 'desc' },
        offset: 20,
        limit: 10
    });
    await base.get();
    expect(listUsers).toHaveBeenCalledExactlyOnceWith(500, undefined);
});

it('lets limit and limitToLast replace each other', async () => {
    const base = new Identity(account).users().orderBy('createdAt');
    await base.limit(10).limitToLast(2).get();
    expect(queryUsers).toHaveBeenLastCalledWith({
        orderBy: { field: 'createdAt', direction: 'desc' },
        offset: 0,
        limit: 2
    });
    await base.limitToLast(2).limit(10).get();
    expect(queryUsers).toHaveBeenLastCalledWith({
        orderBy: { field: 'createdAt', direction: 'asc' },
        limit: 10
    });
});

it('preserves page tokens across builder methods without following the next token', async () => {
    listUsers.mockResolvedValue({
        data: { users: [], pageToken: 'next' },
        error: null
    });
    const base = new Identity(account).users();
    const { data } = await base
        .pageToken('previous')
        .orderBy('uid')
        .offset(0)
        .limit(10)
        .get();
    expect(listUsers).toHaveBeenCalledExactlyOnceWith(10, 'previous');
    expect(data).toEqual({
        users: [],
        nextOffset: null,
        nextPageToken: 'next'
    });
    await base.get();
    expect(listUsers).toHaveBeenLastCalledWith(500, undefined);
});

it('rejects disabled filters at compile time and runtime, even with an identifier', () => {
    const query = new Identity(account).users();
    // @ts-expect-error Disabled is not a supported filter field.
    expect(() => query.where('disabled', '==', false)).toThrow();
    const identified = query.where('uid', '==', 'a');
    // @ts-expect-error Disabled is not a supported filter field.
    expect(() => identified.where('disabled', '==', true)).toThrow();
    expect(getUsers).not.toHaveBeenCalled();
    expect(queryUsers).not.toHaveBeenCalled();
    expect(listUsers).not.toHaveBeenCalled();
});

it('returns thrown failures without another endpoint attempt', async () => {
    const failure = new Error('network');
    listUsers.mockRejectedValue(failure);
    const { error, data } = await new Identity(account).users().get();
    expect(error).toBe(failure);
    expect(data).toBeNull();
    expect(listUsers).toHaveBeenCalledTimes(1);
    expect(queryUsers).not.toHaveBeenCalled();
    expect(getUsers).not.toHaveBeenCalled();
});

it.each([-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(
    'rejects offset %s',
    (value) => {
        expect(() => new Identity(account).users().offset(value)).toThrow();
    }
);
it.each([0, -1, 1001, 1.5, NaN, Infinity])('rejects limit %s', (value) => {
    expect(() => new Identity(account).users().limit(value)).toThrow();
    expect(() => new Identity(account).users().limitToLast(value)).toThrow();
});

it('keeps closed field unions and removes unsupported cursor methods', () => {
    expectTypeOf<IdentityFilterField>().toEqualTypeOf<
        'uid' | 'email' | 'phoneNumber' | 'initialEmail' | 'provider'
    >();
    expectTypeOf<IdentityOrderField>().toEqualTypeOf<
        'uid' | 'email' | 'displayName' | 'createdAt' | 'lastLoginAt'
    >();
    const query = new Identity(account).users();
    for (const field of [
        'uid',
        'email',
        'displayName',
        'createdAt',
        'lastLoginAt'
    ] as const) {
        expectTypeOf(query.orderBy(field).get).toEqualTypeOf<
            IdentityQuery['get']
        >();
    }
    // @ts-expect-error Arbitrary user cursors require scans and are no longer exposed.
    expect(query.startAt).toBeUndefined();
    // @ts-expect-error Arbitrary user cursors require scans and are no longer exposed.
    expect(query.startAfter).toBeUndefined();
    // @ts-expect-error End cursors require scans and are no longer exposed.
    expect(query.endAt).toBeUndefined();
    // @ts-expect-error End cursors require scans and are no longer exposed.
    expect(query.endBefore).toBeUndefined();
    // @ts-expect-error Unsupported field.
    expect(() => query.where('customClaims.role', '==', 'admin')).toThrow();
    // @ts-expect-error Unsupported field.
    expect(() => query.orderBy('disabled')).toThrow();
    // @ts-expect-error Wrong value type.
    expect(() => query.where('disabled', '==', 'false')).toThrow();
    // @ts-expect-error Wrong operator.
    expect(() => query.where('email', '!=', 'a')).toThrow();
    // @ts-expect-error Wrong direction.
    expect(() => query.orderBy('uid', 'up')).toThrow();
    expect(() => query.where('email', '==', '')).toThrow();
    // @ts-expect-error Only one sort is supported.
    expect(() => query.orderBy('uid').orderBy('email')).toThrow();
    expect(() => query.pageToken('')).toThrow();
    // @ts-expect-error Wrong token type.
    expect(() => query.pageToken(3)).toThrow();
});

it('creates exact lookups with the appropriate result types', async () => {
    const users = new Identity(account).users();
    const uid = await users.byUid('uid').get();
    expect(uid).toEqual({ error: null, data: null });
    expect(getUsers).toHaveBeenLastCalledWith([{ uid: 'uid' }]);
    const provider = await users.byProvider('google.com', 'external').get();
    expect(provider).toEqual({ error: null, data: null });
    expect(getUsers).toHaveBeenLastCalledWith([
        { providerId: 'google.com', providerUid: 'external' }
    ]);
    expect(getUsers).toHaveBeenCalledTimes(2);
    expectTypeOf(uid.data).toEqualTypeOf<
        import('./identity-reference.js').IdentityUserRecord | null
    >();
    expectTypeOf(provider.data).toEqualTypeOf<
        import('./identity-reference.js').IdentityUserRecord | null
    >();
    expect(users.byUid('uid')).not.toHaveProperty('count');
    expect(users).not.toHaveProperty('byInitialEmail');
});

it('rejects exact lookups after any query modifier', () => {
    const users = new Identity(account).users();
    const queries = [
        users.where('uid', '==', 'uid'),
        users.orderBy('uid'),
        users.offset(0),
        users.limit(1),
        users.limitToLast(1),
        users.pageToken('token')
    ];
    for (const query of queries) {
        // @ts-expect-error Exact lookups require a fresh builder.
        expect(() => query.byUid('uid')).toThrow('cannot be combined');
        // @ts-expect-error Exact lookups require a fresh builder.
        expect(() => query.byEmail('user@example.com')).toThrow(
            'cannot be combined'
        );
        // @ts-expect-error Exact lookups require a fresh builder.
        expect(() => query.byPhoneNumber('+15555550100')).toThrow(
            'cannot be combined'
        );

        // @ts-expect-error Exact lookups require a fresh builder.
        expect(() => query.byProvider('google.com', 'external')).toThrow(
            'cannot be combined'
        );
    }
    expect(() => users.byUid('')).toThrow();
    expect(() => users.byProvider('google.com', '')).toThrow();
    expect(getUsers).not.toHaveBeenCalled();
});

it('executes an initial-email filter with a query result and rejects counting', async () => {
    const query = new Identity(account)
        .users()
        .where('initialEmail', '==', 'old@example.com');
    const { error, data } = await query.get();
    expect(error).toBeNull();
    expect(data).toEqual({ users: [], nextOffset: null, nextPageToken: null });
    expect(getUsers).toHaveBeenCalledExactlyOnceWith([
        { initialEmail: 'old@example.com' }
    ]);
    // @ts-expect-error Initial email does not support counting.
    expect(() => query.count()).toThrow('support only get');
    expect(FirebaseAdminAuth.prototype._countUsers).not.toHaveBeenCalled();
});

it('rejects initial-email modifiers in either chaining order at compile time and runtime', () => {
    const users = new Identity(account).users();
    const lookup = users.where('initialEmail', '==', 'old@example.com');
    // @ts-expect-error Lookup endpoint cannot sort.
    expect(() => lookup.orderBy('uid')).toThrow();
    // @ts-expect-error Lookup endpoint cannot paginate.
    expect(() => lookup.offset(0)).toThrow();
    // @ts-expect-error Lookup endpoint cannot limit.
    expect(() => lookup.limit(1)).toThrow();
    // @ts-expect-error Lookup endpoint cannot limit from the end.
    expect(() => lookup.limitToLast(1)).toThrow();
    // @ts-expect-error Lookup endpoint has no page tokens.
    expect(() => lookup.pageToken('token')).toThrow();
    // @ts-expect-error Only one filter is allowed.
    expect(() => lookup.where('email', '==', 'other@example.com')).toThrow();
    expect(() => {
        // @ts-expect-error Initial email cannot follow a sort.
        users.orderBy('uid').where('initialEmail', '==', 'old@example.com');
    }).toThrow();
    expect(() => {
        // @ts-expect-error Initial email cannot follow a limit.
        users.limit(1).where('initialEmail', '==', 'old@example.com');
    }).toThrow();
    expect(() => {
        // @ts-expect-error Initial email cannot follow an offset.
        users.offset(0).where('initialEmail', '==', 'old@example.com');
    }).toThrow();
    expect(() => {
        // @ts-expect-error Initial email cannot follow a last limit.
        users.limitToLast(1).where('initialEmail', '==', 'old@example.com');
    }).toThrow();
    expect(getUsers).not.toHaveBeenCalled();
});

it('keeps endpoint restrictions through subsequent builder methods', () => {
    const users = new Identity(account).users();
    const native = users
        .where('email', '==', 'a@example.com')
        .limit(10)
        .offset(0);
    // @ts-expect-error Modifiers must not restore filter availability.
    expect(() => native.where('uid', '==', 'a')).toThrow();
    // @ts-expect-error Query endpoint does not accept tokens.
    expect(() => native.pageToken('token')).toThrow();
    const sorted = users.orderBy('createdAt').limit(10);
    // @ts-expect-error Modifiers must not restore sort availability.
    expect(() => sorted.orderBy('uid')).toThrow();
    // @ts-expect-error This ordering cannot use batchGet tokens.
    expect(() => sorted.pageToken('token')).toThrow();
    // @ts-expect-error A nonzero offset cannot use batchGet tokens.
    expect(() => users.offset(1).limit(10).pageToken('token')).toThrow();
    // @ts-expect-error Last queries cannot use batchGet tokens.
    expect(() => users.limitToLast(1).pageToken('token')).toThrow();
    const token = users.pageToken('token').limit(10);
    // @ts-expect-error Tokens cannot be combined with filters.
    expect(() => token.where('uid', '==', 'a')).toThrow();
    // @ts-expect-error Tokens cannot be counted.
    expect(() => token.count()).toThrow();
    // @ts-expect-error Tokens require UID ascending sort.
    expect(() => token.orderBy('email')).toThrow();
    // @ts-expect-error Tokens require UID ascending sort.
    expect(() => token.orderBy('uid', 'desc')).toThrow();
    // @ts-expect-error Tokens cannot use nonzero offsets.
    expect(() => token.offset(1)).toThrow();
    // @ts-expect-error Tokens cannot use last limits.
    expect(() => token.limitToLast(1)).toThrow();
    expect(getUsers).not.toHaveBeenCalled();
    expect(queryUsers).not.toHaveBeenCalled();
    expect(listUsers).not.toHaveBeenCalled();
});

it('preserves valid native filters after modifiers and listing options before tokens', async () => {
    const users = new Identity(account).users();
    await users
        .orderBy('createdAt')
        .offset(2)
        .limit(10)
        .where('phoneNumber', '==', '+15555550100')
        .get();
    expect(queryUsers).toHaveBeenCalledExactlyOnceWith({
        filter: { field: 'phoneNumber', value: '+15555550100' },
        orderBy: { field: 'createdAt', direction: 'asc' },
        offset: 2,
        limit: 10
    });
    await users
        .orderBy('uid', 'asc')
        .offset(0)
        .limit(1000)
        .pageToken('previous')
        .get();
    expect(listUsers).toHaveBeenCalledExactlyOnceWith(1000, 'previous');
});

it.each([
    ['byEmail', 'user@example.com', { email: 'user@example.com' }],
    ['byPhoneNumber', '+15555550100', { phoneNumber: '+15555550100' }]
] as const)(
    'looks up one user with %s and preserves missing/error results',
    async (method, value, identifier) => {
        const base = new Identity(account).users();
        const user = createUserRecord({
            localId: 'uid',
            email: 'user@example.com',
            phoneNumber: '+15555550100'
        });
        getUsers.mockResolvedValueOnce({
            error: null,
            data: { users: [user], notFound: [] }
        });
        const lookup = base[method](value);
        const { error, data } = await lookup.get();
        expect(error).toBeNull();
        expect(data).toBe(user);
        expectTypeOf(data).toEqualTypeOf<
            import('./identity-reference.js').IdentityUserRecord | null
        >();
        expect(getUsers).toHaveBeenCalledExactlyOnceWith([identifier]);
        const missing = await lookup.get();
        expect(missing).toEqual({ error: null, data: null });
        const failure = new Error('network');
        getUsers.mockRejectedValueOnce(failure);
        const failed = await lookup.get();
        expect(failed).toEqual({ error: failure, data: null });
        expect(getUsers).toHaveBeenCalledTimes(3);
        expect(lookup).not.toHaveProperty('where');
        expect(lookup).not.toHaveProperty('count');
        expect(lookup).not.toHaveProperty('orderBy');
        await base.get();
        expect(listUsers).toHaveBeenCalledExactlyOnceWith(500, undefined);
        expect(queryUsers).not.toHaveBeenCalled();
    }
);

it('validates email and phone lookup identifiers before I/O', () => {
    const users = new Identity(account).users();
    for (const email of ['', 'invalid', 'a'.repeat(250) + '@example.com']) {
        expect(() => users.byEmail(email)).toThrow();
    }
    for (const phone of ['', 'invalid', '15555550100']) {
        expect(() => users.byPhoneNumber(phone)).toThrow();
    }
    // @ts-expect-error Email identifiers must be strings.
    expect(() => users.byEmail(123)).toThrow();
    // @ts-expect-error Phone identifiers must be strings.
    expect(() => users.byPhoneNumber(123)).toThrow();
    const lookup = users.where('initialEmail', '==', 'old@example.com');
    // @ts-expect-error An existing initial-email filter cannot become an exact lookup.
    expect(() => lookup.byEmail('user@example.com')).toThrow();
    // @ts-expect-error An existing initial-email filter cannot become an exact lookup.
    expect(() => lookup.byPhoneNumber('+15555550100')).toThrow();
    expect(getUsers).not.toHaveBeenCalled();
});

it.each([
    ['uid', ['one', 'two']],
    ['email', ['one@example.com', 'two@example.com']],
    ['phoneNumber', ['+15555550100', '+15555550101']],
    ['initialEmail', ['old@example.com', 'older@example.com']]
] as const)('supports one in lookup for %s', async (field, values) => {
    const user = createUserRecord({ localId: 'one' });
    getUsers.mockResolvedValueOnce({
        error: null,
        data: { users: [user], notFound: [] }
    });
    const input = [...values];
    const query = new Identity(account).users().where(field, 'in', input);
    input.splice(0);
    const { error, data } = await query.get();
    expect(error).toBeNull();
    expect(data).toEqual({
        users: [user],
        nextOffset: null,
        nextPageToken: null
    });
    expect(getUsers).toHaveBeenCalledExactlyOnceWith(
        values.map((value) => ({ [field]: value }))
    );
    expect(queryUsers).not.toHaveBeenCalled();
    expect(listUsers).not.toHaveBeenCalled();
});

it('requires an in array and rejects unsupported chaining in either order', () => {
    const users = new Identity(account).users();
    // @ts-expect-error in requires an array.
    expect(() => users.where('uid', 'in', 'one')).toThrow();
    // @ts-expect-error == requires one string.
    expect(() => users.where('uid', '==', ['one'])).toThrow();
    // @ts-expect-error in requires string members.
    expect(() => users.where('uid', 'in', [42])).toThrow();
    expect(() => users.where('uid', 'in', [])).toThrow();
    expect(() => users.where('uid', 'in', Array(101).fill('uid'))).toThrow();
    const lookup = users.where('uid', 'in', ['one']);
    // @ts-expect-error Batch lookups cannot count.
    expect(() => lookup.count()).toThrow();
    // @ts-expect-error Batch lookups cannot sort.
    expect(() => lookup.orderBy('uid')).toThrow();
    // @ts-expect-error Batch lookups cannot limit.
    expect(() => lookup.limit(1)).toThrow();
    // @ts-expect-error Batch lookups cannot use last limits.
    expect(() => lookup.limitToLast(1)).toThrow();
    // @ts-expect-error Batch lookups cannot use offsets.
    expect(() => lookup.offset(0)).toThrow();
    // @ts-expect-error Batch lookups cannot use tokens.
    expect(() => lookup.pageToken('token')).toThrow();
    // @ts-expect-error Batch lookups cannot add filters.
    expect(() => lookup.where('uid', '==', 'one')).toThrow();
    const modified = [
        users.limit(1),
        users.offset(0),
        users.orderBy('uid'),
        users.limitToLast(1)
    ];
    for (const query of modified) {
        // @ts-expect-error in cannot follow query modifiers.
        expect(() => query.where('uid', 'in', ['one'])).toThrow();
    }
    expect(() => {
        // @ts-expect-error Tokens cannot filter.
        users.pageToken('token').where('uid', 'in', ['one']);
    }).toThrow();
    expect(getUsers).not.toHaveBeenCalled();
});

it('looks up multiple provider identities in one request and snapshots the pairs', async () => {
    const pairs = [
        { providerId: 'google.com', providerUid: 'google-user' },
        { providerId: 'github.com', providerUid: 'github-user' }
    ];
    const original = structuredClone(pairs);
    const user = createUserRecord({ localId: 'one' });
    getUsers.mockResolvedValueOnce({
        error: null,
        data: { users: [user], notFound: [] }
    });
    const query = new Identity(account).users().where('provider', 'in', pairs);
    pairs[0]!.providerUid = 'changed';
    pairs.pop();
    const { error, data } = await query.get();
    expect(error).toBeNull();
    expect(data).toEqual({
        users: [user],
        nextOffset: null,
        nextPageToken: null
    });
    expect(getUsers).toHaveBeenCalledExactlyOnceWith(original);
    expect(queryUsers).not.toHaveBeenCalled();
    expect(listUsers).not.toHaveBeenCalled();
});

it('requires provider pairs and prohibits non-lookup operations for provider batches', () => {
    const users = new Identity(account).users();
    const pairs = [
        { providerId: 'google.com', providerUid: 'external' }
    ] as const;
    const query = users.where('provider', 'in', pairs);
    // @ts-expect-error Provider filters accept only in, not ==.
    expect(() => users.where('provider', '==', 'google.com')).toThrow();
    // @ts-expect-error Provider filters require pairs, not strings.
    expect(() => users.where('provider', 'in', ['google.com'])).toThrow();
    expect(() => {
        // @ts-expect-error Both providerId and providerUid are required.
        users.where('provider', 'in', [{ providerId: 'google.com' }]);
    }).toThrow();
    // @ts-expect-error String identifier fields cannot accept provider pairs.
    expect(() => users.where('uid', 'in', pairs)).toThrow();
    expect(() => users.where('provider', 'in', [])).toThrow();
    expect(() =>
        users.where('provider', 'in', Array(101).fill(pairs[0]))
    ).toThrow();
    // @ts-expect-error Provider batch lookups cannot count.
    expect(() => query.count()).toThrow();
    // @ts-expect-error Provider batch lookups cannot sort.
    expect(() => query.orderBy('uid')).toThrow();
    // @ts-expect-error Provider batch lookups cannot limit.
    expect(() => query.limit(1)).toThrow();
    // @ts-expect-error Provider batch lookups cannot paginate.
    expect(() => query.offset(0)).toThrow();
    // @ts-expect-error Provider batch lookups cannot use tokens.
    expect(() => query.pageToken('token')).toThrow();
    // @ts-expect-error Provider batch lookups cannot add filters.
    expect(() => query.where('uid', '==', 'one')).toThrow();
    expect(() => {
        // @ts-expect-error Provider filters cannot follow query modifiers.
        users.orderBy('uid').where('provider', 'in', pairs);
    }).toThrow();
    expect(getUsers).not.toHaveBeenCalled();
});

it('adds users and imports through a fresh collection builder', async () => {
    const users = new Identity(account).users();
    const write = vi.mocked(FirebaseAdminAuth.prototype._writeIdentityUser);
    write.mockResolvedValue({ error: null, data: { uid: 'created' } });
    const added = await users.add({
        email: 'a@example.com',
        customClaims: { role: 'editor' }
    });
    expect(added).toEqual({ error: null, data: { uid: 'created' } });
    expect(write).toHaveBeenLastCalledWith(undefined, {
        email: 'a@example.com',
        customClaims: { role: 'editor' }
    });
    await users.add({ uid: 'chosen', displayName: 'Name' });
    expect(write).toHaveBeenLastCalledWith(undefined, {
        uid: 'chosen',
        displayName: 'Name'
    });
    const importer = vi.mocked(FirebaseAdminAuth.prototype.importUsers);
    const result = { successCount: 1, failureCount: 0, errors: [] };
    importer.mockResolvedValue({ error: null, data: result });
    const records = [{ uid: 'imported' }];
    const imported = await users.import(records);
    expect(imported).toEqual({ error: null, data: result });
    expect(importer).toHaveBeenCalledExactlyOnceWith(records, undefined);
    const filtered = users.where('uid', '==', 'one');
    // @ts-expect-error add is only available on a fresh collection builder.
    expect(() => filtered.add({})).toThrow();
    // @ts-expect-error import is only available on a fresh collection builder.
    expect(() => filtered.import(records)).toThrow();
});

it('deletes only explicit UID batches, without reading users', async () => {
    const users = new Identity(account).users();
    const remove = vi.mocked(FirebaseAdminAuth.prototype.deleteUsers);
    const result = { successCount: 2, failureCount: 0, errors: [] };
    remove.mockResolvedValue({ error: null, data: result });
    const { error, data } = await users
        .where('uid', 'in', ['one', 'two'])
        .delete();
    expect(error).toBeNull();
    expect(data).toEqual(result);
    expect(remove).toHaveBeenCalledExactlyOnceWith(['one', 'two']);
    // @ts-expect-error Deletion requires a UID in filter.
    expect(() => users.delete()).toThrow();
    const filtered = users.where('email', 'in', ['a@example.com']);
    // @ts-expect-error Only explicit UID batches support delete.
    expect(() => filtered.delete()).toThrow();
    const singleFilter = users.where('uid', '==', 'one');
    // @ts-expect-error Single deletion uses byUid.
    expect(() => singleFilter.delete()).toThrow();
    expect(getUsers).not.toHaveBeenCalled();
});

it('maps customClaims in imports without changing caller records and rejects the old name', async () => {
    const importer = vi.mocked(FirebaseAdminAuth.prototype.importUsers);
    importer.mockResolvedValue({
        error: null,
        data: { successCount: 2, failureCount: 0, errors: [] }
    });
    const users = new Identity(account).users();
    const records = [
        { uid: 'one', customClaims: { admin: true } },
        { uid: 'two', customClaims: null }
    ];
    const original = structuredClone(records);
    const options = { allowOverwrite: true, sanityCheck: true };
    await users.import(records, options);
    expect(importer).toHaveBeenCalledExactlyOnceWith(
        [
            { uid: 'one', customClaims: { admin: true } },
            { uid: 'two', customClaims: {} }
        ],
        options
    );
    expect(records).toEqual(original);
    expect(() => {
        // @ts-expect-error Identity imports no longer accept claims.
        users.import([{ uid: 'one', claims: { admin: true } }]);
    }).toThrow('Use customClaims');
    // @ts-expect-error Imports require arrays.
    expect(() => users.import(null)).toThrow();
    const malformed = [null, []] as never;
    await users.import(malformed);
    expect(importer).toHaveBeenLastCalledWith(malformed, undefined);
});
