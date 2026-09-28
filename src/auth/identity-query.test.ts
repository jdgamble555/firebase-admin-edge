import { beforeEach, expect, it, vi } from 'vitest';
import { FirebaseAdminAuth } from './firebase-admin-auth.js';
import { executeIdentityQuery } from './identity-query.js';
import type { IdentityQueryOptions } from './identity-types.js';
import type { ServiceAccount } from './firebase-types.js';
import type { UserRecord } from './user-record.js';

vi.mock('./firebase-admin-auth.js');
const auth = new FirebaseAdminAuth({} as ServiceAccount);
const queryUsers = vi.mocked(auth._queryUsers);
const listUsers = vi.mocked(auth.listUsers);
const getUsers = vi.mocked(auth.getUsers);
const a = {
    uid: 'a',
    email: 'Alice@example.com',
    phoneNumber: '+15555550123',
    disabled: false,
    metadata: { creationTime: '2020-01-01', lastSignInTime: '2022-01-01' }
} as UserRecord;
const b = {
    ...a,
    uid: 'b',
    disabled: true,
    metadata: { creationTime: '2021-01-01', lastSignInTime: '2021-01-01' }
} as UserRecord;
beforeEach(() => vi.resetAllMocks());

it('validates direct query input before requesting accounts', async () => {
    for (const options of [
        { filter: { field: 'email', value: 'prefix' } },
        { filter: { field: 'disabled', value: 'false' } },
        { offset: -1 },
        { limit: 0 },
        { orderBy: { field: 'uid', direction: 'up' } }
    ]) {
        const operation = executeIdentityQuery(
            auth,
            options as IdentityQueryOptions
        );
        await expect(operation).rejects.toThrow();
    }
    const invalidToken = executeIdentityQuery(auth, {}, false, '');
    await expect(invalidToken).rejects.toThrow();
    const invalidLast = executeIdentityQuery(auth, {}, 'yes' as never);
    await expect(invalidLast).rejects.toThrow();
    expect(queryUsers).not.toHaveBeenCalled();
    expect(listUsers).not.toHaveBeenCalled();
    expect(getUsers).not.toHaveBeenCalled();
});

it('rejects direct OR options combined with native query options', async () => {
    for (const options of [
        { limit: 1 },
        { offset: 0 },
        { orderBy: { field: 'uid', direction: 'asc' } },
        { filter: { field: 'uid', value: 'one' } }
    ]) {
        const operation = executeIdentityQuery(auth, {
            ...options,
            identifiers: [{ uid: 'one' }]
        } as IdentityQueryOptions);
        await expect(operation).rejects.toThrow();
    }
    for (const [last, token] of [
        [true, undefined],
        [false, 'token']
    ] as const) {
        const operation = executeIdentityQuery(
            auth,
            { identifiers: [{ uid: 'one' }] },
            last,
            token
        );
        await expect(operation).rejects.toThrow();
    }
    expect(getUsers).not.toHaveBeenCalled();
    expect(queryUsers).not.toHaveBeenCalled();
});

it.each([501, 1000])(
    'supports listing %s users without another page request',
    async (limit) => {
        listUsers.mockResolvedValue({
            data: { users: [], pageToken: 'next' },
            error: null
        });
        const { error } = await executeIdentityQuery(
            auth,
            { limit },
            false,
            'previous'
        );
        expect(error).toBeNull();
        expect(listUsers).toHaveBeenCalledExactlyOnceWith(limit, 'previous');
        expect(queryUsers).not.toHaveBeenCalled();
    }
);

it.each([
    { offset: 1, limit: 501 },
    { filter: { field: 'uid', value: 'a' }, limit: 501 },
    { orderBy: { field: 'uid', direction: 'desc' }, limit: 1000 },
    { limit: 1001 }
] as const)(
    'rejects endpoint-specific limits before requests',
    async (options) => {
        const operation = executeIdentityQuery(auth, options);
        await expect(operation).rejects.toMatchObject({
            code: 'auth/invalid-argument'
        });
        expect(listUsers).not.toHaveBeenCalled();
        expect(queryUsers).not.toHaveBeenCalled();
    }
);

it('accepts the query endpoint maximum of 500', async () => {
    queryUsers.mockResolvedValue({ data: [], error: null });
    await executeIdentityQuery(auth, {
        limit: 500,
        filter: { field: 'phoneNumber', value: '+15555550123' }
    });
    expect(queryUsers).toHaveBeenCalledTimes(1);
    expect(getUsers).not.toHaveBeenCalled();
});

it.each(['query', 'batch'])('does not retry %s failures', async (mode) => {
    const failure = new Error('failed');
    queryUsers.mockResolvedValue({ data: null, error: failure });
    listUsers.mockResolvedValue({ data: null, error: failure as never });
    const { error } = await executeIdentityQuery(
        auth,
        mode === 'query' ? { offset: 1 } : {}
    );
    expect(error).toBe(failure);
    expect(queryUsers.mock.calls.length + listUsers.mock.calls.length).toBe(1);
});

it('returns a full native page without probing the next page', async () => {
    queryUsers.mockResolvedValue({ data: [a, b], error: null });
    const { data } = await executeIdentityQuery(auth, {
        orderBy: { field: 'createdAt', direction: 'desc' },
        offset: 20,
        limit: 2
    });
    expect(data).toEqual({
        users: [a, b],
        nextOffset: 22,
        nextPageToken: null
    });
    expect(queryUsers).toHaveBeenCalledTimes(1);
    expect(listUsers).not.toHaveBeenCalled();
    expect(getUsers).not.toHaveBeenCalled();
});

it('returns the backend token without following it, even for empty pages', async () => {
    listUsers.mockResolvedValue({
        data: { users: [], pageToken: 'next' },
        error: null
    });
    const { data } = await executeIdentityQuery(
        auth,
        { limit: 2 },
        false,
        'previous'
    );
    expect(data).toEqual({
        users: [],
        nextOffset: null,
        nextPageToken: 'next'
    });
    expect(listUsers).toHaveBeenCalledExactlyOnceWith(2, 'previous');
    expect(queryUsers).not.toHaveBeenCalled();
});

it('uses native offset instead of walking batch pages', async () => {
    queryUsers.mockResolvedValue({ data: [], error: null });
    await executeIdentityQuery(auth, { offset: 2000, limit: 10 });
    expect(queryUsers).toHaveBeenCalledExactlyOnceWith({
        offset: 2000,
        limit: 10,
        orderBy: { field: 'uid', direction: 'asc' }
    });
    expect(listUsers).not.toHaveBeenCalled();
});

it.each([0, 1, 3])(
    'implements last-limit with offset %s by reversing one native request',
    async (offset) => {
        queryUsers.mockResolvedValue({ data: [b, a], error: null });
        const { data } = await executeIdentityQuery(
            auth,
            { limit: 2, offset, orderBy: { field: 'uid', direction: 'asc' } },
            true
        );
        expect(queryUsers).toHaveBeenCalledExactlyOnceWith({
            offset: 0,
            limit: 2 + offset,
            orderBy: { field: 'uid', direction: 'desc' }
        });
        expect(data).toEqual({
            users: offset === 0 ? [a, b] : offset === 1 ? [b] : [],
            nextOffset: null,
            nextPageToken: null
        });
    }
);

it('reverses descending queries for last-limit', async () => {
    queryUsers.mockResolvedValue({ data: [a, b], error: null });
    const { data } = await executeIdentityQuery(
        auth,
        { limit: 2, orderBy: { field: 'createdAt', direction: 'desc' } },
        true
    );
    expect(queryUsers).toHaveBeenCalledExactlyOnceWith({
        offset: 0,
        limit: 2,
        orderBy: { field: 'createdAt', direction: 'asc' }
    });
    expect(data?.users).toEqual([b, a]);
});

it.each([
    [{ offset: 1 }, false, 'token'],
    [{ filter: { field: 'uid', value: 'a' } }, false, 'token'],
    [{ orderBy: { field: 'uid', direction: 'desc' } }, false, 'token'],
    [{}, true, 'token'],
    [{ offset: 1, limit: 500 }, true, undefined]
] as const)(
    'rejects unsupported combinations before any request',
    async (options, last, token) => {
        const operation = executeIdentityQuery(
            auth,
            options as IdentityQueryOptions,
            last,
            token
        );
        await expect(operation).rejects.toMatchObject({
            code: 'auth/invalid-argument'
        });
        expect(queryUsers).not.toHaveBeenCalled();
        expect(listUsers).not.toHaveBeenCalled();
        expect(getUsers).not.toHaveBeenCalled();
    }
);

it('returns all initial-email matches with one lookup and forwards lookup errors', async () => {
    const options = {
        filter: { field: 'initialEmail' as const, value: 'old@example.com' }
    };
    getUsers.mockResolvedValueOnce({
        error: null,
        data: { users: [a, b], notFound: [] }
    });
    const result = await executeIdentityQuery(auth, options);
    expect(result).toEqual({
        error: null,
        data: { users: [a, b], nextOffset: null, nextPageToken: null }
    });
    expect(getUsers).toHaveBeenCalledExactlyOnceWith([
        { initialEmail: 'old@example.com' }
    ]);
    const error = new Error('failed');
    getUsers.mockResolvedValueOnce({ error: error as never, data: null });
    const failed = await executeIdentityQuery(auth, options);
    expect(failed).toEqual({ error, data: null });
    expect(queryUsers).not.toHaveBeenCalled();
    expect(listUsers).not.toHaveBeenCalled();
});

it('rejects initial-email query modifiers before any request', async () => {
    const filter = { field: 'initialEmail' as const, value: 'old@example.com' };
    for (const options of [
        { orderBy: { field: 'uid' as const, direction: 'asc' as const } },
        { offset: 0 },
        { limit: 1 }
    ]) {
        await expect(
            executeIdentityQuery(auth, { filter, ...options })
        ).rejects.toThrow('do not support');
    }
    await expect(executeIdentityQuery(auth, { filter }, true)).rejects.toThrow(
        'do not support'
    );
    await expect(
        executeIdentityQuery(auth, { filter }, false, 'token')
    ).rejects.toThrow('do not support');
    expect(getUsers).not.toHaveBeenCalled();
});

it('keeps in batches in one request, including the 100-identifier boundary', async () => {
    const filter = {
        field: 'uid' as const,
        operator: 'in' as const,
        value: Array.from({ length: 100 }, (_, index) => String(index))
    };
    getUsers.mockResolvedValueOnce({
        error: null,
        data: { users: [], notFound: [] }
    });
    const { error, data } = await executeIdentityQuery(auth, { filter });
    expect(error).toBeNull();
    expect(data?.users).toEqual([]);
    expect(getUsers).toHaveBeenCalledExactlyOnceWith(
        filter.value.map((uid) => ({ uid }))
    );
    for (const options of [
        { limit: 1 },
        { offset: 0 },
        { orderBy: { field: 'uid' as const, direction: 'asc' as const } }
    ]) {
        await expect(
            executeIdentityQuery(auth, { filter, ...options })
        ).rejects.toThrow();
    }
    await expect(
        executeIdentityQuery(auth, { filter }, true)
    ).rejects.toThrow();
    await expect(
        executeIdentityQuery(auth, { filter }, false, 'token')
    ).rejects.toThrow();
    await expect(
        executeIdentityQuery(auth, { filter: { ...filter, value: [] } })
    ).rejects.toThrow();
    const failure = new Error('failed');
    getUsers.mockRejectedValueOnce(failure);
    await expect(executeIdentityQuery(auth, { filter })).rejects.toBe(failure);
    expect(getUsers).toHaveBeenCalledTimes(2);
});

it('executes provider batches through lookup and preserves empty and error responses', async () => {
    const pairs = [{ providerId: 'google.com', providerUid: 'external' }];
    const filter = {
        field: 'provider' as const,
        operator: 'in' as const,
        value: pairs
    };
    getUsers.mockResolvedValueOnce({
        error: null,
        data: { users: [], notFound: pairs }
    });
    const empty = await executeIdentityQuery(auth, { filter });
    expect(empty).toEqual({
        error: null,
        data: { users: [], nextOffset: null, nextPageToken: null }
    });
    expect(getUsers).toHaveBeenCalledExactlyOnceWith(pairs);
    const error = new Error('lookup failed');
    getUsers.mockResolvedValueOnce({ error: error as never, data: null });
    const failed = await executeIdentityQuery(auth, { filter });
    expect(failed).toEqual({ error, data: null });
    expect(getUsers).toHaveBeenCalledTimes(2);
    expect(queryUsers).not.toHaveBeenCalled();
    expect(listUsers).not.toHaveBeenCalled();
});
