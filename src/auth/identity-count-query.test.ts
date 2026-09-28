import { beforeEach, expect, it, vi } from 'vitest';
import { IdentityCountQuery } from './identity-count-query.js';
import { FirebaseAdminAuth } from './firebase-admin-auth.js';
import type { ServiceAccount } from './firebase-types.js';

vi.mock('./firebase-admin-auth.js');
const auth = new FirebaseAdminAuth({} as ServiceAccount);
const countUsers = vi.mocked(auth._countUsers);
beforeEach(() => vi.resetAllMocks());

it('validates direct count input before requesting a total', async () => {
    for (const options of [
        null,
        { filter: { field: 'email', value: 'prefix' } },
        { filter: { field: 'disabled', value: 'false' } },
        { offset: -1 },
        { limit: 0 }
    ]) {
        const { error, data } = await new IdentityCountQuery(
            auth,
            options as never
        ).get();
        expect(error).toBeInstanceOf(Error);
        expect(data).toBeNull();
    }
    expect(countUsers).not.toHaveBeenCalled();
});

it('rejects direct OR counts without a request', async () => {
    const { error, data } = await new IdentityCountQuery(auth, {
        identifiers: [{ uid: 'one' }]
    }).get();
    expect(error).toMatchObject({ code: 'auth/invalid-argument' });
    expect(data).toBeNull();
    expect(countUsers).not.toHaveBeenCalled();
});

it('counts all matches without imposing the default fetch page size', async () => {
    countUsers.mockResolvedValue({ data: 50000, error: null });
    const { data } = await new IdentityCountQuery(auth).get();
    expect(data).toEqual({ count: 50000 });
    expect(countUsers).toHaveBeenCalledExactlyOnceWith(undefined);
    expect(auth._queryUsers).not.toHaveBeenCalled();
    expect(auth.listUsers).not.toHaveBeenCalled();
});

it.each([
    [{ offset: 20, limit: 10 }, 10],
    [{ offset: 200 }, 0],
    [{ limit: 1000 }, 100],
    [{ offset: 90, limit: 50 }, 10]
])(
    'applies explicit pagination arithmetically after the native count',
    async (options, expected) => {
        countUsers.mockResolvedValue({ data: 100, error: null });
        const { error, data } = await new IdentityCountQuery(
            auth,
            options
        ).get();
        expect(error).toBeNull();
        expect(data).toEqual({ count: expected });
        expect(countUsers).toHaveBeenCalledTimes(1);
    }
);

it('forwards only the count-compatible filter', async () => {
    countUsers.mockResolvedValue({ data: 1, error: null });
    const { data } = await new IdentityCountQuery(auth, {
        filter: { field: 'uid', value: 'a' },
        orderBy: { field: 'createdAt', direction: 'desc' },
        limit: 10
    }).get();
    expect(data).toEqual({ count: 1 });
    expect(countUsers).toHaveBeenCalledExactlyOnceWith({
        field: 'uid',
        value: 'a'
    });
});

it('rejects opaque page tokens without requesting a count', async () => {
    const { error, data } = await new IdentityCountQuery(
        auth,
        {},
        'token'
    ).get();
    expect(error).toMatchObject({ code: 'auth/invalid-argument' });
    expect(data).toBeNull();
    expect(countUsers).not.toHaveBeenCalled();
});

it('preserves returned and thrown failures without retrying', async () => {
    const failure = new Error('count failed');
    countUsers.mockResolvedValueOnce({ data: null, error: failure });
    const { error, data } = await new IdentityCountQuery(auth).get();
    expect(error).toBe(failure);
    expect(data).toBeNull();
    countUsers.mockRejectedValueOnce(failure);
    const { error: thrown } = await new IdentityCountQuery(auth).get();
    expect(thrown).toBe(failure);
    expect(countUsers).toHaveBeenCalledTimes(2);
});

it('rejects initial-email counts without downloading users', async () => {
    const query = new IdentityCountQuery(auth, {
        filter: { field: 'initialEmail', value: 'old@example.com' }
    });
    const { error, data } = await query.get();
    expect(error).toMatchObject({ code: 'auth/invalid-argument' });
    expect(data).toBeNull();
    expect(countUsers).not.toHaveBeenCalled();
    expect(auth.getUsers).not.toHaveBeenCalled();
});

it('rejects in counts without requesting account data', async () => {
    const { error, data } = await new IdentityCountQuery(auth, {
        filter: { field: 'uid', operator: 'in', value: ['one', 'two'] }
    }).get();
    expect(error).toMatchObject({ code: 'auth/invalid-argument' });
    expect(data).toBeNull();
    expect(countUsers).not.toHaveBeenCalled();
    expect(auth.getUsers).not.toHaveBeenCalled();
});

it('rejects provider batch counts before I/O', async () => {
    const { error, data } = await new IdentityCountQuery(auth, {
        filter: {
            field: 'provider',
            operator: 'in',
            value: [{ providerId: 'google.com', providerUid: 'external' }]
        }
    }).get();
    expect(error).toMatchObject({ code: 'auth/invalid-argument' });
    expect(data).toBeNull();
    expect(countUsers).not.toHaveBeenCalled();
    expect(auth.getUsers).not.toHaveBeenCalled();
});
