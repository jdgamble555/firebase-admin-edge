import { createUserRecord } from './user-record.js';
import { expect, expectTypeOf, it, vi } from 'vitest';
import { IdentityReference } from './identity-reference.js';
import { FirebaseAdminAuth } from './firebase-admin-auth.js';
import type { ServiceAccount } from './firebase-types.js';

it('defaults to a single read-only lookup and snapshots named options', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const read = vi.spyOn(auth, 'getUsers').mockResolvedValue({
        error: null,
        data: { users: [], notFound: [] }
    });
    const lookup = new IdentityReference(auth, { uid: 'missing' });
    const options = { multiple: true as const };
    const matches = new IdentityReference(
        auth,
        { initialEmail: 'old@example.com' },
        options
    );
    Object.assign(options, { multiple: false });
    expect(read).not.toHaveBeenCalled();

    const single = await lookup.get();
    const multiple = await matches.get();
    expect(single).toEqual({ error: null, data: null });
    expect(multiple).toEqual({ error: null, data: [] });
    expectTypeOf(multiple.data).toEqualTypeOf<
        import('./identity-reference.js').IdentityUserRecord[] | null
    >();
    // @ts-expect-error Default lookups do not enable UID mutations.
    expect(() => lookup.delete()).toThrow();
});

it('rejects positional booleans and invalid lookup options before I/O', () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const read = vi.spyOn(auth, 'getUsers');
    for (const options of [
        false,
        true,
        null,
        [],
        { multiple: 'true' },
        { uidReference: 1 }
    ]) {
        expect(
            () => new IdentityReference(auth, { uid: 'one' }, options as never)
        ).toThrow();
    }
    expect(read).not.toHaveBeenCalled();
});

it('checks existence for each single-user identifier and preserves lookup failures', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const read = vi.spyOn(auth, 'getUsers');
    for (const identifier of [
        { uid: 'one' },
        { email: 'a@example.com' },
        { phoneNumber: '+15555550123' },
        { providerId: 'google.com', providerUid: 'one' }
    ]) {
        const lookup = new IdentityReference(auth, identifier);
        read.mockResolvedValueOnce({
            error: null,
            data: {
                users: [createUserRecord({ localId: 'one' })],
                notFound: []
            }
        });
        const found = await lookup.exists();
        expect(found).toEqual({ error: null, data: true });
        if (!found.error) {
            expectTypeOf(found.data).toEqualTypeOf<boolean>();
        }
        expect(read).toHaveBeenLastCalledWith([identifier]);
        read.mockResolvedValueOnce({
            error: null,
            data: { users: [], notFound: [identifier] }
        });
        const missing = await lookup.exists();
        expect(missing).toEqual({ error: null, data: false });
        const failure = new Error('lookup failed');
        read.mockResolvedValueOnce({ error: failure, data: null });
        const denied = await lookup.exists();
        expect(denied).toEqual({ error: failure, data: null });
        read.mockRejectedValueOnce(failure);
        const thrown = await lookup.exists();
        expect(thrown).toEqual({ error: failure, data: null });
    }
    expect(read).toHaveBeenCalledTimes(16);
    const multiple = new IdentityReference(
        auth,
        { email: 'a@example.com' },
        { multiple: true }
    );
    // @ts-expect-error Existence checks require a single-user lookup.
    const invalid = await multiple.exists();
    expect(invalid.error).toBeInstanceOf(Error);
    expect(read).toHaveBeenCalledTimes(16);
});

it('returns the same UID result for every single-user write and preserves failures', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    vi.spyOn(auth, 'getUsers').mockResolvedValue({
        error: null,
        data: { users: [createUserRecord({ localId: 'one' })], notFound: [] }
    });
    vi.spyOn(auth, '_writeIdentityUser').mockResolvedValue({
        error: null,
        data: { uid: 'one' }
    });
    const claims = vi
        .spyOn(auth, 'setCustomUserClaims')
        .mockResolvedValue({ error: null, data: undefined });
    const remove = vi
        .spyOn(auth, 'deleteUser')
        .mockResolvedValue({ error: null, data: undefined });
    const revoke = vi
        .spyOn(auth, 'revokeRefreshTokens')
        .mockResolvedValue({ error: null, data: { localId: 'one' } });
    const user = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    );
    const operations = [
        () => user.update({}),
        () => user.set({}),
        () => user.delete(),
        () => user.metadata.update({}),
        () => user.metadata.revokeTokens(),
        () => user.claims.set({}),
        () => user.claims.update({}),
        () => user.claims.delete(),
        () => user.claims.byKey('role').set('editor'),
        () => user.claims.byKey('role').update('viewer'),
        () => user.claims.byKey('role').delete()
    ];
    for (const operation of operations) {
        const { error, data } = await operation();
        expect(error).toBeNull();
        expect(data).toEqual({ uid: 'one' });
        if (!error) {
            expectTypeOf(data).toEqualTypeOf<{ uid: string }>();
        }
    }
    const failure = new Error('failed');
    for (const [mock, operation] of [
        [claims, () => user.claims.set({})],
        [remove, () => user.delete()],
        [revoke, () => user.metadata.revokeTokens()]
    ] as const) {
        mock.mockResolvedValueOnce({ error: failure, data: null });
        const denied = await operation();
        expect(denied).toEqual({ error: failure, data: null });
        mock.mockRejectedValueOnce(failure);
        const thrown = await operation();
        expect(thrown).toEqual({ error: failure, data: null });
    }
});

it('sets new or existing claim keys without replacing unrelated claims', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const user = createUserRecord({
        localId: 'one',
        customAttributes: '{"role":"viewer","retained":true}'
    });
    const read = vi.spyOn(auth, 'getUsers').mockResolvedValue({
        error: null,
        data: { users: [user], notFound: [] }
    });
    const write = vi
        .spyOn(auth, 'setCustomUserClaims')
        .mockResolvedValue({ error: null, data: undefined });
    const claims = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    ).claims;
    const result = await claims.byKey('role').set('editor');
    expect(result).toEqual({ error: null, data: { uid: 'one' } });
    expect(read).toHaveBeenCalledExactlyOnceWith([{ uid: 'one' }]);
    expect(write).toHaveBeenCalledExactlyOnceWith('one', {
        role: 'editor',
        retained: true
    });
    await claims.byKey('new-key').set(null);
    expect(write).toHaveBeenLastCalledWith('one', {
        role: 'viewer',
        retained: true,
        'new-key': null
    });
    expect(user.customClaims).toEqual({ role: 'viewer', retained: true });
    const invalid = await claims.byKey('role').set(undefined);
    expect(invalid.error).toBeInstanceOf(Error);
    expect(read).toHaveBeenCalledTimes(2);
    expect(write).toHaveBeenCalledTimes(2);
    const failure = new Error('read failed');
    read.mockResolvedValueOnce({ error: failure, data: null });
    const failed = await claims.byKey('role').set('editor');
    expect(failed).toEqual({ error: failure, data: null });
    expect(write).toHaveBeenCalledTimes(2);
});

it('reads a literal claim key in one lookup, preserving null and falsy values', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const values = {
        role: 'editor',
        'some.key': { nested: true },
        nullable: null,
        enabled: false,
        count: 0,
        empty: ''
    };
    const user = createUserRecord({
        localId: 'one',
        customAttributes: JSON.stringify(values)
    });
    const read = vi.spyOn(auth, 'getUsers').mockResolvedValue({
        error: null,
        data: { users: [user], notFound: [] }
    });
    const write = vi.spyOn(auth, 'setCustomUserClaims');
    const claims = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    ).claims;
    // @ts-expect-error Renamed to byKey.
    expect(claims.byField).toBeUndefined();
    for (const [key, value] of Object.entries(values)) {
        read.mockClear();
        const result = await claims.byKey(key).get();
        expect(result).toEqual({ error: null, data: value });
        expect(read).toHaveBeenCalledExactlyOnceWith([{ uid: 'one' }]);
    }
    for (const key of ['absent', 'toString', '__proto__']) {
        const result = await claims.byKey(key).get();
        expect(result).toEqual({ error: null, data: undefined });
    }
    expect(write).not.toHaveBeenCalled();
});

it('propagates missing-user and read failures from claim-key get', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const read = vi.spyOn(auth, 'getUsers').mockResolvedValue({
        error: null,
        data: { users: [], notFound: [{ uid: 'one' }] }
    });
    const key = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    ).claims.byKey('role');
    const { error, data } = await key.get();
    expect(error).toMatchObject({ code: 'auth/user-not-found' });
    expect(data).toBeNull();
    const failure = new Error('failed');
    read.mockResolvedValueOnce({ error: failure, data: null });
    const failed = await key.get();
    expect(failed).toEqual({ error: failure, data: null });
    read.mockRejectedValueOnce(failure);
    const thrown = await key.get();
    expect(thrown).toEqual({ error: failure, data: null });
});

it('reads claims and metadata with one lookup per get and no writes', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const user = createUserRecord({
        localId: 'one',
        customAttributes: '{"role":"editor"}',
        createdAt: '0',
        lastLoginAt: '1704067200000'
    });
    const read = vi.spyOn(auth, 'getUsers').mockResolvedValue({
        error: null,
        data: { users: [user], notFound: [] }
    });
    const write = vi.spyOn(auth, 'setCustomUserClaims');
    const reference = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    );
    const claims = await reference.claims.get();
    expect(claims).toEqual({ error: null, data: { role: 'editor' } });
    expect(read).toHaveBeenCalledExactlyOnceWith([{ uid: 'one' }]);
    const metadata = await reference.metadata.get();
    expect(metadata).toEqual({ error: null, data: user.metadata });
    expect(read).toHaveBeenCalledTimes(2);
    read.mockResolvedValueOnce({
        error: null,
        data: { users: [createUserRecord({ localId: 'one' })], notFound: [] }
    });
    const empty = await reference.claims.get();
    expect(empty).toEqual({ error: null, data: {} });
    expect(write).not.toHaveBeenCalled();
});

it('returns missing-user, returned, and thrown errors from resource reads', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const read = vi.spyOn(auth, 'getUsers');
    const reference = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    );
    const failure = new Error('read failed');
    for (const resource of [reference.claims, reference.metadata]) {
        read.mockResolvedValueOnce({
            error: null,
            data: { users: [], notFound: [{ uid: 'one' }] }
        });
        const { error, data } = await resource.get();
        expect(error).toMatchObject({ code: 'auth/user-not-found' });
        expect(data).toBeNull();
        read.mockResolvedValueOnce({ error: failure, data: null });
        const failed = await resource.get();
        expect(failed).toEqual({ error: failure, data: null });
        read.mockRejectedValueOnce(failure);
        const thrown = await resource.get();
        expect(thrown).toEqual({ error: failure, data: null });
    }
});

it('updates and deletes literal claim fields while preserving unrelated claims', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const user = createUserRecord({
        localId: 'one',
        customAttributes: '{"role":"viewer","retained":true,"some.field":"old"}'
    });
    const read = vi.spyOn(auth, 'getUsers').mockResolvedValue({
        error: null,
        data: { users: [user], notFound: [] }
    });
    const write = vi
        .spyOn(auth, 'setCustomUserClaims')
        .mockResolvedValue({ error: null, data: undefined });
    const claims = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    ).claims;
    const field = claims.byKey('some.field');
    expect(read).not.toHaveBeenCalled();
    const { error } = await field.update({ nested: true });
    expect(error).toBeNull();
    expect(write).toHaveBeenLastCalledWith('one', {
        role: 'viewer',
        retained: true,
        'some.field': { nested: true }
    });
    await field.update(null);
    expect(write).toHaveBeenLastCalledWith('one', {
        role: 'viewer',
        retained: true,
        'some.field': null
    });
    await field.delete();
    expect(write).toHaveBeenLastCalledWith('one', {
        role: 'viewer',
        retained: true
    });
    await claims.byKey('absent').delete();
    expect(write).toHaveBeenLastCalledWith('one', user.customClaims);
    expect(user.customClaims?.['some.field']).toBe('old');
    expect(read).toHaveBeenCalledTimes(4);
    expect(write).toHaveBeenCalledTimes(4);
});

it('validates claim fields and values before I/O and propagates field-operation errors', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const read = vi.spyOn(auth, 'getUsers');
    const write = vi.spyOn(auth, 'setCustomUserClaims');
    const claims = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    ).claims;
    for (const field of ['', null, 42, 'sub', 'firebase', 'x'.repeat(1001)]) {
        expect(() => claims.byKey(field as never)).toThrow();
    }
    const field = claims.byKey('role');
    for (const value of [
        undefined,
        Symbol('invalid'),
        () => true,
        1n,
        'x'.repeat(1001),
        { toJSON: () => undefined }
    ]) {
        const { error } = await field.update(value);
        expect(error).toBeInstanceOf(Error);
    }
    expect(read).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    const failure = new Error('failed');
    read.mockResolvedValueOnce({ error: failure, data: null });
    const failed = await field.delete();
    expect(failed).toEqual({ error: failure, data: null });
    expect(write).not.toHaveBeenCalled();
    read.mockResolvedValueOnce({
        error: null,
        data: { users: [createUserRecord({ localId: 'one' })], notFound: [] }
    });
    write.mockResolvedValueOnce({ error: failure, data: null });
    const denied = await field.delete();
    expect(denied).toEqual({ error: failure, data: null });
});

it('revokes tokens through metadata without a user lookup or profile write', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const revoke = vi
        .spyOn(auth, 'revokeRefreshTokens')
        .mockResolvedValue({ error: null, data: { localId: 'one' } });
    const read = vi.spyOn(auth, 'getUsers');
    const write = vi.spyOn(auth, '_writeIdentityUser');
    const reference = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    );
    const result = await reference.metadata.revokeTokens();
    expect(result).toEqual({ error: null, data: { uid: 'one' } });
    expect(revoke).toHaveBeenCalledExactlyOnceWith('one');
    expect(read).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    const failure = new Error('revocation failed');
    revoke.mockResolvedValueOnce({ error: failure, data: null });
    const failed = await reference.metadata.revokeTokens();
    expect(failed).toEqual({ error: failure, data: null });
    const other = new IdentityReference(auth, { email: 'a@example.com' });
    // @ts-expect-error Revocation requires a UID reference.
    expect(() => other.metadata.revokeTokens()).toThrow();
});

it('exposes metadata.update only on UID references and forwards a dedicated write', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const write = vi
        .spyOn(auth, '_writeIdentityUser')
        .mockResolvedValue({ error: null, data: { uid: 'one' } });
    const read = vi.spyOn(auth, 'getUsers');
    const reference = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    );
    expect(reference.metadata).toBe(reference.metadata);
    expect(write).not.toHaveBeenCalled();
    expect(reference.metadata).not.toHaveProperty('set');
    expect(reference.metadata).not.toHaveProperty('delete');
    const metadata = { creationTime: '2020-01-01T00:00:00Z' };
    const result = await reference.metadata.update(metadata);
    expect(result).toEqual({ error: null, data: { uid: 'one' } });
    expect(write).toHaveBeenCalledExactlyOnceWith('one', metadata, 'metadata');
    expect(read).not.toHaveBeenCalled();
    const failure = new Error('failed');
    write.mockResolvedValueOnce({ error: failure, data: null });
    const failed = await reference.metadata.update({});
    expect(failed).toEqual({ error: failure, data: null });
    const other = new IdentityReference(auth, { email: 'a@example.com' });
    // @ts-expect-error Metadata writes require a UID reference.
    expect(() => other.metadata.update(metadata)).toThrow();
    const multiple = new IdentityReference(
        auth,
        { uid: 'one' },
        { multiple: true, uidReference: true }
    );
    expect(() => multiple.metadata).toThrow();
    if (false) {
        reference.update({ metadata });
        // @ts-expect-error Only the two writable timestamps are supported.
        reference.metadata.update({ lastRefreshTime: '2020-01-01' });
    }
});

it('exposes a stable claims property only for UID mutation references without I/O', () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const read = vi.spyOn(auth, 'getUsers');
    const write = vi.spyOn(auth, 'setCustomUserClaims');
    const reference = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    );
    expect(reference.claims).toBe(reference.claims);
    expect(reference).not.toHaveProperty('setClaims');
    expect(reference).not.toHaveProperty('updateClaims');
    for (const other of [
        new IdentityReference(auth, { uid: 'one' }),
        new IdentityReference(auth, { email: 'a@example.com' }),
        new IdentityReference(
            auth,
            { uid: 'one' },
            { multiple: true, uidReference: true }
        )
    ]) {
        expect(() => other.claims).toThrow('requires a UID');
    }
    expect(read).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
});

it('validates replacement claims and the merged claims size through the shared writer', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const read = vi.spyOn(auth, 'getUsers').mockResolvedValue({
        error: null,
        data: {
            users: [
                createUserRecord({
                    localId: 'one',
                    customAttributes: JSON.stringify({
                        existing: 'x'.repeat(800)
                    })
                })
            ],
            notFound: []
        }
    });
    const reference = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    );
    const { error: invalid } = await reference.claims.set({ sub: 'reserved' });
    expect(invalid).toBeInstanceOf(Error);
    expect(read).not.toHaveBeenCalled();
    const { error: tooLarge } = await reference.claims.update({
        added: 'x'.repeat(300)
    });
    expect(tooLarge).toBeInstanceOf(Error);
    expect(read).toHaveBeenCalledOnce();
    if (false) {
        reference.set({ customClaims: {} });
        reference.update({ customClaims: {} });
        // @ts-expect-error Clear with claims.delete(), not claims.update(null).
        reference.claims.update(null);
    }
});

it('replaces or clears claims with one write and no lookup', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const write = vi
        .spyOn(auth, 'setCustomUserClaims')
        .mockResolvedValue({ error: null, data: undefined });
    const read = vi.spyOn(auth, 'getUsers');
    const reference = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    );
    const { error } = await reference.claims.set({ role: 'editor' });
    expect(error).toBeNull();
    expect(write).toHaveBeenLastCalledWith('one', { role: 'editor' });
    await reference.claims.delete();
    expect(write).toHaveBeenLastCalledWith('one', null);
    const removeUser = vi.spyOn(auth, 'deleteUser');
    const deleteFailure = new Error('cannot clear claims');
    write.mockResolvedValueOnce({ error: deleteFailure, data: null });
    const deleted = await reference.claims.delete();
    expect(deleted).toEqual({ error: deleteFailure, data: null });
    expect(removeUser).not.toHaveBeenCalled();
    expect(read).not.toHaveBeenCalled();
    const failure = new Error('denied');
    write.mockResolvedValueOnce({ error: failure, data: null });
    const failed = await reference.claims.set({});
    expect(failed).toEqual({ error: failure, data: null });
    const other = new IdentityReference(auth, { email: 'a@example.com' });
    // @ts-expect-error Claims writes require a UID reference.
    expect(() => other.claims.set({})).toThrow();
});

it('merges claims shallowly after one read and snapshots the patch before I/O', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const user = createUserRecord({
        localId: 'one',
        customAttributes: JSON.stringify({
            retained: true,
            role: 'viewer',
            nested: { old: true }
        })
    });
    const read = vi.spyOn(auth, 'getUsers').mockResolvedValue({
        error: null,
        data: { users: [user], notFound: [] }
    });
    const write = vi
        .spyOn(auth, 'setCustomUserClaims')
        .mockResolvedValue({ error: null, data: undefined });
    const reference = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    );
    const patch = {
        role: 'editor',
        nested: { replacement: true },
        nullable: null
    };
    const operation = reference.claims.update(patch);
    patch.role = 'changed';
    patch.nested.replacement = false;
    const { error } = await operation;
    expect(error).toBeNull();
    expect(read).toHaveBeenCalledExactlyOnceWith([{ uid: 'one' }]);
    expect(write).toHaveBeenCalledExactlyOnceWith('one', {
        retained: true,
        role: 'editor',
        nested: { replacement: true },
        nullable: null
    });
    expect(user.customClaims?.role).toBe('viewer');
    read.mockResolvedValueOnce({
        error: null,
        data: { users: [createUserRecord({ localId: 'one' })], notFound: [] }
    });
    await reference.claims.update({ first: true });
    expect(write).toHaveBeenLastCalledWith('one', { first: true });
});

it('rejects invalid claims before reading and stops on missing users or read errors', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const read = vi.spyOn(auth, 'getUsers').mockResolvedValue({
        error: null,
        data: { users: [], notFound: [{ uid: 'one' }] }
    });
    const write = vi.spyOn(auth, 'setCustomUserClaims');
    const reference = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    );
    for (const claims of [
        null,
        [],
        undefined,
        { sub: 'reserved' },
        { large: 'x'.repeat(1001) }
    ]) {
        const { error } = await reference.claims.update(claims as never);
        expect(error).toBeInstanceOf(Error);
    }
    expect(read).not.toHaveBeenCalled();
    const { error: missing } = await reference.claims.update({
        role: 'editor'
    });
    expect(missing).toMatchObject({ code: 'auth/user-not-found' });
    const failure = new Error('failed');
    read.mockResolvedValueOnce({ error: failure, data: null });
    const failed = await reference.claims.update({});
    expect(failed).toEqual({ error: failure, data: null });
    expect(write).not.toHaveBeenCalled();
    read.mockResolvedValue({
        error: null,
        data: { users: [createUserRecord({ localId: 'one' })], notFound: [] }
    });
    write.mockResolvedValueOnce({ error: failure, data: null });
    const denied = await reference.claims.update({});
    expect(denied).toEqual({ error: failure, data: null });
    write.mockRejectedValueOnce(failure);
    const thrown = await reference.claims.update({});
    expect(thrown).toEqual({ error: failure, data: null });
    const other = new IdentityReference(auth, { email: 'a@example.com' });
    // @ts-expect-error Claims writes require a UID reference.
    expect(() => other.claims.update({})).toThrow();
});
import { FirebaseEdgeError } from './errors.js';

it('returns one user or all initial-email matches with exactly one call', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const users = [
        createUserRecord({ localId: 'one' }),
        createUserRecord({ localId: 'two' })
    ];
    const request = vi
        .spyOn(auth, 'getUsers')
        .mockResolvedValue({ error: null, data: { users, notFound: [] } });
    const identifier = { uid: 'one' };
    const lookup = new IdentityReference(auth, identifier);
    identifier.uid = 'changed';
    const single = await lookup.get();
    expect(single).toEqual({ error: null, data: users[0] });
    expect(request).toHaveBeenCalledExactlyOnceWith([{ uid: 'one' }]);
    request.mockClear();
    const multiple = await new IdentityReference(
        auth,
        { initialEmail: 'old@example.com' },
        { multiple: true }
    ).get();
    expect(multiple).toEqual({ error: null, data: users });
    expect(request).toHaveBeenCalledExactlyOnceWith([
        { initialEmail: 'old@example.com' }
    ]);
});

it('handles missing users, returned errors, and thrown errors without retrying', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const request = vi.spyOn(auth, 'getUsers').mockResolvedValue({
        error: null,
        data: { users: [], notFound: [{ uid: 'missing' }] }
    });
    const lookup = new IdentityReference(auth, { uid: 'missing' });
    const missing = await lookup.get();
    expect(missing).toEqual({ error: null, data: null });
    const error = new FirebaseEdgeError({
        code: 'auth/internal-error',
        message: 'failed'
    });
    request.mockResolvedValueOnce({ error, data: null });
    const failed = await lookup.get();
    expect(failed).toEqual({ error, data: null });
    request.mockRejectedValueOnce(error);
    const thrown = await lookup.get();
    expect(thrown).toEqual({ error, data: null });
    expect(request).toHaveBeenCalledTimes(3);
    expect(() => new IdentityReference(auth, { uid: '' })).toThrow();
    expect(request).toHaveBeenCalledTimes(3);
});

it('updates and deletes UID references without a lookup', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const write = vi
        .spyOn(auth, '_writeIdentityUser')
        .mockResolvedValue({ error: null, data: { uid: 'one' } });
    const remove = vi
        .spyOn(auth, 'deleteUser')
        .mockResolvedValue({ error: null, data: undefined });
    const read = vi.spyOn(auth, 'getUsers');
    const reference = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    );
    const payload = { displayName: 'Name' };
    const written = await reference.update(payload);
    expect(written).toEqual({ error: null, data: { uid: 'one' } });
    expect(write).toHaveBeenCalledExactlyOnceWith('one', payload);
    const deleted = await reference.delete();
    expect(deleted).toEqual({ error: null, data: { uid: 'one' } });
    expect(remove).toHaveBeenCalledExactlyOnceWith('one');
    expect(read).not.toHaveBeenCalled();
    const other = new IdentityReference(auth, { email: 'a@example.com' });
    // @ts-expect-error Non-UID mutation is not available without UID resolution.
    expect(() => other.update({})).toThrow();
    // @ts-expect-error Only UID references support delete.
    expect(() => other.delete()).toThrow();
});

it('sets only UID references and forwards the existing-only replacement operation', async () => {
    const auth = new FirebaseAdminAuth({
        project_id: 'project'
    } as ServiceAccount);
    const write = vi
        .spyOn(auth, '_writeIdentityUser')
        .mockResolvedValue({ error: null, data: { uid: 'one' } });
    const reference = new IdentityReference(
        auth,
        { uid: 'one' },
        { uidReference: true }
    );
    const payload = { displayName: 'Sam' };
    const result = await reference.set(payload);
    expect(result).toEqual({ error: null, data: { uid: 'one' } });
    expect(write).toHaveBeenCalledExactlyOnceWith('one', payload, 'set');
    const other = new IdentityReference(auth, { email: 'a@example.com' });
    // @ts-expect-error Other identifiers are read-only.
    expect(() => other.set(payload)).toThrow();
    if (false) {
        // @ts-expect-error Replacement data does not include password operations.
        reference.set({ password: 'password' });
    }
});
