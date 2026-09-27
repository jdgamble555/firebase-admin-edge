import { expect, it, vi } from 'vitest';
import { Acl } from './storage-acl.js';
import type { Storage } from './storage.js';

it('returns malformed options and resolver failures as error results', async () => {
    const failure = new Error('resolver failed');
    const acl = new Acl(
        () => {
            throw failure;
        },
        { scope: 'bucket' }
    );
    for (const operation of [
        () => acl.get(null as never),
        () => acl.delete(null as never),
        () => acl.add({ entity: 'allUsers', role: 'READER' }),
        () => acl.update({ entity: 'allUsers', role: 'READER' })
    ]) {
        const { error, data } = await operation();
        expect(error).toBeInstanceOf(Error);
        expect(data).toBeNull();
    }
});

it('preserves successful results without nesting envelopes', async () => {
    const entry = { entity: 'allUsers', role: 'READER' };
    const transport = {
        createAcl: vi.fn().mockResolvedValue({ error: null, data: entry }),
        updateAcl: vi.fn().mockResolvedValue({ error: null, data: entry }),
        getAcl: vi.fn().mockResolvedValue({ error: null, data: entry }),
        listAcl: vi.fn().mockResolvedValue({ error: null, data: [entry] }),
        deleteAcl: vi.fn().mockResolvedValue({ error: null, data: undefined })
    };
    const acl = new Acl(transport as unknown as Storage, { scope: 'bucket' });
    const added = await acl.add({ entity: 'allUsers', role: 'READER' });
    const updated = await acl.update({ entity: 'allUsers', role: 'READER' });
    const read = await acl.get({ entity: 'allUsers' });
    const listed = await acl.get();
    const deleted = await acl.delete({ entity: 'allUsers' });
    expect(added).toEqual({ error: null, data: entry });
    expect(updated).toEqual(added);
    expect(read).toEqual(added);
    expect(listed).toEqual({ error: null, data: [entry] });
    expect(deleted).toEqual({ error: null, data: undefined });
});

it('delegates ACL CRUD and resolves the current scoped transport', async () => {
    const original = {
        createAcl: vi.fn(),
        updateAcl: vi.fn(),
        getAcl: vi.fn(),
        listAcl: vi.fn(),
        deleteAcl: vi.fn()
    };
    let transport = original;
    const target = { scope: 'bucket' } as const;
    const acl = new Acl(() => transport as unknown as Storage, target);
    await acl.add({ entity: 'allUsers', role: 'READER' });
    await acl.update({ entity: 'allUsers', role: 'READER' });
    await acl.get({ entity: 'allUsers' });
    await acl.get();
    await acl.delete({ entity: 'allUsers' });
    expect(original.createAcl).toHaveBeenCalledWith(target, {
        entity: 'allUsers',
        role: 'READER'
    });
    expect(original.updateAcl).toHaveBeenCalledWith(target, {
        entity: 'allUsers',
        role: 'READER'
    });
    expect(original.getAcl).toHaveBeenCalledWith(target, 'allUsers');
    expect(original.listAcl).toHaveBeenCalledWith(target);
    expect(original.deleteAcl).toHaveBeenCalledWith(target, 'allUsers');
    transport = { ...original, listAcl: vi.fn() };
    await acl.get();
    expect(transport.listAcl).toHaveBeenCalledOnce();
});

it.each(['readers', 'writers', 'owners'] as const)(
    'provides all entity helpers for %s',
    async (roleName) => {
        const createAcl = vi.fn();
        const deleteAcl = vi.fn();
        const acl = new Acl({ createAcl, deleteAcl } as unknown as Storage, {
            scope: 'bucket'
        });
        const role = acl[roleName];
        await role.addAllUsers();
        await role.deleteAllUsers();
        await role.addAllAuthenticatedUsers();
        await role.deleteAllAuthenticatedUsers();
        await role.addUser('a@example.com');
        await role.deleteUser('a@example.com');
        await role.addGroup('b@example.com');
        await role.deleteGroup('b@example.com');
        await role.addDomain('example.com');
        await role.deleteDomain('example.com');
        await role.addProject('viewers', '123');
        await role.deleteProject('viewers', '123');
        const entities = [
            'allUsers',
            'allAuthenticatedUsers',
            'user-a@example.com',
            'group-b@example.com',
            'domain-example.com',
            'project-viewers-123'
        ];
        expect(createAcl.mock.calls.map(([, entry]) => entry.entity)).toEqual(
            entities
        );
        expect(deleteAcl.mock.calls.map(([, entity]) => entity)).toEqual(
            entities
        );
        expect(createAcl.mock.calls[0]?.[1].role).toBe(
            { readers: 'READER', writers: 'WRITER', owners: 'OWNER' }[roleName]
        );
    }
);
