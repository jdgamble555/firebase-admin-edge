import { expect, it, vi } from 'vitest';
import { TenantManager } from './tenant-manager.js';
import type { AuthConfigExecutor } from './auth-config-types.js';
import type { FirebaseAdminAuth } from './firebase-admin-auth.js';

it('coordinates tenant CRUD and pagination', async () => {
    const execute = vi
        .fn<AuthConfigExecutor>()
        .mockResolvedValue({ data: {}, error: null });
    const manager = new TenantManager(execute as AuthConfigExecutor, vi.fn());
    const properties = { displayName: 'Example' };
    const created = await manager.createTenant(properties);
    const fetched = await manager.getTenant('t');
    const updated = await manager.updateTenant('t', properties);
    const deleted = await manager.deleteTenant('t');
    const listed = await manager.listTenants();
    await manager.listTenants(10, 'next');
    for (const result of [created, fetched, updated, deleted, listed])
        expect(result.error).toBeNull();
    expect(execute.mock.calls.map(([op]) => op)).toEqual([
        { resource: 'tenant', action: 'create', properties },
        { resource: 'tenant', action: 'get', id: 't' },
        { resource: 'tenant', action: 'update', id: 't', properties },
        { resource: 'tenant', action: 'delete', id: 't' },
        {
            resource: 'tenant',
            action: 'list',
            maxResults: 1000,
            pageToken: undefined
        },
        {
            resource: 'tenant',
            action: 'list',
            maxResults: 10,
            pageToken: 'next'
        }
    ]);
});

it('validates tenant IDs synchronously and reuses instances', () => {
    const createAuth = vi
        .fn()
        .mockImplementation(() => ({}) as FirebaseAdminAuth);
    const manager = new TenantManager(vi.fn(), createAuth);
    expect(() => manager.authForTenant('')).toThrow();
    expect(createAuth).not.toHaveBeenCalled();
    const first = manager.authForTenant('a');
    expect(manager.authForTenant('a')).toBe(first);
    expect(manager.authForTenant('b')).not.toBe(first);
    expect(createAuth.mock.calls).toEqual([['a'], ['b']]);
});
