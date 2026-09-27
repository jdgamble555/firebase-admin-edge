import { expect, it, vi } from 'vitest';
import { Iam } from './storage-iam.js';
import type { Storage } from './storage.js';

it('returns resolver and invalid options failures through the result contract', async () => {
    const iam = new Iam(() => {
        throw new Error('resolver failed');
    });
    const read = await iam.getPolicy();
    const write = await iam.setPolicy({ bindings: [] });
    const invalid = await iam.setPolicy({ bindings: [] }, null as never);
    for (const { error, data } of [read, write, invalid]) {
        expect(error).toBeInstanceOf(Error);
        expect(data).toBeNull();
    }
});

it('delegates policies and maps each requested permission to a boolean', async () => {
    const policy = { version: 1 as const, bindings: [] };
    const transport = {
        getIamPolicy: vi.fn().mockResolvedValue({ error: null, data: policy }),
        setIamPolicy: vi.fn().mockResolvedValue({ error: null, data: policy }),
        testIamPermissions: vi
            .fn()
            .mockResolvedValue({ error: null, data: ['storage.objects.get'] })
    };
    const iam = new Iam(() => transport as unknown as Storage);
    await expect(iam.getPolicy()).resolves.toEqual({
        error: null,
        data: policy
    });
    const updated = await iam.setPolicy(policy);
    expect(updated).toEqual({ error: null, data: policy });
    await iam.getPolicy({ requestedPolicyVersion: 3, userProject: 'billing' });
    expect(transport.getIamPolicy).toHaveBeenLastCalledWith({
        requestedPolicyVersion: 3,
        userProject: 'billing'
    });
    expect(transport.setIamPolicy).toHaveBeenCalledWith(policy);
    await expect(
        iam.testPermissions(['storage.objects.get', 'storage.objects.delete'])
    ).resolves.toEqual({
        error: null,
        data: { 'storage.objects.get': true, 'storage.objects.delete': false }
    });
});
