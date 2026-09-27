import { expect, it } from 'vitest';
import {
    storageGeneration,
    storagePreconditions,
    storageCopyOptions,
    storageLoggingPolicy
} from './storage-reference-helpers.js';

it('merges log-delivery IAM without changing existing policies or conditional grants', () => {
    const policy = {
        version: 3 as const,
        etag: 'current',
        bindings: [
            {
                role: 'roles/storage.objectCreator',
                members: ['user:owner@example.com'],
                condition: { title: 'limited', expression: 'false' }
            }
        ]
    };
    const updated = storageLoggingPolicy(policy);
    expect(updated?.etag).toBe('current');
    expect(updated?.bindings).toHaveLength(2);
    expect(policy.bindings).toHaveLength(1);
    expect(updated?.bindings[1]).toEqual({
        role: 'roles/storage.objectCreator',
        members: ['group:cloud-storage-analytics@google.com']
    });
    expect(storageLoggingPolicy(updated!)).toBeUndefined();
    const merged = storageLoggingPolicy({
        bindings: [
            {
                role: 'roles/storage.objectCreator',
                members: ['user:owner@example.com']
            }
        ]
    });
    expect(merged?.bindings[0]?.members).toEqual([
        'user:owner@example.com',
        'group:cloud-storage-analytics@google.com'
    ]);
});

it('normalizes safe numbers and preserves large integer strings', () => {
    expect(storageCopyOptions({})).toEqual({});
    expect(
        storageCopyOptions({
            contentType: 'text/plain',
            metadata: { tag: 'value' },
            preconditionOpts: { ifGenerationMatch: 0 }
        })
    ).toEqual({
        metadata: { contentType: 'text/plain', metadata: { tag: 'value' } },
        ifGenerationMatch: '0'
    });
    expect(storageGeneration('90071992547409930')).toBe('90071992547409930');
    expect(storageGeneration(0)).toBe('0');
    expect(storagePreconditions()).toEqual({});
    expect(
        storagePreconditions({
            ifGenerationMatch: 0,
            ifMetagenerationMatch: '2',
            ifGenerationNotMatch: 3,
            ifMetagenerationNotMatch: 4
        })
    ).toEqual({
        ifGenerationMatch: '0',
        ifMetagenerationMatch: '2',
        ifGenerationNotMatch: '3',
        ifMetagenerationNotMatch: '4'
    });
});
it.each([
    -1,
    1.5,
    NaN,
    Infinity,
    Number.MAX_SAFE_INTEGER + 1,
    '',
    '1e3',
    '1.2'
])('rejects invalid generation %s', (value) => {
    expect(() => storageGeneration(value)).toThrow(/Generation/);
});
