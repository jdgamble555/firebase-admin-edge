import { expect, it, vi } from 'vitest';
import {
    bucketRequest,
    validateBucketOperation
} from './storage-bucket-endpoints.js';
import type { StorageBucketOperation } from './storage-bucket-types.js';

const bucket = { name: 'bucket', metageneration: '2', location: 'US' };

it('maps specialized bucket creation aliases into metadata and query parameters', async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json(bucket));
    await bucketRequest(
        'bucket',
        'project',
        'token',
        {
            kind: 'create',
            metadata: {
                location: 'US',
                dataLocations: ['US-EAST1', 'US-WEST1'],
                standard: true,
                requesterPays: true,
                enableObjectRetention: true,
                predefinedAcl: 'private',
                predefinedDefaultObjectAcl: 'private',
                projection: 'full',
                userProject: 'billing',
                hierarchicalNamespace: { enabled: true },
                rpo: 'DEFAULT'
            }
        },
        fetch
    );
    const [url, init] = fetch.mock.calls[0]!;
    expect(Object.fromEntries(new URL(url).searchParams)).toEqual({
        project: 'project',
        enableObjectRetention: 'true',
        predefinedAcl: 'private',
        predefinedDefaultObjectAcl: 'private',
        projection: 'full',
        userProject: 'billing'
    });
    expect(JSON.parse(init.body)).toEqual({
        name: 'bucket',
        location: 'US',
        customPlacementConfig: { dataLocations: ['US-EAST1', 'US-WEST1'] },
        storageClass: 'STANDARD',
        billing: { requesterPays: true },
        hierarchicalNamespace: { enabled: true },
        rpo: 'DEFAULT'
    });
});

it.each([
    { dataLocations: ['US-EAST1'] },
    { dataLocations: ['US-EAST1', 'US-EAST1'] },
    { standard: true, archive: true },
    { requesterPays: 'yes' },
    { requesterPays: true, billing: { requesterPays: false } },
    { dataLocations: [], customPlacementConfig: { dataLocations: [] } },
    { enableObjectRetention: 'yes' },
    { projection: 'invalid' },
    { hierarchicalNamespace: { enabled: 'yes' } },
    { rpo: 'invalid' },
    { acl: [{ entity: 'allUsers', role: 'invalid' }] }
])('rejects malformed specialized settings %j', (settings) => {
    expect(() =>
        validateBucketOperation('bucket', 'project', {
            kind: 'create',
            metadata: { location: 'US', ...settings }
        } as never)
    ).toThrow();
});

it('accepts writable ACL and numeric retention metadata while guarding create-only settings', () => {
    validateBucketOperation('bucket', 'project', {
        kind: 'update',
        metadata: {
            acl: null,
            defaultObjectAcl: [{ entity: 'allUsers', role: 'READER' }],
            retentionPolicy: { retentionPeriod: 60 },
            softDeletePolicy: { retentionDurationSeconds: 604800 }
        },
        options: {}
    });
    expect(() =>
        validateBucketOperation('bucket', 'project', {
            kind: 'update',
            metadata: { hierarchicalNamespace: { enabled: true } },
            options: {}
        } as never)
    ).toThrow();
});

it('locks retention with an explicit metageneration precondition', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValue(
            Response.json({ ...bucket, retentionPolicy: { isLocked: true } })
        );
    const data = await bucketRequest(
        'bucket',
        'project',
        'token',
        { kind: 'lockRetention', options: { ifMetagenerationMatch: '2' } },
        fetch
    );
    expect(data.retentionPolicy).toEqual({ isLocked: true });
    const [url, init] = fetch.mock.calls[0]!;
    expect(new URL(url).pathname).toBe(
        '/storage/v1/b/bucket/lockRetentionPolicy'
    );
    expect(new URL(url).searchParams.get('ifMetagenerationMatch')).toBe('2');
    expect(init.method).toBe('POST');
});
it.each(['', '0', '-1', undefined, 2])(
    'rejects missing or invalid retention metageneration %j',
    (value) => {
        expect(() =>
            validateBucketOperation('bucket', 'project', {
                kind: 'lockRetention',
                options: { ifMetagenerationMatch: value as string }
            })
        ).toThrow();
    }
);

it('reads, creates, patches and deletes buckets with the appropriate methods', async () => {
    const fetch = vi
        .fn()
        .mockImplementation(() => Promise.resolve(Response.json(bucket)));
    const get = await bucketRequest(
        'bucket',
        'project',
        'token',
        { kind: 'get', options: { ifMetagenerationMatch: '2' } },
        fetch
    );
    const create = await bucketRequest(
        'bucket',
        'project',
        'token',
        {
            kind: 'create',
            metadata: { location: 'US', versioning: { enabled: true } }
        },
        fetch
    );
    const patch = {
        cors: [
            {
                origin: ['https://example.com'],
                method: ['GET', 'PUT'],
                responseHeader: ['Content-Type'],
                maxAgeSeconds: 3600
            }
        ],
        lifecycle: {
            rule: [
                { action: { type: 'Delete' as const }, condition: { age: 30 } }
            ]
        },
        labels: { app: 'demo', removed: null }
    };
    const update = await bucketRequest(
        'bucket',
        'project',
        'token',
        {
            kind: 'update',
            metadata: patch,
            options: { ifMetagenerationMatch: '2' }
        },
        fetch
    );
    fetch.mockResolvedValueOnce(new Response(null, { status: 204 }));
    const deleted = await bucketRequest(
        'bucket',
        'project',
        'token',
        { kind: 'delete', options: { ifMetagenerationNotMatch: '1' } },
        fetch
    );
    expect(get).toEqual(bucket);
    expect(create).toEqual(bucket);
    expect(update).toEqual(bucket);
    expect(deleted).toBeUndefined();
    expect(fetch.mock.calls.map((call) => call[1].method)).toEqual([
        'GET',
        'POST',
        'PATCH',
        'DELETE'
    ]);
    expect(fetch.mock.calls[0]![0]).toBe(
        'https://storage.googleapis.com/storage/v1/b/bucket?ifMetagenerationMatch=2'
    );
    expect(fetch.mock.calls[1]![0]).toBe(
        'https://storage.googleapis.com/storage/v1/b?project=project'
    );
    expect(JSON.parse(fetch.mock.calls[1]![1].body)).toEqual({
        name: 'bucket',
        location: 'US',
        versioning: { enabled: true }
    });
    expect(JSON.parse(fetch.mock.calls[2]![1].body)).toEqual(patch);
    expect(fetch.mock.calls[3]![0]).toContain('ifMetagenerationNotMatch=1');
});

it('paginates bucket lists without requiring a configured bucket', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(
            Response.json({ items: [bucket], nextPageToken: 'next' })
        )
        .mockResolvedValueOnce(Response.json({}));
    const first = await bucketRequest(
        undefined,
        'project',
        'token',
        {
            kind: 'list',
            options: { prefix: 'a &', pageToken: 'p+', maxResults: 3 }
        },
        fetch
    );
    const empty = await bucketRequest(
        undefined,
        'project',
        'token',
        { kind: 'list', options: {} },
        fetch
    );
    expect(first).toEqual({ buckets: [bucket], nextPageToken: 'next' });
    expect(empty).toEqual({ buckets: [] });
    expect(
        Object.fromEntries(new URL(fetch.mock.calls[0]![0]).searchParams)
    ).toEqual({
        project: 'project',
        prefix: 'a &',
        pageToken: 'p+',
        maxResults: '3'
    });
});

it('preserves conditional IAM policies and etags and sends repeated permissions', async () => {
    const policy = {
        version: 3 as const,
        etag: 'etag',
        bindings: [
            {
                role: 'roles/storage.objectViewer',
                members: ['user:reader@example.com'],
                condition: {
                    title: 'prefix',
                    expression:
                        'resource.name.startsWith("projects/_/buckets/bucket/objects/public/")'
                }
            }
        ]
    };
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(Response.json(policy))
        .mockResolvedValueOnce(Response.json(policy))
        .mockResolvedValueOnce(
            Response.json({ permissions: ['storage.objects.get'] })
        )
        .mockResolvedValueOnce(Response.json({}));
    const read = await bucketRequest(
        'bucket',
        'project',
        'token',
        { kind: 'getIam' },
        fetch
    );
    const updated = await bucketRequest(
        'bucket',
        'project',
        'token',
        { kind: 'setIam', policy },
        fetch
    );
    const permissions = await bucketRequest(
        'bucket',
        'project',
        'token',
        {
            kind: 'testIam',
            permissions: ['storage.objects.get', 'storage.objects.create']
        },
        fetch
    );
    const denied = await bucketRequest(
        'bucket',
        'project',
        'token',
        { kind: 'testIam', permissions: ['storage.objects.delete'] },
        fetch
    );
    expect(read).toEqual(policy);
    expect(updated).toEqual(policy);
    expect(permissions).toEqual(['storage.objects.get']);
    expect(denied).toEqual([]);
    expect(fetch.mock.calls[0]![0]).toBe(
        'https://storage.googleapis.com/storage/v1/b/bucket/iam?optionsRequestedPolicyVersion=3'
    );
    expect(fetch.mock.calls[1]![1].method).toBe('PUT');
    expect(JSON.parse(fetch.mock.calls[1]![1].body)).toEqual(policy);
    expect(
        new URL(fetch.mock.calls[2]![0]).searchParams.getAll('permissions')
    ).toEqual(['storage.objects.get', 'storage.objects.create']);
});

it('normalizes an IAM policy without bindings', async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json({ etag: 'e' }));
    const policy = await bucketRequest(
        'bucket',
        'project',
        'token',
        { kind: 'getIam' },
        fetch
    );
    expect(policy).toEqual({ etag: 'e', bindings: [] });
});

it.each([
    { cors: null },
    { cors: [] },
    { lifecycle: null },
    { lifecycle: { rule: [] } },
    { versioning: { enabled: false } },
    { storageClass: 'STANDARD' },
    { defaultEventBasedHold: false },
    { billing: { requesterPays: true } },
    {
        encryption: {
            defaultKmsKeyName: 'projects/p/locations/l/keyRings/r/cryptoKeys/k'
        }
    },
    { encryption: null },
    { retentionPolicy: { retentionPeriod: '86400' } },
    { retentionPolicy: null },
    { softDeletePolicy: { retentionDurationSeconds: '0' } },
    { autoclass: { enabled: true } },
    {
        iamConfiguration: {
            uniformBucketLevelAccess: { enabled: true },
            publicAccessPrevention: 'enforced'
        }
    }
])('accepts supported bucket setting %#', (metadata) => {
    expect(() =>
        validateBucketOperation('bucket', 'project', {
            kind: 'update',
            metadata: metadata as never,
            options: {}
        })
    ).not.toThrow();
});

it.each([
    { kind: 'list', options: { maxResults: 0 } },
    { kind: 'get', options: { ifMetagenerationMatch: 'bad' } },
    { kind: 'update', metadata: {}, options: {} },
    { kind: 'update', metadata: { name: 'rename' }, options: {} },
    { kind: 'update', metadata: { location: 'EU' }, options: {} },
    { kind: 'create', metadata: {} },
    { kind: 'update', metadata: { cors: [{}] }, options: {} },
    {
        kind: 'update',
        metadata: { versioning: { enabled: 'true' } },
        options: {}
    },
    { kind: 'update', metadata: { labels: { a: 1 } }, options: {} },
    {
        kind: 'update',
        metadata: { retentionPolicy: { retentionPeriod: '1', isLocked: true } },
        options: {}
    },
    {
        kind: 'update',
        metadata: {
            lifecycle: {
                rule: [{ action: { type: 'Unknown' }, condition: {} }]
            }
        },
        options: {}
    },
    { kind: 'setIam', policy: null },
    { kind: 'setIam', policy: { version: 2, bindings: [] } },
    { kind: 'setIam', policy: { bindings: [{ role: '', members: [] }] } },
    {
        kind: 'setIam',
        policy: {
            bindings: [
                {
                    role: 'roles/x',
                    members: ['user:a'],
                    condition: { title: 'a', expression: 'true' }
                }
            ]
        }
    },
    { kind: 'testIam', permissions: [] },
    { kind: 'testIam', permissions: ['storage.*'] }
])(
    'rejects invalid administration request %# before fetch',
    async (operation) => {
        const fetch = vi.fn();
        await expect(
            bucketRequest(
                'bucket',
                'project',
                'token',
                operation as StorageBucketOperation,
                fetch
            )
        ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
        expect(fetch).not.toHaveBeenCalled();
    }
);

it('requires project IDs for collection requests and bucket names for object requests', () => {
    expect(() =>
        validateBucketOperation(undefined, '', { kind: 'list', options: {} })
    ).toThrow();
    expect(() =>
        validateBucketOperation(undefined, 'project', {
            kind: 'get',
            options: {}
        })
    ).toThrow();
});

it.each([
    [{ kind: 'get', options: {} }, {}],
    [{ kind: 'list', options: {} }, { items: {} }],
    [{ kind: 'list', options: {} }, { items: [{}] }],
    [{ kind: 'list', options: {} }, { nextPageToken: 1 }],
    [
        { kind: 'testIam', permissions: ['storage.objects.get'] },
        { permissions: [1] }
    ]
])('rejects malformed administration responses %#', async (operation, body) => {
    const fetch = vi.fn().mockResolvedValue(Response.json(body));
    await expect(
        bucketRequest(
            'bucket',
            'project',
            'token',
            operation as StorageBucketOperation,
            fetch
        )
    ).rejects.toMatchObject({ code: 'storage/internal-error' });
});

it('maps missing buckets separately from missing objects', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValue(new Response('missing bucket', { status: 404 }));
    await expect(
        bucketRequest(
            'bucket',
            'project',
            'token',
            { kind: 'get', options: {} },
            fetch
        )
    ).rejects.toMatchObject({ code: 'storage/bucket-not-found' });
});

it('reports malformed policy responses as server errors', async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json({ bindings: 'bad' }));
    await expect(
        bucketRequest('bucket', 'project', 'token', { kind: 'getIam' }, fetch)
    ).rejects.toMatchObject({ code: 'storage/internal-error' });
});

it('preserves IAM and bucket request failures', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValue(
            Response.json({ error: { message: 'denied' } }, { status: 403 })
        );
    await expect(
        bucketRequest('bucket', 'project', 'token', { kind: 'getIam' }, fetch)
    ).rejects.toMatchObject({ code: 'storage/permission-denied' });
});
