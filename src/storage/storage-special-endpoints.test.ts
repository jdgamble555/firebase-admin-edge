import { expect, it, vi } from 'vitest';
import {
    storageNotificationTopic,
    specialStorageRequest,
    validateSpecialOperation
} from './storage-special-endpoints.js';
import type { StorageSpecialOperation } from './storage-special-types.js';

it('qualifies short notification topics and preserves explicit projects', () => {
    expect(storageNotificationTopic('project', 'topic')).toBe(
        '//pubsub.googleapis.com/projects/project/topics/topic'
    );
    expect(
        storageNotificationTopic('project', '//pubsub.googleapis.com/topic')
    ).toBe('//pubsub.googleapis.com/projects/project/topics/topic');
    expect(
        storageNotificationTopic('project', 'projects/other/topics/topic')
    ).toBe('//pubsub.googleapis.com/projects/other/topics/topic');
    expect(() => storageNotificationTopic('project', '')).toThrow();
    expect(() => storageNotificationTopic('project', 'bad/path')).toThrow();
});

const notification = {
    id: '7',
    topic: '//pubsub.googleapis.com/projects/project/topics/topic',
    payload_format: 'JSON_API_V1' as const
};
const folder = { name: 'folder/a/', metageneration: '1' };
const hmac = {
    accessId: 'key',
    projectId: 'project',
    serviceAccountEmail: 'service@example.com',
    state: 'ACTIVE'
};
const entry = { entity: 'user-a@example.com', role: 'READER' as const };
const target = {
    scope: 'object' as const,
    name: 'folder/a',
    generation: '123'
};
const policy = { version: 3 as const, etag: 'etag', bindings: [] };
const cases: Array<
    [StorageSpecialOperation, string, string, unknown, object?]
> = [
    [
        { kind: 'notificationCreate', config: notification },
        'POST',
        '/b/bucket/notificationConfigs',
        notification,
        notification
    ],
    [
        { kind: 'notificationList' },
        'GET',
        '/b/bucket/notificationConfigs',
        { items: [notification] }
    ],
    [
        { kind: 'notificationGet', id: '7' },
        'GET',
        '/b/bucket/notificationConfigs/7',
        notification
    ],
    [
        { kind: 'notificationDelete', id: '7' },
        'DELETE',
        '/b/bucket/notificationConfigs/7',
        undefined
    ],
    [
        { kind: 'folderCreate', name: folder.name },
        'POST',
        '/b/bucket/managedFolders',
        folder,
        { name: folder.name }
    ],
    [
        { kind: 'folderGet', name: folder.name, options: {} },
        'GET',
        '/b/bucket/managedFolders/folder%2Fa%2F',
        folder
    ],
    [
        {
            kind: 'folderList',
            options: { maxResults: 1, prefix: 'folder/', pageToken: 'next' }
        },
        'GET',
        '/b/bucket/managedFolders',
        { items: [folder], nextPageToken: 'later' }
    ],
    [
        {
            kind: 'folderDelete',
            name: folder.name,
            options: { ifMetagenerationMatch: '1', allowNonEmpty: true }
        },
        'DELETE',
        '/b/bucket/managedFolders/folder%2Fa%2F',
        undefined
    ],
    [
        { kind: 'folderGetIam', name: folder.name },
        'GET',
        '/b/bucket/managedFolders/folder%2Fa%2F/iam',
        policy
    ],
    [
        { kind: 'folderSetIam', name: folder.name, policy },
        'PUT',
        '/b/bucket/managedFolders/folder%2Fa%2F/iam',
        policy,
        policy
    ],
    [
        {
            kind: 'folderTestIam',
            name: folder.name,
            permissions: ['storage.objects.get', 'storage.objects.list']
        },
        'GET',
        '/b/bucket/managedFolders/folder%2Fa%2F/iam/testPermissions',
        { permissions: ['storage.objects.get'] }
    ],
    [
        { kind: 'hmacCreate', serviceAccountEmail: hmac.serviceAccountEmail },
        'POST',
        '/projects/project/hmacKeys',
        { metadata: hmac, secret: 'one-time' }
    ],
    [
        {
            kind: 'hmacList',
            options: {
                serviceAccountEmail: hmac.serviceAccountEmail,
                showDeletedKeys: false,
                maxResults: 2
            }
        },
        'GET',
        '/projects/project/hmacKeys',
        { items: [hmac] }
    ],
    [
        { kind: 'hmacGet', accessId: 'key' },
        'GET',
        '/projects/project/hmacKeys/key',
        hmac
    ],
    [
        {
            kind: 'hmacUpdate',
            accessId: 'key',
            state: 'INACTIVE',
            etag: 'etag'
        },
        'PUT',
        '/projects/project/hmacKeys/key',
        { ...hmac, state: 'INACTIVE' },
        { state: 'INACTIVE', etag: 'etag' }
    ],
    [
        { kind: 'hmacDelete', accessId: 'key' },
        'DELETE',
        '/projects/project/hmacKeys/key',
        undefined
    ],
    [
        { kind: 'aclList', target: { scope: 'bucket' } },
        'GET',
        '/b/bucket/acl',
        { items: [entry] }
    ],
    [
        { kind: 'aclGet', target, entity: entry.entity },
        'GET',
        '/b/bucket/o/folder%2Fa/acl/user-a%40example.com',
        entry
    ],
    [
        { kind: 'aclCreate', target: { scope: 'defaultObject' }, entry },
        'POST',
        '/b/bucket/defaultObjectAcl',
        entry,
        entry
    ],
    [
        { kind: 'aclUpdate', target, entry },
        'PATCH',
        '/b/bucket/o/folder%2Fa/acl/user-a%40example.com',
        entry,
        entry
    ],
    [
        { kind: 'aclDelete', target, entity: entry.entity },
        'DELETE',
        '/b/bucket/o/folder%2Fa/acl/user-a%40example.com',
        undefined
    ]
];
it.each(cases)(
    'constructs and parses %j',
    async (operation, method, path, responseBody, body) => {
        const fetch = vi
            .fn()
            .mockResolvedValue(
                responseBody === undefined
                    ? new Response(null, { status: 204 })
                    : Response.json(responseBody)
            );
        const data = await specialStorageRequest(
            'bucket',
            'project',
            'token',
            operation,
            fetch
        );
        const [rawUrl, init] = fetch.mock.calls[0]!;
        const url = new URL(rawUrl);
        expect(url.pathname).toBe(`/storage/v1${path}`);
        expect(init.method).toBe(method);
        expect(init.headers.Authorization).toBe('Bearer token');
        expect(
            init.body === undefined ? undefined : JSON.parse(init.body)
        ).toEqual(body);
        expect(data).toEqual(
            operation.kind === 'folderTestIam'
                ? ['storage.objects.get']
                : responseBody
        );
        if ('target' in operation && operation.target.scope === 'object') {
            expect(url.searchParams.get('generation')).toBe('123');
        }
        if (operation.kind === 'folderList') {
            expect(url.searchParams.get('pageSize')).toBe('1');
            expect(url.searchParams.get('prefix')).toBe('folder/');
            expect(url.searchParams.get('pageToken')).toBe('next');
        }
        if (operation.kind === 'folderGetIam') {
            expect(url.searchParams.get('optionsRequestedPolicyVersion')).toBe(
                '3'
            );
        }
        if (operation.kind === 'folderTestIam') {
            expect(url.searchParams.getAll('permissions')).toEqual(
                operation.permissions
            );
        }
        if (operation.kind === 'folderDelete') {
            expect(url.searchParams.get('ifMetagenerationMatch')).toBe('1');
            expect(url.searchParams.get('allowNonEmpty')).toBe('true');
        }
        if (operation.kind === 'hmacCreate' || operation.kind === 'hmacList') {
            expect(url.searchParams.get('serviceAccountEmail')).toBe(
                hmac.serviceAccountEmail
            );
        }
    }
);
it.each(['notificationList', 'folderList', 'hmacList', 'aclList'] as const)(
    'normalizes empty %s results',
    async (kind) => {
        const fetch = vi.fn().mockResolvedValue(Response.json({}));
        const operation = {
            kind,
            options: {},
            target: { scope: 'bucket' }
        } as StorageSpecialOperation;
        const data = await specialStorageRequest(
            'bucket',
            'project',
            'token',
            operation,
            fetch
        );
        expect(data).toEqual({ items: [] });
    }
);
it.each([
    { kind: 'notificationCreate', config: { ...notification, topic: 'bad' } },
    {
        kind: 'notificationCreate',
        config: { ...notification, custom_attributes: { bad: 1 } }
    },
    { kind: 'notificationGet', id: '..' },
    { kind: 'folderCreate', name: '/' },
    { kind: 'folderCreate', name: 'missing-slash' },
    { kind: 'folderList', options: { maxResults: 0 } },
    {
        kind: 'folderDelete',
        name: 'folder/',
        options: { allowNonEmpty: 'yes' }
    },
    { kind: 'folderSetIam', name: 'folder/', policy: {} },
    { kind: 'folderTestIam', name: 'folder/', permissions: ['storage.*'] },
    { kind: 'hmacCreate', serviceAccountEmail: '' },
    { kind: 'hmacUpdate', accessId: 'key', state: 'DELETED' },
    { kind: 'hmacList', options: { serviceAccountEmail: '' } },
    { kind: 'hmacList', options: { showDeletedKeys: 1 } },
    { kind: 'aclList', target: null },
    { kind: 'aclCreate', target, entry: { ...entry, role: 'WRITER' } },
    {
        kind: 'aclGet',
        target: { ...target, generation: '-1' },
        entity: entry.entity
    }
])(
    'rejects invalid specialized operation %j before network access',
    async (operation) => {
        const fetch = vi.fn();
        await expect(
            specialStorageRequest(
                'bucket',
                'project',
                'token',
                operation as StorageSpecialOperation,
                fetch
            )
        ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
        expect(fetch).not.toHaveBeenCalled();
    }
);
it('requires project IDs for HMAC, but does not require a bucket', () => {
    validateSpecialOperation(undefined, 'project', {
        kind: 'hmacList',
        options: {}
    });
    expect(() =>
        validateSpecialOperation('bucket', '', {
            kind: 'hmacList',
            options: {}
        })
    ).toThrow();
    expect(() =>
        validateSpecialOperation(undefined, 'project', {
            kind: 'notificationList'
        })
    ).toThrow();
});
it.each([
    [{ kind: 'notificationGet', id: '7' }, {}],
    [{ kind: 'folderGet', name: 'folder/', options: {} }, null],
    [{ kind: 'folderList', options: {} }, { items: [null] }],
    [
        { kind: 'folderList', options: {} },
        { items: {}, nextPageToken: 1 }
    ],
    [{ kind: 'folderGetIam', name: 'folder/' }, { bindings: 'bad' }],
    [
        {
            kind: 'folderTestIam',
            name: 'folder/',
            permissions: ['storage.objects.get']
        },
        { permissions: [1] }
    ],
    [
        { kind: 'hmacCreate', serviceAccountEmail: hmac.serviceAccountEmail },
        { metadata: hmac }
    ],
    [{ kind: 'hmacGet', accessId: 'key' }, {}]
])('rejects malformed specialized response %j', async (operation, body) => {
    const fetch = vi.fn().mockResolvedValue(Response.json(body));
    await expect(
        specialStorageRequest(
            'bucket',
            'project',
            'token',
            operation as StorageSpecialOperation,
            fetch
        )
    ).rejects.toMatchObject({ code: 'storage/internal-error' });
});
it('maps missing resources without exposing request secrets', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValue(
            Response.json({ error: { message: 'missing' } }, { status: 404 })
        );
    await expect(
        specialStorageRequest(
            'bucket',
            'project',
            'secret-token',
            { kind: 'hmacGet', accessId: 'key' },
            fetch
        )
    ).rejects.toMatchObject({ code: 'storage/resource-not-found' });
});

it.each(['.', '..', 'user-a\nb'])(
    'rejects invalid ACL path identifiers %s',
    (entity) => {
        expect(() =>
            validateSpecialOperation('bucket', 'project', {
                kind: 'aclUpdate',
                target,
                entry: { entity, role: 'READER' }
            })
        ).toThrow();
    }
);
