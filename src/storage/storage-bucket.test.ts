import { beforeEach, expect, it, vi } from 'vitest';
import { Storage, File, Notification, Channel } from './storage.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { StorageCrc32c } from './storage-checksum.js';

it.each(['create', 'list'] as const)(
    'keeps the requested billing scope on notification references from %s',
    async (operation) => {
        const scoped = new Storage(
            { project_id: 'project' } as ServiceAccount,
            { bucketName: 'bucket', fetch: vi.fn() }
        );
        const bucket = storage.bucket();
        vi.mocked(storage.scoped).mockReturnValue(scoped);
        const notificationMetadata = {
            id: 'notice',
            topic: '//pubsub.googleapis.com/projects/project/topics/events',
            payload_format: 'JSON_API_V1' as const
        };
        vi.spyOn(scoped, 'createNotification').mockResolvedValue({
            error: null,
            data: notificationMetadata
        });
        vi.spyOn(scoped, 'listNotifications').mockResolvedValue({
            error: null,
            data: { items: [notificationMetadata] }
        });
        const get = vi
            .spyOn(scoped, 'getNotification')
            .mockResolvedValue({ error: null, data: notificationMetadata });
        const remove = vi
            .spyOn(scoped, 'deleteNotification')
            .mockResolvedValue({ error: null, data: undefined });
        const unscopedGet = vi
            .spyOn(storage, 'getNotification')
            .mockResolvedValue({ error: null, data: notificationMetadata });
        const unscopedDelete = vi
            .spyOn(storage, 'deleteNotification')
            .mockResolvedValue({ error: null, data: undefined });

        const { error, data } =
            operation === 'create'
                ? await bucket.createNotification(
                      'projects/project/topics/events',
                      { userProject: 'billing-project' }
                  )
                : await bucket.getNotifications({
                      userProject: 'billing-project'
                  });
        expect(error).toBeNull();
        if (error || !data) {
            throw error ?? new Error('Missing notification');
        }
        const notification = Array.isArray(data) ? data[0]! : data;
        const { error: readError } = await notification.getMetadata();
        const { error: deleteError } = await notification.delete();

        expect(readError).toBeNull();
        expect(deleteError).toBeNull();
        expect(storage.scoped).toHaveBeenCalledWith({
            userProject: 'billing-project'
        });
        expect(get).toHaveBeenCalledWith('notice');
        expect(remove).toHaveBeenCalledWith('notice');
        expect(unscopedGet).not.toHaveBeenCalled();
        expect(unscopedDelete).not.toHaveBeenCalled();
    }
);

it('keeps the requested billing scope when stopping a created channel', async () => {
    const scoped = new Storage({ project_id: 'project' } as ServiceAccount, {
        bucketName: 'bucket',
        fetch: vi.fn()
    });
    const bucket = storage.bucket();
    vi.mocked(storage.scoped).mockReturnValue(scoped);
    const action = vi
        .spyOn(scoped, 'referenceAction')
        .mockResolvedValue({ error: null, data: { resourceId: 'resource' } });
    const unscopedAction = vi
        .spyOn(storage, 'referenceAction')
        .mockResolvedValue({ error: null, data: {} });
    const { error, data: channel } = await bucket.createChannel(
        'channel',
        { address: 'https://example.com/hook' },
        { userProject: 'billing-project' }
    );
    expect(error).toBeNull();
    if (error || !channel) {
        throw error ?? new Error('Missing channel');
    }

    const { error: stopError } = await channel.stop();

    expect(stopError).toBeNull();
    expect(action).toHaveBeenLastCalledWith(
        { kind: 'channel', id: 'channel' },
        { kind: 'stopChannel', id: 'channel', resourceId: 'resource' }
    );
    expect(unscopedAction).not.toHaveBeenCalled();
});

it('stops pagination when cancelled during an in-flight empty page', async () => {
    const bucket = storage.bucket();
    let finish!: (result: Awaited<ReturnType<typeof bucket.getFiles>>) => void;
    const page = new Promise<Awaited<ReturnType<typeof bucket.getFiles>>>(
        (resolve) => {
            finish = resolve;
        }
    );
    const list = vi
        .spyOn(bucket, 'getFiles')
        .mockResolvedValue({ error: null, data: { files: [], prefixes: [] } })
        .mockReturnValueOnce(page);
    const reader = bucket.getFilesStream().getReader();
    const pending = reader.read();
    await vi.waitFor(() => expect(list).toHaveBeenCalledOnce());

    await reader.cancel();
    finish({
        error: null,
        data: { files: [], prefixes: [], nextQuery: { pageToken: 'next' } }
    });
    await page;

    const result = await pending;
    expect(result.done).toBe(true);
    expect(list).toHaveBeenCalledOnce();
});

it('inherits bucket options and forwards SDK resource options', async () => {
    const generator = () => new StorageCrc32c();
    const bucket = storage.bucket(undefined, {
        crc32cGenerator: generator,
        userProject: 'billing',
        generation: 12,
        softDeleted: true,
        preconditionOpts: { ifMetagenerationMatch: 2 }
    });
    const get = vi
        .spyOn(storage, 'getBucketMetadata')
        .mockResolvedValue({ error: null, data: metadata });
    await bucket.getLabels({ userProject: 'other' });
    expect(get).toHaveBeenCalledWith({
        userProject: 'other',
        generation: '12',
        softDeleted: true,
        ifMetagenerationMatch: '2'
    });
    const upload = vi
        .spyOn(storage, 'uploadStream')
        .mockResolvedValue({ error: null, data: object });
    await bucket.upload(new Uint8Array(3), {
        destination: 'file',
        encryptionKey: 'key'
    });
    expect(storage.scoped).toHaveBeenCalledWith(
        expect.objectContaining({
            encryptionKey: 'key',
            crc32cGenerator: generator
        })
    );
    expect(upload).toHaveBeenCalledWith(
        'file',
        expect.any(Uint8Array),
        expect.objectContaining({ crc32cGenerator: generator })
    );
    const compose = vi
        .spyOn(storage, 'compose')
        .mockResolvedValue({ error: null, data: object });
    await bucket.combine(['a', 'b'], 'file', { ifGenerationMatch: 0 });
    expect(compose).toHaveBeenCalledWith(
        'file',
        [{ name: 'a' }, { name: 'b' }],
        { ifGenerationMatch: '0' }
    );
    vi.spyOn(bucket, 'getFiles').mockResolvedValue({
        error: null,
        data: { files: [bucket.file('file')], prefixes: [] }
    });
    const remove = vi
        .spyOn(storage, 'deleteFiles')
        .mockResolvedValue({ error: null, data: { results: [] } });
    await bucket.deleteFiles({ ifGenerationMatch: 12, userProject: 'billing' });
    expect(remove).toHaveBeenCalledWith(
        [
            expect.objectContaining({
                name: 'file',
                ifGenerationMatch: '12',
                userProject: 'billing'
            })
        ],
        expect.any(Object)
    );
    const action = vi
        .spyOn(storage, 'referenceAction')
        .mockResolvedValue({ error: null, data: { resourceId: 'resource' } });
    await bucket.restore({ generation: 12, projection: 'noAcl' });
    expect(action).toHaveBeenLastCalledWith(
        { kind: 'bucket' },
        { kind: 'restoreBucket', generation: '12', projection: 'noAcl' }
    );
    await bucket.createChannel(
        'id',
        { address: 'https://example.com' },
        { userProject: 'channel-billing' }
    );
    expect(storage.scoped).toHaveBeenLastCalledWith({
        userProject: 'channel-billing'
    });
    vi.spyOn(storage, 'listNotifications').mockResolvedValue({
        error: null,
        data: { items: [] }
    });
    await bucket.getNotifications({ userProject: 'notification-billing' });
    expect(storage.scoped).toHaveBeenLastCalledWith({
        userProject: 'notification-billing'
    });
});

let storage: Storage;
const metadata = {
    name: 'bucket',
    metageneration: '2',
    labels: { keep: 'yes', remove: 'yes' }
};
const object = { name: 'file', bucket: 'bucket', generation: '12', size: '3' };

it('grants log delivery on the destination before enabling logging, retries conflicts, and preserves errors', async () => {
    const destination = storage.bucket('logs');
    const source = storage.bucket();
    const denied = new FirebaseEdgeError({
        code: 'storage/permission-denied',
        message: 'denied'
    });
    const conflict = new FirebaseEdgeError({
        code: 'storage/precondition-failed',
        message: 'changed'
    });
    const get = vi.spyOn(destination.iam, 'getPolicy').mockResolvedValue({
        error: null,
        data: { etag: 'fresh', bindings: [] }
    });
    const set = vi
        .spyOn(destination.iam, 'setPolicy')
        .mockResolvedValueOnce({ error: conflict, data: null })
        .mockResolvedValue({ error: null, data: { bindings: [] } });
    const update = vi
        .spyOn(storage, 'updateBucketMetadata')
        .mockResolvedValue({ error: null, data: metadata });
    await expect(
        source.enableLogging({
            bucket: destination,
            prefix: 'logs/',
            ifMetagenerationMatch: 2
        })
    ).resolves.toEqual({ error: null, data: metadata });
    expect(get).toHaveBeenCalledTimes(2);
    expect(set).toHaveBeenLastCalledWith({
        etag: 'fresh',
        bindings: [
            {
                role: 'roles/storage.objectCreator',
                members: ['group:cloud-storage-analytics@google.com']
            }
        ]
    });
    expect(update).toHaveBeenCalledWith(
        { logging: { logBucket: 'logs', logObjectPrefix: 'logs/' } },
        { ifMetagenerationMatch: '2' }
    );
    update.mockClear();
    set.mockResolvedValue({ error: denied, data: null });
    await expect(
        source.enableLogging({ bucket: destination, prefix: 'logs/' })
    ).resolves.toEqual({ error: denied, data: null });
    expect(update).not.toHaveBeenCalled();
    await expect(source.enableLogging({} as never)).resolves.toMatchObject({
        error: { code: 'storage/invalid-argument' }
    });
    get.mockResolvedValue({
        error: null,
        data: {
            bindings: [
                {
                    role: 'roles/storage.objectCreator',
                    members: ['group:cloud-storage-analytics@google.com']
                }
            ]
        }
    });
    set.mockClear();
    await source.enableLogging({ bucket: destination, prefix: 'logs/' });
    expect(set).not.toHaveBeenCalled();
});
beforeEach(() => {
    vi.restoreAllMocks();
    storage = new Storage({ project_id: 'project' } as ServiceAccount, {
        bucketName: 'bucket',
        fetch: vi.fn()
    });
    vi.spyOn(Storage.prototype, 'scoped').mockImplementation(function (
        this: Storage
    ) {
        return this;
    });
});

it('constructs bucket and file references and handles metadata and missing buckets', async () => {
    const get = vi
        .spyOn(storage, 'getBucketMetadata')
        .mockResolvedValue({ error: null, data: metadata });
    const create = vi
        .spyOn(storage, 'createBucket')
        .mockResolvedValue({ error: null, data: metadata });
    const remove = vi
        .spyOn(storage, 'deleteBucket')
        .mockResolvedValue({ error: null, data: undefined });
    const bucket = storage.bucket();
    expect(bucket.getId()).toBe('bucket');
    expect(bucket.cloudStorageURI.toString()).toBe('gs://bucket');
    expect(bucket.file('file')).toBeInstanceOf(File);
    expect(bucket.notification('1')).toBeInstanceOf(Notification);
    await expect(bucket.get()).resolves.toEqual({ error: null, data: bucket });
    await expect(bucket.exists()).resolves.toEqual({ error: null, data: true });
    expect(bucket.metadata).toBe(metadata);
    await bucket.delete({ ifMetagenerationMatch: 2 });
    expect(remove).toHaveBeenCalledWith({ ifMetagenerationMatch: '2' });
    const missing = new FirebaseEdgeError({
        code: 'storage/bucket-not-found',
        message: 'missing'
    });
    get.mockResolvedValue({ error: missing, data: null });
    await expect(bucket.exists()).resolves.toEqual({
        error: null,
        data: false
    });
    await expect(bucket.get()).resolves.toEqual({ error: missing, data: null });
    await expect(
        bucket.get({ autoCreate: true, location: 'EU' })
    ).resolves.toEqual({ error: null, data: bucket });
    expect(create).toHaveBeenCalledWith({ location: 'EU' });
    await expect(
        bucket.delete({ ifMetagenerationMatch: -1 })
    ).resolves.toMatchObject({ error: { code: 'storage/invalid-argument' } });
});
it('paginates into versioned File references and preserves prefixes and manual cursors', async () => {
    const list = vi
        .spyOn(storage, 'listFiles')
        .mockResolvedValueOnce({
            error: null,
            data: { files: [object], prefixes: ['dir/'], nextPageToken: 'next' }
        })
        .mockResolvedValueOnce({
            error: null,
            data: {
                files: [{ ...object, name: 'second', generation: '13' }],
                prefixes: ['other/']
            }
        });
    const bucket = storage.bucket();
    const { error, data } = await bucket.getFiles({ versions: true });
    expect(error).toBeNull();
    expect(data?.files.map((file) => [file.name, file.generation])).toEqual([
        ['file', '12'],
        ['second', '13']
    ]);
    expect(data?.prefixes).toEqual(['dir/', 'other/']);
    expect(data?.nextQuery).toBeUndefined();
    expect(list).toHaveBeenLastCalledWith({
        versions: true,
        pageToken: 'next'
    });
    list.mockResolvedValue({
        error: null,
        data: { prefixes: [], files: [object], nextPageToken: 'more' }
    });
    const manual = await bucket.getFiles({ autoPaginate: false, prefix: 'f' });
    expect(manual.data?.nextQuery).toEqual({
        autoPaginate: false,
        prefix: 'f',
        pageToken: 'more'
    });
    await expect(bucket.getFiles()).resolves.toMatchObject({
        error: { code: 'storage/internal-error' }
    });
    await expect(bucket.getFiles({ maxApiCalls: 0 })).resolves.toMatchObject({
        error: { code: 'storage/invalid-argument' }
    });
});
it('streams lazily across empty pages and honors maxApiCalls and cancellation', async () => {
    const list = vi
        .spyOn(storage, 'listFiles')
        .mockResolvedValueOnce({
            error: null,
            data: { prefixes: [], files: [], nextPageToken: 'next' }
        })
        .mockResolvedValue({
            error: null,
            data: { prefixes: [], files: [object], nextPageToken: 'more' }
        });
    const stream = storage.bucket().getFilesStream({ maxApiCalls: 2 });
    expect(list).not.toHaveBeenCalled();
    const reader = stream.getReader();
    const first = await reader.read();
    expect(first.value?.name).toBe('file');
    await expect(reader.read()).resolves.toMatchObject({ done: true });
    expect(list).toHaveBeenCalledTimes(2);
    const cancelled = storage.bucket().getFilesStream();
    await cancelled.cancel();
    expect(list).toHaveBeenCalledTimes(2);
});
it('uploads web input, composes same-bucket sources and reports batch failures', async () => {
    vi.spyOn(storage, 'uploadStream').mockResolvedValue({
        error: null,
        data: object
    });
    const compose = vi
        .spyOn(storage, 'compose')
        .mockResolvedValue({ error: null, data: object });
    vi.spyOn(storage, 'listFiles').mockResolvedValue({
        error: null,
        data: { prefixes: [], files: [object] }
    });
    const remove = vi.spyOn(storage, 'deleteFiles').mockResolvedValue({
        error: null,
        data: { results: [{ name: 'file', error: null }] }
    });
    const bucket = storage.bucket();
    const uploaded = await bucket.upload(new Blob(['abc']), {
        destination: 'file'
    });
    expect(uploaded.data).toBeInstanceOf(File);
    await expect(bucket.upload('/tmp/file')).resolves.toMatchObject({
        error: { code: 'storage/unsupported-operation' }
    });
    await expect(bucket.upload(new Uint8Array())).resolves.toMatchObject({
        error: { code: 'storage/invalid-argument' }
    });
    await bucket.combine(
        ['one', bucket.file('two', { generation: 12 })],
        'combined'
    );
    expect(compose).toHaveBeenCalledWith(
        'combined',
        [{ name: 'one' }, { name: 'two', generation: '12' }],
        {}
    );
    await expect(
        bucket.combine([storage.bucket('other').file('one')], 'combined')
    ).resolves.toMatchObject({ error: { code: 'storage/invalid-argument' } });
    await expect(bucket.deleteFiles({ force: true })).resolves.toEqual({
        error: null,
        data: undefined
    });
    expect(remove).toHaveBeenCalledWith(
        [{ name: 'file', generation: undefined }],
        { concurrency: undefined, ignoreNotFound: true }
    );
    remove.mockResolvedValue({
        error: null,
        data: {
            results: [
                {
                    name: 'file',
                    error: new FirebaseEdgeError({
                        code: 'storage/permission-denied',
                        message: 'denied'
                    })
                }
            ]
        }
    });
    await expect(bucket.deleteFiles()).resolves.toMatchObject({
        error: { code: 'storage/batch-incomplete' }
    });
});
it('coordinates metadata conveniences with metageneration guards', async () => {
    vi.spyOn(storage, 'getBucketMetadata').mockResolvedValue({
        error: null,
        data: metadata
    });
    const update = vi
        .spyOn(storage, 'updateBucketMetadata')
        .mockResolvedValue({ error: null, data: metadata });
    const lock = vi
        .spyOn(storage, 'lockRetentionPolicy')
        .mockResolvedValue({ error: null, data: metadata });
    const bucket = storage.bucket();
    await expect(bucket.getLabels()).resolves.toEqual({
        error: null,
        data: metadata.labels
    });
    await bucket.setLabels({ new: 'label' });
    await bucket.deleteLabels('remove');
    expect(update).toHaveBeenLastCalledWith(
        { labels: { remove: null } },
        { ifMetagenerationMatch: '2' }
    );
    await bucket.deleteLabels();
    expect(update).toHaveBeenLastCalledWith(
        { labels: { remove: null, keep: null } },
        { ifMetagenerationMatch: '2' }
    );
    await bucket.setCorsConfiguration([
        { origin: ['https://example.com'], method: ['GET'] }
    ]);
    await bucket.setStorageClass('STANDARD');
    await bucket.setRetentionPeriod(60);
    expect(update).toHaveBeenLastCalledWith(
        { retentionPolicy: { retentionPeriod: '60' } },
        {}
    );
    await bucket.removeRetentionPeriod();
    expect(update).toHaveBeenLastCalledWith({ retentionPolicy: null }, {});
    await bucket.enableRequesterPays();
    expect(update).toHaveBeenLastCalledWith(
        { billing: { requesterPays: true } },
        {}
    );
    await bucket.disableRequesterPays();
    expect(update).toHaveBeenLastCalledWith(
        { billing: { requesterPays: false } },
        {}
    );
    vi.spyOn(storage, 'getIamPolicy').mockResolvedValue({
        error: null,
        data: { bindings: [] }
    });
    vi.spyOn(storage, 'setIamPolicy').mockResolvedValue({
        error: null,
        data: { bindings: [] }
    });
    await bucket.enableLogging({ bucket, prefix: 'logs/' });
    expect(update).toHaveBeenLastCalledWith(
        { logging: { logBucket: 'bucket', logObjectPrefix: 'logs/' } },
        {}
    );
    await bucket.addLifecycleRule({
        action: { type: 'Delete' },
        condition: { age: 30 }
    });
    expect(update).toHaveBeenLastCalledWith(
        {
            lifecycle: {
                rule: [{ action: { type: 'Delete' }, condition: { age: 30 } }]
            }
        },
        { ifMetagenerationMatch: '2' }
    );
    await bucket.lock(2);
    expect(lock).toHaveBeenCalledWith('2');
    await expect(bucket.setRetentionPeriod(-1)).resolves.toMatchObject({
        error: { code: 'storage/invalid-argument' }
    });
});
it('returns notification and channel references and restores bucket generations', async () => {
    const notificationMetadata = {
        id: '1',
        topic: '//pubsub.googleapis.com/projects/project/topics/topic',
        payload_format: 'JSON_API_V1' as const
    };
    const create = vi
        .spyOn(storage, 'createNotification')
        .mockResolvedValue({ error: null, data: notificationMetadata });
    vi.spyOn(storage, 'listNotifications').mockResolvedValue({
        error: null,
        data: { items: [notificationMetadata] }
    });
    const action = vi
        .spyOn(storage, 'referenceAction')
        .mockResolvedValue({ error: null, data: { resourceId: 'resource' } });
    const bucket = storage.bucket();
    const notification = await bucket.createNotification(
        'projects/project/topics/topic',
        { eventTypes: ['OBJECT_FINALIZE'] }
    );
    expect(notification.data).toBeInstanceOf(Notification);
    expect(create).toHaveBeenCalledWith(
        expect.objectContaining({
            topic: notificationMetadata.topic,
            event_types: ['OBJECT_FINALIZE']
        })
    );
    const notifications = await bucket.getNotifications();
    expect(notifications.data?.[0]?.metadata).toBe(notificationMetadata);
    const channel = await bucket.createChannel('channel', {
        address: 'https://example.com/hooks'
    });
    expect(channel.data).toBeInstanceOf(Channel);
    action.mockResolvedValue({ error: null, data: metadata });
    await expect(bucket.restore({ generation: 12 })).resolves.toEqual({
        error: null,
        data: bucket
    });
    expect(action).toHaveBeenLastCalledWith(
        { kind: 'bucket' },
        { kind: 'restoreBucket', generation: '12' }
    );
    await expect(
        bucket.createChannel('channel', {
            address: 'https://example.com/hooks'
        })
    ).resolves.toMatchObject({ error: { code: 'storage/internal-error' } });
});
it('updates current and default ACLs and optionally object visibility', async () => {
    const acl = vi.spyOn(storage, 'createAcl').mockResolvedValue({
        error: null,
        data: { entity: 'allUsers', role: 'READER' }
    });
    vi.spyOn(storage, 'listFiles').mockResolvedValue({
        error: null,
        data: { prefixes: [], files: [object] }
    });
    const action = vi
        .spyOn(storage, 'referenceAction')
        .mockResolvedValue({ error: null, data: {} });
    const bucket = storage.bucket();
    await bucket.makePublic({ includeFiles: true });
    expect(acl.mock.calls.map(([target]) => target.scope)).toEqual([
        'bucket',
        'defaultObject',
        'object'
    ]);
    await bucket.makePrivate({ includeFiles: true });
    expect(action.mock.calls.map(([resource]) => resource.kind)).toEqual([
        'bucket',
        'file'
    ]);
    const denied = new FirebaseEdgeError({
        code: 'storage/permission-denied',
        message: 'denied'
    });
    acl.mockImplementation(async (target) =>
        target.scope === 'object'
            ? { error: denied, data: null }
            : { error: null, data: { entity: 'allUsers', role: 'READER' } }
    );
    await expect(
        bucket.makePublic({ includeFiles: true, force: true })
    ).resolves.toMatchObject({ error: { code: 'storage/batch-incomplete' } });
});
it('delegates signing, raw requests and billing scope', async () => {
    const sign = vi
        .spyOn(storage, 'referenceSignedUrl')
        .mockResolvedValue({ error: null, data: 'signed' });
    const request = vi
        .spyOn(storage, 'requestResource')
        .mockResolvedValue({ error: null, data: {} });
    const bucket = storage.bucket();
    const options = { action: 'read' as const, expires: Date.now() + 60000 };
    await bucket.getSignedUrl(options);
    expect(sign).toHaveBeenCalledWith(undefined, options);
    await bucket.request({ method: 'GET' });
    expect(request).toHaveBeenCalledWith({ kind: 'bucket' }, { method: 'GET' });
    expect(bucket.setUserProject('billing')).toBe(bucket);
    expect(storage.scoped).toHaveBeenCalledWith({ userProject: 'billing' });
});
