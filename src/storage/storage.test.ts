import { beforeEach, expect, it, vi } from 'vitest';
import { Storage, Bucket, HmacKey, getStorage } from './storage.js';
import { storageRequest } from './storage-endpoints.js';
import { getToken } from '../auth/google-oauth.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { signStorageUrl } from './storage-signed-url.js';
import { bucketRequest } from './storage-bucket-endpoints.js';
import { resumableRequest } from './storage-resumable.js';
import { createStorageRetryFetch } from './storage-retry.js';
import { specialStorageRequest } from './storage-special-endpoints.js';
import { signStorageXmlRequest } from './storage-xml-signing.js';
import { uploadStorageStream } from './storage-upload-stream.js';
import type {
    ServiceAccount,
    GoogleTokenResponse
} from '../auth/firebase-types.js';

vi.mock('../auth/google-oauth.js');
vi.mock('./storage-signed-url.js', async (original) => {
    const actual = await original<typeof import('./storage-signed-url.js')>();
    return { ...actual, signStorageUrl: vi.fn() };
});
vi.mock('./storage-resumable.js');
vi.mock('./storage-retry.js');
vi.mock('./storage-xml-signing.js');
vi.mock('./storage-upload-stream.js');
vi.mock('./storage-special-endpoints.js', async (original) => {
    const actual =
        await original<typeof import('./storage-special-endpoints.js')>();
    return { ...actual, specialStorageRequest: vi.fn() };
});
vi.mock('./storage-bucket-endpoints.js', async (original) => {
    const actual =
        await original<typeof import('./storage-bucket-endpoints.js')>();
    return { ...actual, bucketRequest: vi.fn() };
});
vi.mock('./storage-endpoints.js', async (original) => {
    const actual = await original<typeof import('./storage-endpoints.js')>();
    return { ...actual, storageRequest: vi.fn() };
});
const account = {
    project_id: 'project',
    client_email: 'service@example.com'
} as ServiceAccount;
const oauth = {
    access_token: 'access',
    expires_in: 3600
} as GoogleTokenResponse;
const fetch = vi.fn();
beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(createStorageRetryFetch).mockImplementation((fetch) => fetch);
    vi.mocked(getToken).mockResolvedValue({ error: null, data: oauth });
});

it('configures the retry transport once per instance', () => {
    new Storage(account, {
        bucketName: 'bucket',
        fetch,
        retryOptions: {
            maxRetries: 0
        }
    });
    expect(createStorageRetryFetch).toHaveBeenCalledWith(fetch, {
        maxRetries: 0
    });
});

it('reuses configured OAuth and fetch for explicitly requested IAM signing', async () => {
    fetch.mockResolvedValue(Response.json({ signedBlob: 'AQID' }));
    const storage = new Storage(account, { bucketName: 'bucket', fetch });
    const { error, data } = await storage.referenceSignedUrl('file', {
        action: 'read',
        expires: Date.now() + 60000,
        signingEndpoint:
            'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/'
    });
    expect(error).toBeNull();
    expect(data).toContain('Signature=AQID');
    expect(getToken).toHaveBeenCalledWith(account, fetch);
    expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining(':signBlob'),
        expect.objectContaining({
            headers: {
                Authorization: 'Bearer access',
                'Content-Type': 'application/json'
            }
        })
    );
});

it('creates bucket and HMAC references without network operations', () => {
    const storage = new Storage(account, { bucketName: 'bucket', fetch });
    expect(getStorage({ storage })).toBe(storage);
    expect(() => getStorage(undefined as never)).toThrow(/configured/);
    expect(storage.bucket()).toBeInstanceOf(Bucket);
    expect(storage.bucket('other').name).toBe('other');
    expect(storage.hmacKey('access-id')).toBeInstanceOf(HmacKey);
    expect(() => storage.bucket('gs://bucket')).toThrow();
    expect(() => storage.hmacKey('')).toThrow();
    expect(fetch).not.toHaveBeenCalled();
    expect(getToken).not.toHaveBeenCalled();
});

it('delegates upload automation and XML signing and coordinates retention locking', async () => {
    const storage = new Storage(account, { bucketName: 'bucket', fetch });
    const metadata = {
        name: 'file',
        bucket: 'bucket',
        generation: '1',
        size: '3'
    };
    vi.mocked(uploadStorageStream).mockResolvedValue(metadata);
    const { error, data } = await storage.uploadStream('file', 'abc');
    expect(error).toBeNull();
    expect(data).toEqual(metadata);
    expect(uploadStorageStream).toHaveBeenCalledWith(
        storage,
        'file',
        'abc',
        {}
    );
    const request = new Request('https://storage.googleapis.com/bucket/file');
    vi.mocked(signStorageXmlRequest).mockResolvedValue(request);
    const signed = await storage.signXmlRequest({
        method: 'GET',
        name: 'file'
    });
    expect(signed).toEqual({ error: null, data: request });
    expect(signStorageXmlRequest).toHaveBeenCalledWith(account, 'bucket', {
        method: 'GET',
        name: 'file'
    });
    await storage.lockRetentionPolicy('2');
    expect(bucketRequest).toHaveBeenCalledWith(
        'bucket',
        'project',
        'access',
        { kind: 'lockRetention', options: { ifMetagenerationMatch: '2' } },
        fetch
    );
});

it('normalizes new helper failures and validates irreversible locks before OAuth', async () => {
    const storage = new Storage(account, { bucketName: 'bucket', fetch });
    const { error: lockError } = await storage.lockRetentionPolicy('');
    expect(lockError?.code).toBe('storage/invalid-argument');
    expect(getToken).not.toHaveBeenCalled();
    vi.mocked(signStorageXmlRequest).mockRejectedValue(new Error('signing'));
    const { error: signError } = await storage.signXmlRequest({
        method: 'GET'
    });
    expect(signError?.code).toBe('storage/internal-error');
    vi.mocked(uploadStorageStream).mockRejectedValue(new Error('upload'));
    const { error: uploadError } = await storage.uploadStream('file', 'abc');
    expect(uploadError?.code).toBe('storage/internal-error');
});

it('coordinates every specialized operation through authenticated endpoints', async () => {
    const storage = new Storage(account, { bucketName: 'bucket', fetch });
    const config = {
        topic: '//pubsub.googleapis.com/projects/project/topics/topic',
        payload_format: 'NONE' as const
    };
    const policy = { bindings: [] };
    const target = { scope: 'bucket' as const };
    const entry = { entity: 'user-a@example.com', role: 'READER' as const };
    await storage.createNotification(config);
    await storage.listNotifications();
    await storage.getNotification('7');
    await storage.deleteNotification('7');
    await storage.createManagedFolder('folder/');
    await storage.getManagedFolder('folder/');
    await storage.listManagedFolders();
    await storage.deleteManagedFolder('folder/');
    await storage.getManagedFolderIamPolicy('folder/');
    await storage.setManagedFolderIamPolicy('folder/', policy);
    await storage.testManagedFolderIamPermissions('folder/', [
        'storage.objects.get'
    ]);
    await storage.createHmacKey(account.client_email);
    await storage.listHmacKeys();
    await storage.getHmacKey('key');
    await storage.updateHmacKey('key', 'INACTIVE', 'etag');
    await storage.deleteHmacKey('key');
    await storage.listAcl(target);
    await storage.getAcl(target, entry.entity);
    await storage.createAcl(target, entry);
    await storage.updateAcl(target, entry);
    await storage.deleteAcl(target, entry.entity);
    const operations = vi
        .mocked(specialStorageRequest)
        .mock.calls.map(([bucket, project, token, operation, transport]) => {
            expect([bucket, project, token, transport]).toEqual([
                'bucket',
                'project',
                'access',
                fetch
            ]);
            return operation;
        });
    expect(operations).toEqual([
        { kind: 'notificationCreate', config },
        { kind: 'notificationList' },
        { kind: 'notificationGet', id: '7' },
        { kind: 'notificationDelete', id: '7' },
        { kind: 'folderCreate', name: 'folder/' },
        { kind: 'folderGet', name: 'folder/', options: {} },
        { kind: 'folderList', options: {} },
        { kind: 'folderDelete', name: 'folder/', options: {} },
        { kind: 'folderGetIam', name: 'folder/' },
        { kind: 'folderSetIam', name: 'folder/', policy },
        {
            kind: 'folderTestIam',
            name: 'folder/',
            permissions: ['storage.objects.get']
        },
        { kind: 'hmacCreate', serviceAccountEmail: account.client_email },
        { kind: 'hmacList', options: {} },
        { kind: 'hmacGet', accessId: 'key' },
        {
            kind: 'hmacUpdate',
            accessId: 'key',
            state: 'INACTIVE',
            etag: 'etag'
        },
        { kind: 'hmacDelete', accessId: 'key' },
        { kind: 'aclList', target },
        { kind: 'aclGet', target, entity: entry.entity },
        { kind: 'aclCreate', target, entry },
        { kind: 'aclUpdate', target, entry },
        { kind: 'aclDelete', target, entity: entry.entity }
    ]);
});

it('validates specialized calls before OAuth and normalizes endpoint failures', async () => {
    const storage = new Storage(account, { bucketName: 'bucket', fetch });
    const { error: invalid } = await storage.createManagedFolder('invalid');
    expect(invalid?.code).toBe('storage/invalid-argument');
    expect(getToken).not.toHaveBeenCalled();
    vi.mocked(specialStorageRequest).mockRejectedValue(new Error('network'));
    const { error } = await storage.listNotifications();
    expect(error).toBeInstanceOf(Error);
    vi.mocked(getToken).mockResolvedValue({
        error: new Error('oauth'),
        data: null
    });
    const { error: oauthError } = await storage.listHmacKeys();
    expect(oauthError?.message).toBe('oauth');
    expect(specialStorageRequest).toHaveBeenCalledOnce();
});

it('coordinates streams, version reads, resumable creation, compose and restore', async () => {
    const storage = new Storage(account, { bucketName: 'bucket', fetch });
    const response = new Response('stream');
    vi.mocked(storageRequest)
        .mockResolvedValueOnce(response)
        .mockResolvedValueOnce('session')
        .mockResolvedValueOnce(undefined)
        .mockResolvedValueOnce(undefined)
        .mockResolvedValueOnce(undefined)
        .mockResolvedValueOnce(undefined);
    const streamed = await storage.downloadStream('file', {
        start: 2,
        generation: '7'
    });
    const created = await storage.createResumableUpload('file', { size: 3 });
    await storage.compose('joined', [{ name: 'a' }]);
    await storage.restore('file', { generation: '7' });
    await storage.getMetadata('file', { generation: '7' });
    await storage.download('file', { generation: '7' });
    expect(streamed).toEqual({ error: null, data: response });
    expect(created).toEqual({ error: null, data: 'session' });
    expect(vi.mocked(storageRequest).mock.calls.map((call) => call[2])).toEqual(
        [
            {
                kind: 'stream',
                name: 'file',
                options: { start: 2, generation: '7' }
            },
            { kind: 'resumable', name: 'file', options: { size: 3 } },
            {
                kind: 'compose',
                name: 'joined',
                sources: [{ name: 'a' }],
                options: {}
            },
            { kind: 'restore', name: 'file', options: { generation: '7' } },
            { kind: 'metadata', name: 'file', options: { generation: '7' } },
            { kind: 'download', name: 'file', options: { generation: '7' } }
        ]
    );
});

it('performs resumable session operations without requiring OAuth or a configured bucket', async () => {
    const storage = new Storage(account, { fetch });
    vi.mocked(resumableRequest)
        .mockResolvedValueOnce({ complete: false, nextOffset: 262144 })
        .mockResolvedValueOnce({ complete: false, nextOffset: 262144 })
        .mockResolvedValueOnce(undefined);
    const chunk = await storage.uploadChunk('session', 'abc', {
        offset: 262144,
        totalSize: 262147
    });
    const status = await storage.getUploadStatus('session', 262147);
    const cancel = await storage.cancelUpload('session');
    expect(chunk).toEqual({
        error: null,
        data: { complete: false, nextOffset: 262144 }
    });
    expect(status).toEqual(chunk);
    expect(cancel).toEqual({ error: null, data: undefined });
    expect(resumableRequest).toHaveBeenNthCalledWith(
        1,
        'session',
        {
            kind: 'chunk',
            body: 'abc',
            options: { offset: 262144, totalSize: 262147 }
        },
        fetch
    );
    expect(resumableRequest).toHaveBeenNthCalledWith(
        2,
        'session',
        { kind: 'status', totalSize: 262147 },
        fetch
    );
    expect(resumableRequest).toHaveBeenNthCalledWith(
        3,
        'session',
        { kind: 'cancel' },
        fetch
    );
    expect(getToken).not.toHaveBeenCalled();
});

it('normalizes session errors', async () => {
    vi.mocked(resumableRequest).mockRejectedValue(new Error('offline'));
    const { error, data } = await new Storage(account).getUploadStatus(
        'session'
    );
    expect(error?.code).toBe('storage/internal-error');
    expect(data).toBeNull();
});

it('coordinates every bucket and IAM method', async () => {
    const storage = new Storage(account, { bucketName: 'bucket', fetch });
    vi.mocked(bucketRequest).mockResolvedValue({
        name: 'bucket',
        metageneration: '1'
    });
    const { error, data } = await storage.getBucketMetadata();
    expect(error).toBeNull();
    expect(data?.name).toBe('bucket');
    await storage.updateBucketMetadata(
        { cors: [] },
        { ifMetagenerationMatch: '1' }
    );
    await storage.createBucket({ location: 'US' });
    await storage.deleteBucket();
    await storage.listBuckets({ prefix: 'test' });
    await storage.getIamPolicy();
    await storage.setIamPolicy({ bindings: [], etag: 'e' });
    await storage.testIamPermissions(['storage.objects.get']);
    expect(vi.mocked(bucketRequest).mock.calls.map((call) => call[3])).toEqual([
        { kind: 'get', options: {} },
        {
            kind: 'update',
            metadata: { cors: [] },
            options: { ifMetagenerationMatch: '1' }
        },
        { kind: 'create', metadata: { location: 'US' } },
        { kind: 'delete', options: {} },
        { kind: 'list', options: { prefix: 'test' } },
        { kind: 'getIam' },
        { kind: 'setIam', policy: { bindings: [], etag: 'e' } },
        { kind: 'testIam', permissions: ['storage.objects.get'] }
    ]);
    expect(bucketRequest).toHaveBeenCalledWith(
        'bucket',
        'project',
        'access',
        expect.any(Object),
        fetch
    );
});

it('validates admin inputs and preserves authentication and endpoint failures', async () => {
    const storage = new Storage(account, { bucketName: 'bucket' });
    const invalid = await storage.updateBucketMetadata({});
    expect(invalid).toMatchObject({
        error: { code: 'storage/invalid-argument' },
        data: null
    });
    expect(getToken).not.toHaveBeenCalled();
    const failure = new FirebaseEdgeError({
        code: 'google/token-error',
        message: 'failed'
    });
    vi.mocked(getToken).mockResolvedValueOnce({ error: failure, data: null });
    const unauthorized = await storage.getIamPolicy();
    expect(unauthorized).toEqual({ error: failure, data: null });
    expect(bucketRequest).not.toHaveBeenCalled();
    vi.mocked(bucketRequest).mockRejectedValueOnce(new Error('offline'));
    const failed = await storage.listBuckets();
    expect(failed).toMatchObject({
        error: { code: 'storage/internal-error' },
        data: null
    });
});

it('deletes batches with bounded concurrency, stable ordering and per-file failures', async () => {
    let active = 0;
    let maximum = 0;
    const denied = new FirebaseEdgeError({
        code: 'storage/permission-denied',
        message: 'denied'
    });
    vi.mocked(storageRequest).mockImplementation(
        async (_bucket, _token, operation) => {
            active++;
            maximum = Math.max(maximum, active);
            await new Promise((resolve) => setTimeout(resolve, 5));
            active--;
            if ('name' in operation && operation.name === 'b') {
                throw denied;
            }
            if ('name' in operation && operation.name === 'missing') {
                throw new FirebaseEdgeError({
                    code: 'storage/object-not-found',
                    message: 'missing'
                });
            }
            return undefined;
        }
    );
    const storage = new Storage(account, { bucketName: 'bucket' });
    const { error, data } = await storage.deleteFiles(
        ['a', { name: 'b', generation: '7' }, 'c', 'missing'],
        { concurrency: 2, ignoreNotFound: true }
    );
    expect(error).toBeNull();
    expect(maximum).toBe(2);
    expect(data?.results).toEqual([
        { name: 'a', error: null },
        { name: 'b', generation: '7', error: denied },
        { name: 'c', error: null },
        { name: 'missing', error: null }
    ]);
    expect(storageRequest).toHaveBeenCalledWith(
        'bucket',
        'access',
        { kind: 'delete', name: 'b', options: { generation: '7' } },
        globalThis.fetch
    );
    const { data: missing } = await storage.deleteFiles(['missing']);
    expect(missing?.results[0]?.error?.code).toBe('storage/object-not-found');
});

it('validates an entire batch before deleting anything and supports empty batches', async () => {
    const storage = new Storage(account, { bucketName: 'bucket' });
    for (const targets of [
        ['valid', ''],
        [null],
        [{ name: 'valid', generation: 'bad' }]
    ]) {
        const { error } = await storage.deleteFiles(targets as never);
        expect(error?.code).toBe('storage/invalid-argument');
    }
    for (const options of [
        null,
        { concurrency: 0 },
        { concurrency: 33 },
        { ignoreNotFound: 'true' }
    ]) {
        const { error } = await storage.deleteFiles(['file'], options as never);
        expect(error?.code).toBe('storage/invalid-argument');
    }
    const empty = await storage.deleteFiles([]);
    expect(empty).toEqual({ error: null, data: { results: [] } });
    expect(getToken).not.toHaveBeenCalled();
});

it('moves a selected version and never deletes a newer generation', async () => {
    const source = {
        name: 'file',
        bucket: 'bucket',
        generation: '7',
        size: '2'
    };
    const copied = { ...source, name: 'copy', generation: '9' };
    vi.mocked(storageRequest)
        .mockResolvedValueOnce(source)
        .mockResolvedValueOnce(copied)
        .mockResolvedValueOnce(undefined);
    const { error } = await new Storage(account, { bucketName: 'bucket' }).move(
        'file',
        'copy',
        { sourceGeneration: '7' }
    );
    expect(error).toBeNull();
    expect(vi.mocked(storageRequest).mock.calls[0]![2]).toEqual({
        kind: 'metadata',
        name: 'file',
        options: { generation: '7' }
    });
    expect(vi.mocked(storageRequest).mock.calls[2]![2]).toEqual({
        kind: 'delete',
        name: 'file',
        options: { generation: '7', ifGenerationMatch: '7' }
    });
    const same = await new Storage(account, { bucketName: 'bucket' }).move(
        'file',
        'file',
        {
            sourceGeneration: '7'
        }
    );
    expect(same).toMatchObject({ error: { code: 'storage/invalid-argument' } });
});

it('coordinates all essential methods and forwards typed results', async () => {
    const storage = new Storage(account, { bucketName: 'bucket', fetch });
    const metadata = {
        name: 'file',
        bucket: 'bucket',
        size: '3',
        generation: '1'
    };
    vi.mocked(storageRequest)
        .mockResolvedValueOnce(metadata)
        .mockResolvedValueOnce(new Uint8Array([0, 255]))
        .mockResolvedValueOnce(metadata)
        .mockResolvedValueOnce(undefined)
        .mockResolvedValueOnce({ files: [], prefixes: [] });
    const upload = await storage.upload('file', 'abc', {
        contentType: 'text/plain'
    });
    const download = await storage.download('file');
    const info = await storage.getMetadata('file');
    const removed = await storage.delete('file', { ifGenerationMatch: '1' });
    const listed = await storage.listFiles({ prefix: 'folder/' });
    expect(upload).toEqual({ error: null, data: metadata });
    expect(download).toEqual({ error: null, data: new Uint8Array([0, 255]) });
    expect(info).toEqual(upload);
    expect(removed).toEqual({ error: null, data: undefined });
    expect(listed).toEqual({ error: null, data: { files: [], prefixes: [] } });
    expect(vi.mocked(storageRequest).mock.calls.map((call) => call[2])).toEqual(
        [
            {
                kind: 'upload',
                name: 'file',
                body: 'abc',
                options: { contentType: 'text/plain' }
            },
            { kind: 'download', name: 'file' },
            { kind: 'metadata', name: 'file' },
            {
                kind: 'delete',
                name: 'file',
                options: { ifGenerationMatch: '1' }
            },
            { kind: 'list', options: { prefix: 'folder/' } }
        ]
    );
    expect(storageRequest).toHaveBeenCalledWith(
        'bucket',
        'access',
        expect.any(Object),
        fetch
    );
    expect(getToken).toHaveBeenCalledWith(account, fetch);
});

it('reuses cached credentials with a separate cache key and expiry margin', async () => {
    const cache = {
        getCache: vi.fn().mockReturnValueOnce(undefined).mockReturnValue(oauth),
        setCache: vi.fn()
    };
    const storage = new Storage(account, {
        bucketName: 'bucket',
        fetch,
        cache,
        cacheName: 'custom'
    });
    await storage.listFiles();
    await storage.listFiles();
    expect(getToken).toHaveBeenCalledTimes(1);
    expect(cache.setCache).toHaveBeenCalledWith(
        'custom:storage:service@example.com',
        oauth,
        3540000
    );
});

it.each([0, 60, NaN])(
    'does not cache unusable token lifetimes (%s)',
    async (expires_in) => {
        vi.mocked(getToken).mockResolvedValue({
            error: null,
            data: { ...oauth, expires_in }
        });
        const cache = { getCache: vi.fn(), setCache: vi.fn() };
        await new Storage(account, {
            bucketName: 'bucket',
            fetch,
            cache
        }).listFiles();
        expect(cache.setCache).not.toHaveBeenCalled();
    }
);

it('returns authentication failures without requesting storage', async () => {
    const failure = new FirebaseEdgeError({
        code: 'google/token-error',
        message: 'failed'
    });
    vi.mocked(getToken).mockResolvedValue({ error: failure, data: null });
    const { error, data } = await new Storage(account, {
        bucketName: 'bucket'
    }).download('file');
    expect(error).toBe(failure);
    expect(data).toBeNull();
    expect(storageRequest).not.toHaveBeenCalled();
});

it('preserves endpoint errors and normalizes thrown failures', async () => {
    const failure = new FirebaseEdgeError({
        code: 'storage/object-not-found',
        message: 'missing'
    });
    vi.mocked(storageRequest)
        .mockRejectedValueOnce(failure)
        .mockRejectedValueOnce(new Error('offline'));
    const storage = new Storage(account, { bucketName: 'bucket' });
    const { error } = await storage.getMetadata('file');
    expect(error).toBe(failure);
    const { error: networkError, data } = await storage.download('file');
    expect(networkError?.code).toBe('storage/internal-error');
    expect(networkError?.cause).toEqual(new Error('offline'));
    expect(data).toBeNull();
});

it('normalizes cache failures', async () => {
    const cache = {
        getCache: vi.fn().mockRejectedValue('offline'),
        setCache: vi.fn()
    };
    const { error } = await new Storage(account, {
        bucketName: 'bucket',
        fetch,
        cache
    }).listFiles();
    expect(error?.code).toBe('storage/internal-error');
    expect(storageRequest).not.toHaveBeenCalled();
});

it('allows construction without a bucket but rejects operations before auth', async () => {
    const storage = new Storage(account);
    const { error } = await storage.listFiles();
    expect(error?.code).toBe('storage/invalid-argument');
    expect(getToken).not.toHaveBeenCalled();
});

it('validates each public operation before authentication', async () => {
    const storage = new Storage(account, { bucketName: 'bucket' });
    const results = await Promise.all([
        storage.upload('', ''),
        storage.download(''),
        storage.getMetadata(''),
        storage.delete(''),
        storage.listFiles({ maxResults: 0 })
    ]);
    for (const { error, data } of results) {
        expect(error?.code).toBe('storage/invalid-argument');
        expect(data).toBeNull();
    }
    expect(getToken).not.toHaveBeenCalled();
});

it('signs URLs locally without OAuth or storage requests', async () => {
    vi.mocked(signStorageUrl).mockResolvedValue('https://signed.example/file');
    const options = {
        action: 'write',
        expiresInSeconds: 60,
        contentType: 'text/plain'
    } as const;
    const { error, data } = await new Storage(account, {
        bucketName: 'bucket'
    }).getSignedUrl('file', options);
    expect(error).toBeNull();
    expect(data).toBe('https://signed.example/file');
    expect(signStorageUrl).toHaveBeenCalledWith(
        account,
        'bucket',
        'file',
        options
    );
    expect(getToken).not.toHaveBeenCalled();
    expect(storageRequest).not.toHaveBeenCalled();
});

it.each([
    new FirebaseEdgeError({
        code: 'storage/invalid-argument',
        message: 'bad options'
    }),
    new Error('bad key')
])('normalizes signing failures', async (failure) => {
    vi.mocked(signStorageUrl).mockRejectedValue(failure);
    const { error, data } = await new Storage(account, {
        bucketName: 'bucket'
    }).getSignedUrl('file', { action: 'read' });
    expect(data).toBeNull();
    expect(error?.code).toBe(
        failure instanceof FirebaseEdgeError
            ? failure.code
            : 'storage/internal-error'
    );
});

it('coordinates metadata patches and copies', async () => {
    const storage = new Storage(account, { bucketName: 'bucket', fetch });
    const metadata = {
        name: 'file',
        bucket: 'bucket',
        generation: '1',
        size: '2'
    };
    vi.mocked(storageRequest).mockResolvedValue(metadata);
    const patch = {
        cacheControl: 'public, max-age=60',
        metadata: { tag: 'value', removed: null }
    };
    const updated = await storage.updateMetadata('file', patch, {
        ifMetagenerationMatch: '2'
    });
    const copied = await storage.copy('file', 'copy', {
        destinationBucket: 'other',
        ifGenerationMatch: '0'
    });
    expect(updated).toEqual({ error: null, data: metadata });
    expect(copied).toEqual(updated);
    expect(storageRequest).toHaveBeenNthCalledWith(
        1,
        'bucket',
        'access',
        {
            kind: 'updateMetadata',
            name: 'file',
            metadata: patch,
            options: { ifMetagenerationMatch: '2' }
        },
        fetch
    );
    expect(storageRequest).toHaveBeenNthCalledWith(
        2,
        'bucket',
        'access',
        {
            kind: 'copy',
            name: 'file',
            destination: 'copy',
            options: { destinationBucket: 'other', ifGenerationMatch: '0' }
        },
        fetch
    );
});

it('exists returns false only for missing objects and preserves other errors', async () => {
    const denied = new FirebaseEdgeError({
        code: 'storage/permission-denied',
        message: 'denied'
    });
    vi.mocked(storageRequest)
        .mockResolvedValueOnce({
            name: 'file',
            bucket: 'bucket',
            generation: '1',
            size: '2'
        })
        .mockRejectedValueOnce(
            new FirebaseEdgeError({
                code: 'storage/object-not-found',
                message: 'missing'
            })
        )
        .mockRejectedValueOnce(denied);
    const storage = new Storage(account, { bucketName: 'bucket' });
    const found = await storage.exists('file');
    const missing = await storage.exists('missing');
    const forbidden = await storage.exists('forbidden');
    expect(found).toEqual({ error: null, data: true });
    expect(missing).toEqual({ error: null, data: false });
    expect(forbidden).toEqual({ error: denied, data: null });
});

it.each([
    {},
    {
        destinationBucket: 'other',
        ifGenerationMatch: '0',
        ifSourceGenerationMatch: '7'
    }
])('moves with source generation guards (%j)', async (options) => {
    const source = {
        name: 'file',
        bucket: 'bucket',
        generation: '7',
        size: '2'
    };
    const copied = {
        ...source,
        name: 'copy',
        bucket: options.destinationBucket ?? 'bucket',
        generation: '9'
    };
    vi.mocked(storageRequest)
        .mockResolvedValueOnce(source)
        .mockResolvedValueOnce(copied)
        .mockResolvedValueOnce(undefined);
    const { error, data } = await new Storage(account, {
        bucketName: 'bucket',
        fetch
    }).move('file', 'copy', options);
    expect(error).toBeNull();
    expect(data).toEqual(copied);
    expect(vi.mocked(storageRequest).mock.calls.map((call) => call[2])).toEqual(
        [
            { kind: 'metadata', name: 'file' },
            {
                kind: 'copy',
                name: 'file',
                destination: 'copy',
                options: { ...options, ifSourceGenerationMatch: '7' }
            },
            {
                kind: 'delete',
                name: 'file',
                options: { ifGenerationMatch: '7' }
            }
        ]
    );
});

it('reports partial moves with the surviving destination and original failure', async () => {
    const source = {
        name: 'file',
        bucket: 'bucket',
        generation: '7',
        size: '2'
    };
    const copied = {
        ...source,
        name: 'copy',
        bucket: 'other',
        generation: '9'
    };
    const failure = new FirebaseEdgeError({
        code: 'storage/precondition-failed',
        message: 'source changed'
    });
    vi.mocked(storageRequest)
        .mockResolvedValueOnce(source)
        .mockResolvedValueOnce(copied)
        .mockRejectedValueOnce(failure);
    const { error, data } = await new Storage(account, {
        bucketName: 'bucket'
    }).move('file', 'copy', { destinationBucket: 'other' });
    expect(data).toBeNull();
    expect(error).toMatchObject({
        code: 'storage/move-incomplete',
        cause: failure,
        context: {
            sourceBucket: 'bucket',
            sourceName: 'file',
            sourceGeneration: '7',
            destinationBucket: 'other',
            destinationName: 'copy',
            destinationGeneration: '9'
        }
    });
    expect(storageRequest).toHaveBeenCalledTimes(3);
});

it.each(['metadata', 'copy'] as const)(
    'does not delete after a failed %s step',
    async (step) => {
        const failure = new FirebaseEdgeError({
            code: 'storage/permission-denied',
            message: 'denied'
        });
        if (step === 'copy') {
            vi.mocked(storageRequest).mockResolvedValueOnce({
                name: 'file',
                bucket: 'bucket',
                generation: '7',
                size: '2'
            });
        }
        vi.mocked(storageRequest).mockRejectedValueOnce(failure);
        const { error } = await new Storage(account, {
            bucketName: 'bucket'
        }).move('file', 'copy');
        expect(error).toBe(failure);
        expect(
            vi
                .mocked(storageRequest)
                .mock.calls.some((call) => call[2].kind === 'delete')
        ).toBe(false);
    }
);

it('rejects a source generation mismatch before copying', async () => {
    vi.mocked(storageRequest).mockResolvedValueOnce({
        name: 'file',
        bucket: 'bucket',
        generation: '7',
        size: '2'
    });
    const { error } = await new Storage(account, { bucketName: 'bucket' }).move(
        'file',
        'copy',
        { ifSourceGenerationMatch: '6' }
    );
    expect(error?.code).toBe('storage/precondition-failed');
    expect(storageRequest).toHaveBeenCalledTimes(1);
});

it('validates new operations before authentication, including same-object moves', async () => {
    const storage = new Storage(account, { bucketName: 'bucket' });
    const results = await Promise.all([
        storage.exists(''),
        storage.updateMetadata('file', {}),
        storage.copy('file', ''),
        storage.move('file', 'file'),
        storage.move('file', 'copy', null as never),
        storage.copy('file', 'copy', { destinationBucket: 'gs://bad' })
    ]);
    for (const { error, data } of results) {
        expect(error?.code).toBe('storage/invalid-argument');
        expect(data).toBeNull();
    }
    expect(getToken).not.toHaveBeenCalled();
});
