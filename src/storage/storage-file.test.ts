import { beforeEach, expect, it, vi } from 'vitest';
import { Storage, File, getDownloadURL } from './storage.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { StorageCrc32c } from './storage-checksum.js';

it.each(['reference', 'request', 'softDeleted'] as const)(
    'does not auto-create a missing historical object selected by %s',
    async (selection) => {
        const missing = new FirebaseEdgeError({
            code: 'storage/object-not-found',
            message: 'Missing version'
        });
        vi.spyOn(storage, 'getMetadata').mockResolvedValue({
            error: missing,
            data: null
        });
        const file = storage
            .bucket()
            .file('file', selection === 'reference' ? { generation: 12 } : {});
        const save = vi
            .spyOn(file, 'save')
            .mockResolvedValue({ error: null, data: undefined });

        const { error, data } = await file.get({
            autoCreate: true,
            ...(selection === 'request' && { generation: 12 }),
            ...(selection === 'softDeleted' && { softDeleted: true })
        });

        expect(error).toBe(missing);
        expect(data).toBeNull();
        expect(save).not.toHaveBeenCalled();
    }
);

it('preserves partial checkpoints for save and Web writable completion without fabricating metadata', async () => {
    const checkpoint = {
        complete: false as const,
        sessionUri: 'session',
        nextOffset: 262144,
        crc32c: 'AAAAAA=='
    };
    const generator = vi.fn(() => new StorageCrc32c());
    const stream = vi
        .spyOn(storage, 'uploadStream')
        .mockImplementation(async (_name, input) => {
            if (input instanceof ReadableStream) {
                await new Response(input).arrayBuffer();
            }
            return { error: null, data: checkpoint };
        });
    const file = storage.bucket().file('file', { crc32cGenerator: generator });
    const { error, data } = await file.save(new Uint8Array(262144), {
        isPartialUpload: true,
        chunkSize: 262144
    });
    expect(error).toBeNull();
    expect(data).toEqual(checkpoint);
    expect(file.metadata).toBeUndefined();
    const writable = file.createWriteStream({
        isPartialUpload: true,
        chunkSize: 262144
    });
    await new Blob([new Uint8Array(262144)]).stream().pipeTo(writable);
    await expect(writable.result).resolves.toEqual({
        error: null,
        data: checkpoint
    });
    expect(stream).toHaveBeenLastCalledWith(
        'file',
        expect.any(ReadableStream),
        expect.objectContaining({
            isPartialUpload: true,
            crc32cGenerator: generator
        })
    );
    for (const invalid of [
        { resumable: false },
        { gzip: true },
        { validation: 'md5' as const }
    ]) {
        await expect(
            file.save('abc', {
                ...invalid,
                isPartialUpload: true,
                chunkSize: 262144
            })
        ).resolves.toMatchObject({
            error: { code: 'storage/invalid-argument' }
        });
    }
    expect(stream).toHaveBeenCalledTimes(2);
});

it('forwards custom checksums, download encryption, and restore projection/preconditions', async () => {
    const generator = () => new StorageCrc32c();
    const file = storage.bucket().file('file', { crc32cGenerator: generator });
    const upload = vi
        .spyOn(storage, 'upload')
        .mockResolvedValue({ error: null, data: metadata });
    const download = vi
        .spyOn(storage, 'download')
        .mockResolvedValue({ error: null, data: new Uint8Array() });
    const restore = vi
        .spyOn(storage, 'restore')
        .mockResolvedValue({ error: null, data: metadata });
    await file.save('abc', { resumable: false });
    expect(upload).toHaveBeenCalledWith(
        'file',
        'abc',
        expect.objectContaining({ crc32cGenerator: generator })
    );
    await file.download({ encryptionKey: 'key', validation: true });
    expect(storage.scoped).toHaveBeenLastCalledWith({ encryptionKey: 'key' });
    expect(download).toHaveBeenCalledWith(
        'file',
        expect.objectContaining({
            crc32cGenerator: generator,
            verifyChecksum: true
        })
    );
    await file.restore({
        generation: 12,
        ifGenerationMatch: 0,
        projection: 'full'
    });
    expect(restore).toHaveBeenCalledWith(
        'file',
        expect.objectContaining({
            generation: '12',
            ifGenerationMatch: '0',
            projection: 'full'
        })
    );
});

const metadata = {
    name: 'file',
    bucket: 'bucket',
    generation: '12',
    size: '3',
    retentionExpirationTime: '2027-01-01T00:00:00Z'
};

it('routes MD5, boolean validation, auto gzip, progress, and URI aliases through the existing upload engine', async () => {
    const upload = vi
        .spyOn(storage, 'upload')
        .mockResolvedValue({ error: null, data: metadata });
    const stream = vi
        .spyOn(storage, 'uploadStream')
        .mockImplementation(async (_name, _input, options) => {
            await options?.onProgress?.({
                bytesTransferred: 3,
                totalBytes: 3,
                complete: true
            });
            return { error: null, data: metadata };
        });
    const file = storage.bucket().file('file');
    const onUploadProgress = vi.fn();
    await file.save('abc', {
        validation: 'md5',
        onUploadProgress,
        uri: 'session',
        private: true
    });
    expect(stream).toHaveBeenLastCalledWith(
        'file',
        'abc',
        expect.objectContaining({
            md5Hash: 'auto',
            verifyChecksum: false,
            sessionUri: 'session',
            predefinedAcl: 'private'
        })
    );
    expect(onUploadProgress).toHaveBeenCalledWith({
        bytesWritten: 3,
        contentLength: 3
    });
    await file.save('abc', { validation: 'md5', resumable: false });
    expect(upload).toHaveBeenCalledWith(
        'file',
        'abc',
        expect.objectContaining({ md5Hash: 'auto', crc32c: undefined })
    );
    await file.save('abc', {
        validation: true,
        gzip: 'auto',
        contentType: 'image/png'
    });
    expect(stream).toHaveBeenLastCalledWith(
        'file',
        'abc',
        expect.objectContaining({ verifyChecksum: true })
    );
    await file.save('abc', {
        gzip: 'auto',
        contentType: 'text/plain',
        timeout: 5000
    });
    expect(stream).toHaveBeenLastCalledWith(
        'file',
        expect.any(ReadableStream),
        expect.objectContaining({ metadata: { contentEncoding: 'gzip' } })
    );
    expect(storage.scoped).toHaveBeenCalledWith({ timeout: 5000 });
    await expect(
        file.save('abc', { validation: 'bad' as never })
    ).resolves.toMatchObject({ error: { code: 'storage/invalid-argument' } });
    await expect(
        file.save('abc', { public: true, private: true })
    ).resolves.toMatchObject({ error: { code: 'storage/invalid-argument' } });
    await expect(
        file.save('abc', { uri: 'one', sessionUri: 'two' })
    ).resolves.toMatchObject({ error: { code: 'storage/invalid-argument' } });
});

it('normalizes numeric read conditions and creates a missing file without overwriting a concurrent creator', async () => {
    const missing = new FirebaseEdgeError({
        code: 'storage/object-not-found',
        message: 'missing'
    });
    const conflict = new FirebaseEdgeError({
        code: 'storage/precondition-failed',
        message: 'created'
    });
    const get = vi
        .spyOn(storage, 'getMetadata')
        .mockResolvedValueOnce({ error: missing, data: null })
        .mockResolvedValue({ error: null, data: metadata });
    const upload = vi
        .spyOn(storage, 'uploadStream')
        .mockResolvedValue({ error: conflict, data: null });
    const file = storage.bucket().file('file');
    await expect(
        file.get({ autoCreate: true, userProject: 'billing' })
    ).resolves.toEqual({ error: null, data: file });
    expect(upload).toHaveBeenCalledWith(
        'file',
        '',
        expect.objectContaining({
            ifGenerationMatch: '0',
            userProject: 'billing'
        })
    );
    await file.getMetadata({ generation: 12, ifMetagenerationMatch: 2 });
    expect(get).toHaveBeenLastCalledWith('file', {
        generation: '12',
        ifMetagenerationMatch: '2'
    });
    await expect(file.getMetadata({ generation: -1 })).resolves.toMatchObject({
        error: { code: 'storage/invalid-argument' }
    });
});
let storage: Storage;
beforeEach(() => {
    vi.restoreAllMocks();
    storage = new Storage(
        { project_id: 'project' } as ServiceAccount,
        'bucket',
        vi.fn()
    );
    vi.spyOn(Storage.prototype, 'scoped').mockImplementation(function (
        this: Storage
    ) {
        return this;
    });
});

it('constructs references and caches metadata through get and set', async () => {
    const get = vi
        .spyOn(storage, 'getMetadata')
        .mockResolvedValue({ error: null, data: metadata });
    const update = vi
        .spyOn(storage, 'updateMetadata')
        .mockResolvedValue({ error: null, data: metadata });
    const exists = vi
        .spyOn(storage, 'exists')
        .mockResolvedValue({ error: null, data: true });
    const file = storage.bucket().file('file', {
        generation: 12,
        preconditionOpts: { ifMetagenerationMatch: 3 }
    });
    expect(file.storage).toBe(storage);
    expect(file.cloudStorageURI.toString()).toBe('gs://bucket/file');
    await expect(file.get()).resolves.toEqual({ error: null, data: file });
    await expect(file.exists()).resolves.toEqual({ error: null, data: true });
    await file.setMetadata({ contentType: 'text/plain' });
    expect(file.metadata).toBe(metadata);
    expect(get).toHaveBeenCalledWith('file', {
        generation: '12',
        ifMetagenerationMatch: '3'
    });
    expect(exists).toHaveBeenCalledWith('file', {
        generation: '12',
        ifMetagenerationMatch: '3'
    });
    expect(update).toHaveBeenCalledWith(
        'file',
        { contentType: 'text/plain' },
        { generation: '12', ifMetagenerationMatch: '3' }
    );
    await expect(file.getExpirationDate()).resolves.toEqual({
        error: null,
        data: new Date(metadata.retentionExpirationTime)
    });
    get.mockResolvedValue({
        error: null,
        data: { ...metadata, retentionExpirationTime: undefined }
    });
    await expect(file.getExpirationDate()).resolves.toMatchObject({
        error: { code: 'storage/no-expiration' },
        data: null
    });
    expect(() => storage.bucket().file('')).toThrow();
});
it('downloads bytes and rejects filesystem-specific options as result errors', async () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const download = vi
        .spyOn(storage, 'download')
        .mockResolvedValue({ error: null, data: bytes });
    const file = storage.bucket().file('file');
    await expect(file.download({ validation: 'crc32c' })).resolves.toEqual({
        error: null,
        data: bytes
    });
    expect(download).toHaveBeenCalledWith('file', { verifyChecksum: true });
    await expect(
        file.download({ destination: '/tmp/file' })
    ).resolves.toMatchObject({
        error: { code: 'storage/unsupported-operation' }
    });
    await expect(file.download({ decompress: false })).resolves.toMatchObject({
        error: { code: 'storage/unsupported-operation' }
    });
});
it('reads lazily through Web Streams, propagates errors, and forwards cancellation', async () => {
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({
        start(controller) {
            controller.enqueue(new Uint8Array([1, 2, 3]));
        },
        cancel
    });
    const download = vi
        .spyOn(storage, 'downloadStream')
        .mockResolvedValue({ error: null, data: new Response(body) });
    const file = storage.bucket().file('file');
    const stream = file.stream();
    expect(download).not.toHaveBeenCalled();
    const reader = stream.getReader();
    await expect(reader.read()).resolves.toMatchObject({
        value: new Uint8Array([1, 2, 3])
    });
    await reader.cancel('stop');
    expect(cancel).toHaveBeenCalledWith('stop');
    download.mockResolvedValue({
        error: new FirebaseEdgeError({
            code: 'storage/permission-denied',
            message: 'denied'
        }),
        data: null
    });
    await expect(
        file.createReadStream().getReader().read()
    ).rejects.toMatchObject({ code: 'storage/permission-denied' });
});
it('saves resumably by default and supports atomic multipart metadata uploads', async () => {
    const upload = vi
        .spyOn(storage, 'upload')
        .mockResolvedValue({ error: null, data: metadata });
    const uploadStream = vi
        .spyOn(storage, 'uploadStream')
        .mockResolvedValue({ error: null, data: metadata });
    const file = storage.bucket().file('file');
    await expect(
        file.save('abc', { preconditionOpts: { ifGenerationMatch: 0 } })
    ).resolves.toEqual({ error: null, data: undefined });
    expect(uploadStream).toHaveBeenCalledWith('file', 'abc', {
        ifGenerationMatch: '0',
        verifyChecksum: true
    });
    await file.upload('abc', {
        resumable: false,
        validation: false,
        metadata: { contentType: 'text/plain', metadata: { tag: 'value' } }
    });
    expect(upload).toHaveBeenCalledWith(
        'file',
        'abc',
        expect.objectContaining({
            contentType: 'text/plain',
            metadata: { contentType: 'text/plain', metadata: { tag: 'value' } },
            crc32c: undefined
        })
    );
    expect(file.metadata).toBe(metadata);
});
it('compresses uploads and supports writable stream completion', async () => {
    const uploadStream = vi
        .spyOn(storage, 'uploadStream')
        .mockImplementation(async (_name, input, options) => {
            const body =
                input instanceof ReadableStream
                    ? input
                    : new Blob([input]).stream();
            const decoded =
                options?.metadata?.contentEncoding === 'gzip'
                    ? body.pipeThrough(new DecompressionStream('gzip'))
                    : body;
            const text = await new Response(decoded).text();
            expect(text).toBe('abc');
            return { error: null, data: metadata };
        });
    const file = storage.bucket().file('file');
    await file.save('abc', { gzip: true });
    expect(() => file.createWriteStream({ highWaterMark: -1 })).toThrow(
        /highWaterMark/
    );
    const stream = file.createWriteStream({ highWaterMark: 1024 });
    const writer = stream.getWriter();
    await writer.write(new TextEncoder().encode('abc'));
    await writer.close();
    await expect(stream.result).resolves.toEqual({
        error: null,
        data: metadata
    });
    expect(uploadStream).toHaveBeenCalledTimes(2);
});
it('creates sessions and returns validation errors without throwing', async () => {
    const create = vi
        .spyOn(storage, 'createResumableUpload')
        .mockResolvedValue({ error: null, data: 'session' });
    const file = storage.bucket().file('file');
    await expect(
        file.createResumableUpload({
            preconditionOpts: { ifGenerationMatch: 0 }
        })
    ).resolves.toEqual({ error: null, data: 'session' });
    expect(create).toHaveBeenCalledWith('file', {
        ifGenerationMatch: '0',
        crc32c: undefined
    });
    await expect(
        file.createResumableUpload({ crc32c: 'auto' })
    ).resolves.toMatchObject({ error: { code: 'storage/invalid-argument' } });
    await expect(
        file.save('abc', { preconditionOpts: { ifGenerationMatch: -1 } })
    ).resolves.toMatchObject({ error: { code: 'storage/invalid-argument' } });
});

it('returns writable upload failures in result and rejects pending writes', async () => {
    const denied = new FirebaseEdgeError({
        code: 'storage/permission-denied',
        message: 'denied'
    });
    vi.spyOn(storage, 'uploadStream').mockResolvedValue({
        error: denied,
        data: null
    });
    const stream = storage.bucket().file('file').createWriteStream();
    const writer = stream.getWriter();
    await expect(writer.write(new Uint8Array([1]))).rejects.toBe(denied);
    await expect(stream.result).resolves.toEqual({ error: denied, data: null });
});

it('cancels a download body when cancellation happens during the request', async () => {
    let finish!: (value: { error: null; data: Response }) => void;
    vi.spyOn(storage, 'downloadStream').mockImplementation(
        () =>
            new Promise((resolve) => {
                finish = resolve;
            })
    );
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({ cancel });
    const reader = storage.bucket().file('file').createReadStream().getReader();
    const pending = reader.read();
    await Promise.resolve();
    await reader.cancel('cancelled');
    finish({ error: null, data: new Response(body) });
    await pending;
    await Promise.resolve();
    expect(cancel).toHaveBeenCalledWith('cancelled');
});
it('deletes with optional missing-object suppression', async () => {
    const missing = new FirebaseEdgeError({
        code: 'storage/object-not-found',
        message: 'missing'
    });
    vi.spyOn(storage, 'delete').mockResolvedValue({
        error: missing,
        data: null
    });
    const file = storage.bucket().file('file');
    await expect(file.delete()).resolves.toEqual({
        error: missing,
        data: null
    });
    await expect(file.delete({ ignoreNotFound: true })).resolves.toEqual({
        error: null,
        data: undefined
    });
});
it('copies and moves to File and gs references with generation and preconditions', async () => {
    const copy = vi
        .spyOn(storage, 'copy')
        .mockResolvedValue({ error: null, data: metadata });
    const move = vi
        .spyOn(storage, 'move')
        .mockResolvedValue({ error: null, data: metadata });
    const file = storage.bucket().file('file', { generation: 12 });
    const { error, data } = await file.copy('gs://other/folder/new', {
        preconditionOpts: { ifGenerationMatch: 0 }
    });
    expect(error).toBeNull();
    expect(data).toBeInstanceOf(File);
    expect(data?.bucket.name).toBe('other');
    expect(copy).toHaveBeenCalledWith(
        'file',
        'folder/new',
        expect.objectContaining({
            sourceGeneration: '12',
            destinationBucket: 'other',
            ifGenerationMatch: '0'
        })
    );
    await file.move('next');
    await file.rename(storage.bucket().file('renamed'));
    expect(move).toHaveBeenLastCalledWith(
        'file',
        'renamed',
        expect.objectContaining({ sourceGeneration: '12' })
    );
});
it('supports atomic moves, key rotation, storage classes and restoration', async () => {
    const action = vi
        .spyOn(storage, 'referenceAction')
        .mockResolvedValue({ error: null, data: metadata });
    const copy = vi
        .spyOn(storage, 'copy')
        .mockResolvedValue({ error: null, data: metadata });
    const restore = vi
        .spyOn(storage, 'restore')
        .mockResolvedValue({ error: null, data: metadata });
    const file = storage.bucket().file('file', { generation: '12' });
    await file.moveFileAtomic('next');
    expect(action).toHaveBeenCalledWith(
        { kind: 'file', name: 'file' },
        { kind: 'atomicMove', destination: 'next', preconditions: {} }
    );
    await expect(file.moveFileAtomic('gs://other/file')).resolves.toMatchObject(
        { error: { code: 'storage/invalid-argument' } }
    );
    await file.rotateEncryptionKey({ kmsKeyName: 'kms/key' });
    expect(copy).toHaveBeenCalledWith(
        'file',
        'file',
        expect.objectContaining({ destinationKmsKeyName: 'kms/key' })
    );
    await file.setStorageClass('NEARLINE');
    expect(copy).toHaveBeenLastCalledWith(
        'file',
        'file',
        expect.objectContaining({ metadata: { storageClass: 'NEARLINE' } })
    );
    const restored = await file.restore();
    expect(restored.data?.generation).toBe('12');
    expect(restore).toHaveBeenCalledWith('file', {
        generation: '12',
        restoreToken: undefined
    });
    await expect(storage.bucket().file('new').restore()).resolves.toMatchObject(
        { error: { code: 'storage/invalid-argument' } }
    );
    await expect(file.rotateEncryptionKey({})).resolves.toMatchObject({
        error: { code: 'storage/invalid-argument' }
    });
});
it('delegates signing, Firebase URLs, ACLs, billing, encryption and requests', async () => {
    const signing = vi
        .spyOn(storage, 'referenceSignedUrl')
        .mockResolvedValue({ error: null, data: 'signed' });
    const policies = vi
        .spyOn(storage, 'referencePostPolicy')
        .mockResolvedValue({
            error: null,
            data: { string: '', base64: '', signature: '' }
        });
    vi.spyOn(storage, 'downloadURL').mockResolvedValue({
        error: null,
        data: 'download'
    });
    const acl = vi.spyOn(storage, 'createAcl').mockResolvedValue({
        error: null,
        data: { entity: 'allUsers', role: 'READER' }
    });
    const action = vi
        .spyOn(storage, 'referenceAction')
        .mockResolvedValue({ error: null, data: {} });
    vi.spyOn(storage, 'objectIsPublic').mockResolvedValue({
        error: null,
        data: false
    });
    const request = vi
        .spyOn(storage, 'requestResource')
        .mockResolvedValue({ error: null, data: {} });
    const file = storage.bucket().file('a b', { generation: 12 });
    await file.getSignedUrl({ action: 'read', expires: Date.now() + 60000 });
    expect(signing).toHaveBeenCalledWith(
        'a b',
        expect.objectContaining({ queryParams: { generation: '12' } })
    );
    await file.generateSignedPostPolicyV2({ expires: Date.now() + 60000 });
    await file.generateSignedPostPolicyV4({ expires: Date.now() + 60000 });
    expect(policies.mock.calls.map(([, version]) => version)).toEqual([
        'v2',
        'v4'
    ]);
    await expect(getDownloadURL(file)).resolves.toEqual({
        error: null,
        data: 'download'
    });
    await expect(
        getDownloadURL(null as unknown as File)
    ).resolves.toMatchObject({ error: { code: 'storage/invalid-argument' } });
    expect(file.publicUrl()).toBe(
        'https://storage.googleapis.com/bucket/a%20b'
    );
    await file.makePublic();
    expect(acl).toHaveBeenCalledWith(
        { scope: 'object', name: 'a b', generation: '12' },
        { entity: 'allUsers', role: 'READER' }
    );
    await file.makePrivate({ strict: true });
    expect(action).toHaveBeenCalledWith(
        { kind: 'file', name: 'a b' },
        expect.objectContaining({ kind: 'makePrivate', strict: true })
    );
    await expect(file.isPublic()).resolves.toEqual({
        error: null,
        data: false
    });
    expect(file.setUserProject('billing')).toBe(file);
    expect(file.setEncryptionKey(new Uint8Array(32))).toBe(file);
    await file.request({ method: 'GET' });
    expect(request).toHaveBeenCalledWith(
        { kind: 'file', name: 'a b' },
        { method: 'GET' }
    );
});
