import { expect, it, vi } from 'vitest';
import { FirebaseEdgeError } from '../auth/errors.js';
import { calculateStorageCrc32c, StorageCrc32c } from './storage-checksum.js';
import {
    uploadStorageStream,
    type StorageUploadTransport
} from './storage-upload-stream.js';

it('returns a partial checkpoint and resumes it to a verified final object', async () => {
    const api = transport();
    const bytes = new Uint8Array(262144).fill(42);
    const generator = vi.fn(() => new StorageCrc32c());
    api.uploadChunk.mockResolvedValueOnce({
        error: null,
        data: { complete: false, nextOffset: bytes.length }
    });
    const checkpoint = await uploadStorageStream(api, 'file', bytes, {
        isPartialUpload: true,
        chunkSize: bytes.length,
        crc32cGenerator: generator
    });
    const crc32c = await calculateStorageCrc32c(bytes);
    expect(checkpoint).toEqual({
        complete: false,
        sessionUri: session,
        nextOffset: bytes.length,
        crc32c
    });
    expect(api.uploadChunk).toHaveBeenCalledExactlyOnceWith(session, bytes, {
        offset: 0,
        totalSize: undefined
    });
    expect(api.createResumableUpload).toHaveBeenCalledWith('file', {
        size: undefined
    });
    const expected = new StorageCrc32c(crc32c);
    expected.update(new TextEncoder().encode('tail'));
    const finalMetadata = {
        ...metadata,
        size: String(bytes.length + 4),
        crc32c: expected.digest()
    };
    api.getUploadStatus.mockResolvedValue({
        error: null,
        data: { complete: false, nextOffset: bytes.length }
    });
    api.uploadChunk.mockResolvedValue({
        error: null,
        data: { complete: true, metadata: finalMetadata }
    });
    await expect(
        uploadStorageStream(api, 'file', 'tail', {
            sessionUri: checkpoint.sessionUri,
            offset: checkpoint.nextOffset,
            resumeCRC32C: checkpoint.crc32c,
            crc32cGenerator: generator
        })
    ).resolves.toEqual(finalMetadata);
    expect(generator).toHaveBeenCalledTimes(2);
});

it('recovers partial acknowledgements without finalizing and omits an unknown prefix checksum', async () => {
    const api = transport();
    const bytes = new Uint8Array(262144);
    api.getUploadStatus
        .mockResolvedValueOnce({
            error: null,
            data: { complete: false, nextOffset: bytes.length }
        })
        .mockResolvedValue({
            error: null,
            data: { complete: false, nextOffset: bytes.length * 2 }
        });
    api.uploadChunk.mockResolvedValue({
        error: new FirebaseEdgeError(
            { code: 'storage/network-error', message: 'lost' },
            { cause: new TypeError('lost') }
        ),
        data: null
    });
    const onProgress = vi.fn();
    const checkpoint = await uploadStorageStream(api, 'file', bytes, {
        isPartialUpload: true,
        chunkSize: bytes.length,
        sessionUri: session,
        offset: bytes.length,
        verifyChecksum: false,
        onProgress
    });
    expect(checkpoint).toEqual({
        complete: false,
        sessionUri: session,
        nextOffset: bytes.length * 2
    });
    expect(onProgress).toHaveBeenCalledWith({
        bytesTransferred: bytes.length * 2,
        totalBytes: undefined,
        complete: false
    });
});

it('rejects empty, unaligned, finalized and contradictory partial uploads', async () => {
    const api = transport();
    for (const [input, options] of [
        ['', { chunkSize: 262144 }],
        ['abc', { chunkSize: 262144 }],
        [new Uint8Array(262144), {}],
        [new Uint8Array(262144), { chunkSize: 262144, md5Hash: 'auto' }],
        [new Uint8Array(262144), { chunkSize: 262144, size: 262144 }]
    ] as const) {
        await expect(
            uploadStorageStream(api, 'file', input, {
                ...options,
                isPartialUpload: true
            })
        ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    }
    expect(api.createResumableUpload).not.toHaveBeenCalled();
    await expect(
        uploadStorageStream(api, 'file', new Blob(['abc']).stream(), {
            isPartialUpload: true,
            chunkSize: 262144
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    expect(api.uploadChunk).not.toHaveBeenCalled();
    api.getUploadStatus.mockResolvedValue({
        error: null,
        data: { complete: true, metadata }
    });
    await expect(
        uploadStorageStream(api, 'file', new Uint8Array(262144), {
            isPartialUpload: true,
            chunkSize: 262144,
            sessionUri: session
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    await expect(
        uploadStorageStream(api, 'file', new Uint8Array(262144), {
            isPartialUpload: true,
            chunkSize: 262144
        })
    ).rejects.toMatchObject({ code: 'storage/internal-error' });
});

it('resumes sliced input at an explicit offset using the preceding CRC32C', async () => {
    const api = transport();
    const preceding = await calculateStorageCrc32c('a');
    api.getUploadStatus.mockResolvedValue({
        error: null,
        data: { complete: false, nextOffset: 1 }
    });
    const data = await uploadStorageStream(api, 'file', 'bc', {
        sessionUri: session,
        offset: 1,
        resumeCRC32C: preceding
    });
    expect(data).toEqual(metadata);
    expect(api.uploadChunk).toHaveBeenCalledWith(
        session,
        new TextEncoder().encode('bc'),
        { offset: 1, totalSize: 3, crc32c: metadata.crc32c }
    );
    await expect(
        uploadStorageStream(api, 'file', 'bc', {
            sessionUri: session,
            offset: 1
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    await expect(
        uploadStorageStream(api, 'file', 'bc', {
            sessionUri: session,
            offset: 1,
            md5Hash: 'auto',
            verifyChecksum: false
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    api.getUploadStatus.mockResolvedValue({
        error: null,
        data: { complete: false, nextOffset: 0 }
    });
    await expect(
        uploadStorageStream(api, 'file', 'bc', {
            sessionUri: session,
            offset: 1,
            resumeCRC32C: preceding
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
});

const session =
    'https://storage.googleapis.com/upload/storage/v1/b/bucket/o?upload_id=test';
const metadata = {
    name: 'file',
    bucket: 'bucket',
    generation: '1',
    size: '3',
    crc32c: 'Nks/tw=='
};

it('allows explicitly disabling automatic completion checksum verification', async () => {
    const api = transport();
    api.uploadChunk.mockResolvedValue({
        error: null,
        data: { complete: true, metadata: { ...metadata, crc32c: undefined } }
    });
    const data = await uploadStorageStream(api, 'file', 'abc', {
        verifyChecksum: false
    });
    expect(data.name).toBe('file');
    expect(api.uploadChunk).toHaveBeenCalledWith(
        session,
        new TextEncoder().encode('abc'),
        { offset: 0, totalSize: 3, crc32c: undefined }
    );
    await expect(
        uploadStorageStream(api, 'file', 'abc', {
            verifyChecksum: 'false' as never
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
});

it('computes incremental MD5 for final chunks and verifies completed resumptions', async () => {
    const api = transport();
    const md5Hash = 'kAFQmDzST7DWlj99KOF/cg==';
    api.uploadChunk.mockResolvedValue({
        error: null,
        data: { complete: true, metadata: { ...metadata, md5Hash } }
    });
    const data = await uploadStorageStream(api, 'file', 'abc', {
        md5Hash: 'auto',
        verifyChecksum: false
    });
    expect(data.md5Hash).toBe(md5Hash);
    expect(api.uploadChunk).toHaveBeenCalledWith(
        session,
        new TextEncoder().encode('abc'),
        { offset: 0, totalSize: 3, md5Hash }
    );
    api.getUploadStatus.mockResolvedValue({
        error: null,
        data: { complete: true, metadata: { ...metadata, md5Hash } }
    });
    await expect(
        uploadStorageStream(api, 'file', 'abc', {
            sessionUri: session,
            md5Hash: 'auto'
        })
    ).resolves.toMatchObject({ md5Hash });
    await expect(
        uploadStorageStream(api, 'file', 'xyz', {
            sessionUri: session,
            md5Hash: 'auto',
            verifyChecksum: false
        })
    ).rejects.toMatchObject({ code: 'storage/checksum-mismatch' });
    await expect(
        uploadStorageStream(api, 'file', 'abc', { md5Hash: 'bad' })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
});
function transport(): StorageUploadTransport & {
    uploadChunk: ReturnType<typeof vi.fn>;
    getUploadStatus: ReturnType<typeof vi.fn>;
    createResumableUpload: ReturnType<typeof vi.fn>;
} {
    return {
        createResumableUpload: vi
            .fn()
            .mockResolvedValue({ error: null, data: session }),
        uploadChunk: vi.fn().mockResolvedValue({
            error: null,
            data: { complete: true, metadata }
        }),
        getUploadStatus: vi.fn().mockResolvedValue({
            error: null,
            data: { complete: false, nextOffset: 0 }
        })
    };
}
it('uploads small input with inferred length, incremental CRC32C and callbacks', async () => {
    const api = transport();
    const onSession = vi.fn();
    const onProgress = vi.fn();
    const data = await uploadStorageStream(api, 'file', 'abc', {
        onSession,
        onProgress
    });
    expect(data).toEqual(metadata);
    expect(onSession).toHaveBeenCalledWith(session);
    expect(api.createResumableUpload).toHaveBeenCalledWith('file', { size: 3 });
    expect(api.uploadChunk).toHaveBeenCalledWith(
        session,
        new TextEncoder().encode('abc'),
        { offset: 0, totalSize: 3, crc32c: metadata.crc32c }
    );
    expect(onProgress).toHaveBeenCalledWith({
        bytesTransferred: 3,
        totalBytes: 3,
        complete: true
    });
});
it('splits oversized stream chunks with one-chunk lookahead and resumes a partial acknowledged upload', async () => {
    const bytes = new Uint8Array(524291).fill(65);
    const crc32c = await calculateStorageCrc32c(bytes);
    const api = transport();
    api.getUploadStatus.mockResolvedValue({
        error: null,
        data: { complete: false, nextOffset: 262144 }
    });
    api.uploadChunk
        .mockResolvedValueOnce({
            error: null,
            data: { complete: false, nextOffset: 524288 }
        })
        .mockResolvedValueOnce({
            error: null,
            data: {
                complete: true,
                metadata: { ...metadata, size: String(bytes.length), crc32c }
            }
        });
    const stream = new ReadableStream<Uint8Array>({
        start(controller) {
            controller.enqueue(bytes);
            controller.close();
        }
    });
    const data = await uploadStorageStream(api, 'file', stream, {
        sessionUri: session,
        chunkSize: 262144
    });
    expect(data.crc32c).toBe(crc32c);
    expect(api.createResumableUpload).not.toHaveBeenCalled();
    expect(
        api.uploadChunk.mock.calls.map(([, body, options]) => [
            body.length,
            options.offset
        ])
    ).toEqual([
        [262144, 262144],
        [3, 524288]
    ]);
});
it('probes a lost final acknowledgement and returns verified metadata without resending', async () => {
    const api = transport();
    api.uploadChunk.mockResolvedValue({
        error: new FirebaseEdgeError(
            { code: 'storage/internal-error', message: 'network' },
            { cause: new TypeError('network') }
        ),
        data: null
    });
    api.getUploadStatus.mockResolvedValue({
        error: null,
        data: { complete: true, metadata }
    });
    const data = await uploadStorageStream(api, 'file', 'abc');
    expect(data).toEqual(metadata);
    expect(api.uploadChunk).toHaveBeenCalledOnce();
});
it('bounds stalled acknowledgements and does not retry permission failures', async () => {
    const api = transport();
    api.uploadChunk.mockResolvedValue({
        error: null,
        data: { complete: false, nextOffset: 0 }
    });
    await expect(
        uploadStorageStream(api, 'file', 'abc', { maxResumeAttempts: 1 })
    ).rejects.toMatchObject({ code: 'storage/retry-limit-exceeded' });
    expect(api.uploadChunk).toHaveBeenCalledTimes(2);
    api.uploadChunk.mockClear().mockResolvedValue({
        error: new FirebaseEdgeError({
            code: 'storage/permission-denied',
            message: 'denied'
        }),
        data: null
    });
    await expect(uploadStorageStream(api, 'file', 'abc')).rejects.toMatchObject(
        { code: 'storage/permission-denied' }
    );
    expect(api.getUploadStatus).not.toHaveBeenCalled();
});

it('replays identical persisted overlap to preserve non-final chunk alignment', async () => {
    const bytes = new Uint8Array(262147).fill(65);
    const crc32c = await calculateStorageCrc32c(bytes);
    const api = transport();
    api.uploadChunk
        .mockResolvedValueOnce({
            error: null,
            data: { complete: false, nextOffset: 131072 }
        })
        .mockResolvedValueOnce({
            error: null,
            data: { complete: false, nextOffset: 262144 }
        })
        .mockResolvedValueOnce({
            error: null,
            data: {
                complete: true,
                metadata: { ...metadata, size: String(bytes.length), crc32c }
            }
        });
    await uploadStorageStream(api, 'file', bytes, { chunkSize: 262144 });
    expect(api.uploadChunk.mock.calls[1]![1]).toEqual(bytes.slice(0, 262144));
    expect(api.uploadChunk.mock.calls[1]![2].offset).toBe(0);
});

it('verifies the supplied source even if a resumed session was already complete', async () => {
    const api = transport();
    api.getUploadStatus.mockResolvedValue({
        error: null,
        data: { complete: true, metadata }
    });
    await expect(
        uploadStorageStream(api, 'file', 'bad', { sessionUri: session })
    ).rejects.toMatchObject({ code: 'storage/checksum-mismatch' });
    expect(api.uploadChunk).not.toHaveBeenCalled();
});
it('recovers a transient HTTP failure and sends only the remaining final bytes', async () => {
    const api = transport();
    api.uploadChunk
        .mockResolvedValueOnce({
            error: new FirebaseEdgeError(
                { code: 'storage/unknown-error', message: 'unavailable' },
                { context: { status: 503 } }
            ),
            data: null
        })
        .mockResolvedValueOnce({
            error: null,
            data: { complete: true, metadata }
        });
    api.getUploadStatus.mockResolvedValue({
        error: null,
        data: { complete: false, nextOffset: 1 }
    });
    await uploadStorageStream(api, 'file', 'abc');
    expect(api.uploadChunk.mock.calls[1]![1]).toEqual(
        new TextEncoder().encode('bc')
    );
    expect(api.uploadChunk.mock.calls[1]![2].offset).toBe(1);
});
it('supports empty uploads and sessions which have already completed', async () => {
    const api = transport();
    api.uploadChunk.mockResolvedValue({
        error: null,
        data: {
            complete: true,
            metadata: { ...metadata, size: '0', crc32c: 'AAAAAA==' }
        }
    });
    const empty = await uploadStorageStream(api, 'file', '');
    expect(empty.size).toBe('0');
    api.getUploadStatus.mockResolvedValue({
        error: null,
        data: { complete: true, metadata }
    });
    const data = await uploadStorageStream(api, 'file', 'abc', {
        sessionUri: session,
        crc32c: metadata.crc32c
    });
    expect(data).toEqual(metadata);
});
it('rejects mismatching sizes, invalid chunks and corrupt final checksums', async () => {
    const api = transport();
    await expect(
        uploadStorageStream(api, 'file', 'abc', { size: 1 })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    const stream = new ReadableStream({
        start(controller) {
            controller.enqueue('bad');
            controller.close();
        }
    });
    await expect(
        uploadStorageStream(api, 'file', stream as never)
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    await expect(
        uploadStorageStream(api, 'file', 'abcd')
    ).rejects.toMatchObject({ code: 'storage/checksum-mismatch' });
});
it.each([
    { chunkSize: 1 },
    { maxResumeAttempts: -1 },
    { crc32c: 'bad' },
    { sessionUri: 'https://example.com/' },
    { onSession: 1 },
    { onProgress: 1 },
    null
])(
    'rejects invalid stream options %j before session creation',
    async (options) => {
        const api = transport();
        await expect(
            uploadStorageStream(api, 'file', 'abc', options as never)
        ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
        expect(api.createResumableUpload).not.toHaveBeenCalled();
    }
);
it('cancels the input reader on upload failure and preserves callback errors without replay', async () => {
    const api = transport();
    const cancel = vi.fn();
    const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
            controller.enqueue(new Uint8Array(262144));
        },
        cancel
    });
    api.uploadChunk.mockResolvedValue({
        error: new FirebaseEdgeError({
            code: 'storage/permission-denied',
            message: 'denied'
        }),
        data: null
    });
    await expect(
        uploadStorageStream(api, 'file', stream, { chunkSize: 262144 })
    ).rejects.toThrow();
    expect(cancel).toHaveBeenCalledOnce();
    const second = transport();
    await expect(
        uploadStorageStream(second, 'file', 'abc', {
            onProgress() {
                throw new Error('observer');
            }
        })
    ).rejects.toMatchObject({ code: 'storage/progress-callback-failed' });
    expect(second.uploadChunk).toHaveBeenCalledOnce();
});
