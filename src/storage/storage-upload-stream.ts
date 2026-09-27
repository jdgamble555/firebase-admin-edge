import { FirebaseEdgeError } from '../auth/errors.js';
import { StorageMd5 } from './storage-md5.js';
import {
    createStorageCrc32c,
    storageUploadBlob,
    validateStorageCrc32c,
    validateStorageMd5,
    verifyStorageUpload
} from './storage-checksum.js';
import type { CRC32CValidatorGenerator } from './storage-checksum.js';
import { reportStorageProgress } from './storage-progress.js';
import { validateSessionUri } from './storage-resumable.js';
import type {
    StorageUploadData,
    StorageResumableOptions,
    StorageChunkOptions,
    StorageUploadProgress,
    StorageFileMetadata,
    StorageResult,
    StorageProgressCallback
} from './storage-types.js';

export interface StorageUploadStreamOptions
    extends Omit<StorageResumableOptions, 'crc32c' | 'md5Hash'> {
    md5Hash?: string | 'auto';
    isPartialUpload?: boolean;
    crc32cGenerator?: CRC32CValidatorGenerator;
    /** The input starts at this session offset; supply the preceding CRC32C when validating. */
    offset?: number;
    resumeCRC32C?: string | number;
    /** Multiple of 256 KiB, up to 64 MiB. Defaults to 8 MiB. */
    chunkSize?: number;
    /** Recovery attempts per chunk. Defaults to 2. */
    maxResumeAttempts?: number;
    verifyChecksum?: boolean;
    sessionUri?: string;
    /** Automatic CRC32C is computed incrementally and verified on completion. */
    crc32c?: string | 'auto';
    onProgress?: StorageProgressCallback;
    onSession?: (sessionUri: string) => void | Promise<void>;
}

export interface StoragePartialUpload {
    complete: false;
    sessionUri: string;
    nextOffset: number;
    crc32c?: string;
}

/** @internal Public Storage methods supply authentication and endpoint handling. */
export interface StorageUploadTransport {
    createResumableUpload(
        name: string,
        options: StorageResumableOptions
    ): Promise<StorageResult<string>>;
    uploadChunk(
        session: string,
        body: StorageUploadData,
        options: StorageChunkOptions
    ): Promise<StorageResult<StorageUploadProgress>>;
    getUploadStatus(
        session: string,
        totalSize?: number
    ): Promise<StorageResult<StorageUploadProgress>>;
}

/** @internal Split a byte stream without accumulating the whole upload. */
async function* storageChunks(
    source: ReadableStream<Uint8Array>,
    chunkSize: number
): AsyncGenerator<Uint8Array<ArrayBuffer>> {
    const reader = source.getReader();
    let buffer = new Uint8Array(chunkSize);
    let used = 0;
    let finished = false;
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) {
                finished = true;
                break;
            }
            if (!(value instanceof Uint8Array)) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'Upload streams must contain Uint8Array chunks.'
                });
            }
            let offset = 0;
            while (offset < value.length) {
                const count = Math.min(chunkSize - used, value.length - offset);
                buffer.set(value.subarray(offset, offset + count), used);
                used += count;
                offset += count;
                if (used === chunkSize) {
                    yield buffer;
                    buffer = new Uint8Array(chunkSize);
                    used = 0;
                }
            }
        }
        if (used > 0) {
            yield buffer.slice(0, used);
        }
    } finally {
        if (!finished) {
            await reader.cancel().catch(() => {});
        }
        reader.releaseLock();
    }
}

/** @internal Retain the current chunk while reconciling uncertain acknowledgements. */
export function uploadStorageStream(
    transport: StorageUploadTransport,
    name: string,
    input: StorageUploadData | ReadableStream<Uint8Array>,
    options: StorageUploadStreamOptions & { isPartialUpload: true }
): Promise<StoragePartialUpload>;
export function uploadStorageStream(
    transport: StorageUploadTransport,
    name: string,
    input: StorageUploadData | ReadableStream<Uint8Array>,
    options?: StorageUploadStreamOptions & { isPartialUpload?: false }
): Promise<StorageFileMetadata>;
export function uploadStorageStream(
    transport: StorageUploadTransport,
    name: string,
    input: StorageUploadData | ReadableStream<Uint8Array>,
    options: StorageUploadStreamOptions
): Promise<StorageFileMetadata | StoragePartialUpload>;
export async function uploadStorageStream(
    transport: StorageUploadTransport,
    name: string,
    input: StorageUploadData | ReadableStream<Uint8Array>,
    options: StorageUploadStreamOptions = {}
): Promise<StorageFileMetadata | StoragePartialUpload> {
    if (!options || typeof options !== 'object' || Array.isArray(options)) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Upload options must be an object.'
        });
    }
    const {
        chunkSize = 8388608,
        maxResumeAttempts = 2,
        verifyChecksum = true,
        sessionUri,
        crc32c = 'auto',
        md5Hash,
        offset: initialOffset = 0,
        resumeCRC32C,
        isPartialUpload = false,
        crc32cGenerator,
        onProgress,
        onSession,
        ...sessionOptions
    } = options;
    if (
        typeof isPartialUpload !== 'boolean' ||
        (isPartialUpload &&
            (options.chunkSize === undefined || md5Hash !== undefined))
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'Partial uploads require chunkSize and cannot validate whole-object MD5.'
        });
    }
    if (
        !Number.isSafeInteger(chunkSize) ||
        chunkSize < 262144 ||
        chunkSize > 67108864 ||
        chunkSize % 262144 !== 0 ||
        !Number.isInteger(maxResumeAttempts) ||
        maxResumeAttempts < 0 ||
        maxResumeAttempts > 10 ||
        typeof verifyChecksum !== 'boolean' ||
        (onProgress !== undefined && typeof onProgress !== 'function') ||
        (onSession !== undefined && typeof onSession !== 'function')
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Invalid chunk size, recovery limit, or upload callback.'
        });
    }
    if (crc32c !== 'auto') {
        validateStorageCrc32c(crc32c);
    }
    if (
        !Number.isSafeInteger(initialOffset) ||
        initialOffset < 0 ||
        (initialOffset > 0 &&
            (!sessionUri ||
                md5Hash !== undefined ||
                (verifyChecksum && resumeCRC32C === undefined))) ||
        (initialOffset === 0 && resumeCRC32C !== undefined)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'Resuming a sliced input requires a session URI, a valid offset, and the preceding CRC32C when validation is enabled; MD5 requires the full input.'
        });
    }
    const checksum = createStorageCrc32c(
        verifyChecksum || isPartialUpload ? crc32cGenerator : undefined,
        resumeCRC32C
    );
    if (md5Hash !== undefined && md5Hash !== 'auto') {
        validateStorageMd5(md5Hash);
    }
    if (sessionUri !== undefined) {
        validateSessionUri(sessionUri);
    }
    const blob =
        input instanceof ReadableStream ? undefined : storageUploadBlob(input);
    const source = blob ? blob.stream() : (input as ReadableStream<Uint8Array>);
    if (source.locked) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Upload stream is already locked.'
        });
    }
    const declaredSize =
        sessionOptions.size ??
        (blob && !isPartialUpload ? blob.size + initialOffset : undefined);
    if (
        isPartialUpload &&
        blob &&
        (blob.size === 0 || blob.size % 262144 !== 0)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'Partial input must contain a positive multiple of 256 KiB.'
        });
    }
    if (
        declaredSize !== undefined &&
        (!Number.isSafeInteger(declaredSize) ||
            declaredSize < 0 ||
            (blob &&
                (isPartialUpload
                    ? declaredSize <= blob.size + initialOffset
                    : declaredSize !== blob.size + initialOffset)))
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Upload size must match the input.'
        });
    }
    let session = sessionUri;
    let persisted = 0;
    if (!session) {
        const { error, data } = await transport.createResumableUpload(name, {
            ...sessionOptions,
            size: declaredSize,
            ...(crc32c !== 'auto' && { crc32c }),
            ...(md5Hash !== undefined && md5Hash !== 'auto' && { md5Hash })
        });
        if (error) {
            throw error;
        }
        session = data;
    }
    await onSession?.(session);
    if (sessionUri) {
        const { error, data } = await transport.getUploadStatus(
            session,
            declaredSize
        );
        if (error) {
            throw error;
        }
        if (data.complete) {
            if (isPartialUpload) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'The partial upload session is already complete.'
                });
            }
            const md5 = md5Hash !== undefined ? new StorageMd5() : undefined;
            let size = initialOffset;
            for await (const bytes of storageChunks(source, chunkSize)) {
                checksum.update(bytes);
                md5?.update(bytes);
                size += bytes.length;
            }
            if (
                String(size) !== data.metadata.size ||
                (declaredSize !== undefined && size !== declaredSize)
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'Input size differs from the completed session.'
                });
            }
            verifyStorageUpload(
                verifyChecksum
                    ? crc32c === 'auto'
                        ? checksum.digest()
                        : crc32c
                    : undefined,
                data.metadata,
                md5Hash === 'auto' ? md5?.digest() : md5Hash
            );
            await reportStorageProgress(onProgress, {
                bytesTransferred: Number(data.metadata.size),
                totalBytes: Number(data.metadata.size),
                complete: true
            });
            return data.metadata;
        }
        persisted = data.nextOffset;
        if (persisted < initialOffset) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message:
                    'The supplied source begins after the acknowledged upload offset.'
            });
        }
    }
    const chunks = storageChunks(source, chunkSize);
    const md5 = md5Hash !== undefined ? new StorageMd5() : undefined;
    let offset = initialOffset;
    try {
        let current = await chunks.next();
        for (;;) {
            const bytes = current.done ? new Uint8Array() : current.value;
            const next = current.done ? current : await chunks.next();
            const sourceEnded = !!next.done;
            const final = sourceEnded && !isPartialUpload;
            const end = offset + bytes.length;
            if (
                !Number.isSafeInteger(end) ||
                (declaredSize !== undefined &&
                    (end > declaredSize ||
                        (final && end !== declaredSize) ||
                        (isPartialUpload && end >= declaredSize))) ||
                (sourceEnded && persisted > end) ||
                (isPartialUpload &&
                    (bytes.length === 0 || bytes.length % 262144 !== 0))
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'Input size does not match the upload session.'
                });
            }
            checksum.update(bytes);
            md5?.update(bytes);
            const expectedMd5 = final
                ? md5Hash === 'auto'
                    ? md5?.digest()
                    : md5Hash
                : undefined;
            const expected =
                final && verifyChecksum
                    ? crc32c === 'auto'
                        ? checksum.digest()
                        : crc32c
                    : undefined;
            if (persisted < end || final) {
                let attempts = 0;
                for (;;) {
                    // Google ignores persisted overlap; replay from a 256 KiB boundary for a valid non-final chunk.
                    const start = final
                        ? Math.max(offset, persisted)
                        : offset +
                          Math.floor(
                              (Math.max(offset, persisted) - offset) / 262144
                          ) *
                              262144;
                    const { error, data } = await transport.uploadChunk(
                        session,
                        bytes.slice(start - offset),
                        {
                            offset: start,
                            totalSize: isPartialUpload
                                ? undefined
                                : final
                                  ? end
                                  : declaredSize,
                            ...(expected !== undefined && { crc32c: expected }),
                            ...(expectedMd5 !== undefined && {
                                md5Hash: expectedMd5
                            })
                        }
                    );
                    const recoverable =
                        error &&
                        (error.cause instanceof TypeError ||
                            [408, 429, 500, 502, 503, 504].includes(
                                Number(
                                    error.context &&
                                        typeof error.context === 'object' &&
                                        'status' in error.context
                                        ? error.context.status
                                        : undefined
                                )
                            ));
                    if (error && !recoverable) {
                        throw error;
                    }
                    let progress = data;
                    if (error) {
                        if (attempts >= maxResumeAttempts) {
                            throw error;
                        }
                        const { error: statusError, data: status } =
                            await transport.getUploadStatus(
                                session,
                                final ? end : declaredSize
                            );
                        if (statusError) {
                            throw statusError;
                        }
                        progress = status;
                    }
                    if (!progress) {
                        throw new FirebaseEdgeError({
                            code: 'storage/internal-error',
                            message: 'Missing upload progress response.'
                        });
                    }
                    if (progress.complete) {
                        if (!final) {
                            throw new FirebaseEdgeError({
                                code: 'storage/internal-error',
                                message:
                                    'Upload completed before the input ended.'
                            });
                        }
                        verifyStorageUpload(
                            expected,
                            progress.metadata,
                            expectedMd5
                        );
                        await reportStorageProgress(onProgress, {
                            bytesTransferred: end,
                            totalBytes: end,
                            complete: true
                        });
                        return progress.metadata;
                    }
                    const nextOffset = progress.nextOffset;
                    if (
                        nextOffset < Math.max(offset, persisted) ||
                        nextOffset > end
                    ) {
                        throw new FirebaseEdgeError({
                            code: 'storage/internal-error',
                            message:
                                'Upload acknowledgement falls outside the retained chunk.'
                        });
                    }
                    persisted = nextOffset;
                    await reportStorageProgress(onProgress, {
                        bytesTransferred: persisted,
                        totalBytes: declaredSize,
                        complete: false
                    });
                    if (persisted === end && !final) {
                        break;
                    }
                    if (attempts++ >= maxResumeAttempts) {
                        throw new FirebaseEdgeError({
                            code: 'storage/retry-limit-exceeded',
                            message:
                                'Upload did not finish within the recovery limit.'
                        });
                    }
                }
            }
            if (sourceEnded && isPartialUpload) {
                return {
                    complete: false,
                    sessionUri: session,
                    nextOffset: end,
                    ...(initialOffset === 0 || resumeCRC32C !== undefined
                        ? { crc32c: checksum.digest() }
                        : {})
                };
            }
            offset = end;
            current = next;
        }
    } finally {
        await chunks.return(undefined);
    }
}
