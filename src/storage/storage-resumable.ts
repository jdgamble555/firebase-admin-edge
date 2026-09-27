import { FirebaseEdgeError } from '../auth/errors.js';
import {
    validateStorageCrc32c,
    validateStorageMd5,
    verifyStorageUpload,
    storageUploadBlob
} from './storage-checksum.js';
import { reportStorageProgress } from './storage-progress.js';
import {
    storageFetch,
    readStorageObject,
    parseStorageMetadata
} from './storage-endpoints.js';
import type {
    StorageChunkOptions,
    StorageUploadData,
    StorageUploadProgress
} from './storage-types.js';

export type StorageSessionOperation =
    | { kind: 'chunk'; body: StorageUploadData; options: StorageChunkOptions }
    | { kind: 'status'; totalSize?: number }
    | { kind: 'cancel' };

/** @internal Session URIs authorize writes, so only send them to the Storage upload endpoint. */
export function validateSessionUri(sessionUri: string): string {
    let url: URL;
    try {
        url = new URL(sessionUri);
    } catch {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Invalid resumable session URI.'
        });
    }
    if (
        url.origin !== 'https://storage.googleapis.com' ||
        url.username ||
        url.password ||
        url.hash ||
        !/^\/upload\/storage\/v1\/b\/[^/]+\/o$/.test(url.pathname) ||
        !url.searchParams.get('upload_id')
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Expected a Google Storage resumable session URI.'
        });
    }
    return url.toString();
}

/** @internal Chunk upload, status probing, and cancellation need no OAuth token. */
export async function resumableRequest<
    K extends StorageSessionOperation['kind']
>(
    sessionUri: string,
    request: StorageSessionOperation & { kind: K },
    fetch: typeof globalThis.fetch
): Promise<K extends 'cancel' ? void : StorageUploadProgress> {
    const operation: StorageSessionOperation = request;
    const url = validateSessionUri(sessionUri);
    if (operation.kind === 'cancel') {
        const response = await storageFetch(
            url,
            { method: 'DELETE', redirect: 'manual' },
            fetch,
            [499]
        );
        await response.body?.cancel();
        return undefined as K extends 'cancel' ? void : StorageUploadProgress;
    }
    if (
        operation.kind === 'chunk' &&
        (!operation.options ||
            typeof operation.options !== 'object' ||
            Array.isArray(operation.options))
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Chunk options are required.'
        });
    }
    const totalSize =
        operation.kind === 'chunk'
            ? operation.options.totalSize
            : operation.totalSize;
    if (
        totalSize !== undefined &&
        (!Number.isSafeInteger(totalSize) || totalSize < 0)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'totalSize must be a nonnegative safe integer.'
        });
    }
    let body: Blob | string = '';
    let range = `bytes */${totalSize ?? '*'}`;
    let sentEnd: number | undefined;
    if (operation.kind === 'chunk') {
        if (operation.options.md5Hash !== undefined) {
            validateStorageMd5(operation.options.md5Hash);
        }
        const { offset } = operation.options;
        if (operation.options.crc32c !== undefined) {
            validateStorageCrc32c(operation.options.crc32c);
        }
        if (
            operation.options.onProgress !== undefined &&
            typeof operation.options.onProgress !== 'function'
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'onProgress must be a function.'
            });
        }
        if (!Number.isSafeInteger(offset) || offset < 0) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Chunk offset must be a nonnegative safe integer.'
            });
        }
        body = storageUploadBlob(operation.body);
        sentEnd = offset + body.size;
        const final = totalSize !== undefined && sentEnd === totalSize;
        if (
            (operation.options.crc32c !== undefined ||
                operation.options.md5Hash !== undefined) &&
            !final
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message:
                    'Send the whole-object CRC32C only with the final chunk.'
            });
        }
        if (
            !Number.isSafeInteger(sentEnd) ||
            (totalSize !== undefined && sentEnd > totalSize) ||
            (!final && (body.size === 0 || body.size % 262144 !== 0))
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message:
                    'Non-final chunks must be positive multiples of 256 KiB and must not exceed totalSize.'
            });
        }
        range =
            body.size === 0
                ? `bytes */${totalSize}`
                : `bytes ${offset}-${sentEnd - 1}/${totalSize ?? '*'}`;
    }
    const response = await storageFetch(
        url,
        {
            method: 'PUT',
            redirect: 'manual',
            headers: {
                'Content-Range': range,
                ...(operation.kind === 'chunk' &&
                    (operation.options.crc32c !== undefined ||
                        operation.options.md5Hash !== undefined) && {
                        'X-Goog-Hash': [
                            operation.options.crc32c !== undefined
                                ? `crc32c=${operation.options.crc32c}`
                                : undefined,
                            operation.options.md5Hash !== undefined
                                ? `md5=${operation.options.md5Hash}`
                                : undefined
                        ]
                            .filter(Boolean)
                            .join(',')
                    })
            },
            body
        },
        fetch,
        [308]
    );
    if (response.status === 308) {
        const received = response.headers.get('range');
        const match =
            received === null ? null : /^bytes=0-(\d+)$/.exec(received);
        const nextOffset = match ? Number(match[1]) + 1 : 0;
        if (
            (received !== null && !match) ||
            !Number.isSafeInteger(nextOffset) ||
            (sentEnd !== undefined && nextOffset > sentEnd) ||
            (totalSize !== undefined && nextOffset > totalSize)
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/internal-error',
                message: 'Invalid resumable upload progress.'
            });
        }
        await response.body?.cancel();
        if (operation.kind === 'chunk') {
            await reportStorageProgress(operation.options.onProgress, {
                bytesTransferred: nextOffset,
                totalBytes: totalSize,
                complete: false
            });
        }
        return { complete: false, nextOffset } as K extends 'cancel'
            ? void
            : StorageUploadProgress;
    }
    const resource = await readStorageObject(response);
    const metadata = parseStorageMetadata(resource);
    if (operation.kind === 'chunk') {
        verifyStorageUpload(
            operation.options.crc32c,
            metadata,
            operation.options.md5Hash
        );
        await reportStorageProgress(operation.options.onProgress, {
            bytesTransferred: totalSize ?? sentEnd!,
            totalBytes: totalSize,
            complete: true
        });
    }
    return {
        complete: true,
        metadata
    } as K extends 'cancel' ? void : StorageUploadProgress;
}
