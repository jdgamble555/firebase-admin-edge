import { FirebaseEdgeError } from '../auth/errors.js';
import {
    calculateStorageCrc32c,
    calculateStorageMd5,
    validateStorageMd5,
    validateStorageCrc32c,
    verifyStorageDownload,
    verifyStorageStream,
    verifyStorageUpload,
    storageUploadBlob
} from './storage-checksum.js';
import { reportStorageProgress } from './storage-progress.js';
import { storageEncryptionHeaders } from './storage-reference-endpoints.js';
import type {
    StorageFileMetadata,
    StorageMetadataUpdate,
    StorageUploadData,
    StorageOperation,
    StorageResponses
} from './storage-types.js';

/** @internal Validate before requesting credentials. */
export function validateStorageOperation(
    bucket: string | undefined,
    operation: StorageOperation
): asserts bucket is string {
    if (
        typeof bucket !== 'string' ||
        !bucket ||
        /[\s/\\?#]/.test(bucket) ||
        bucket === '.' ||
        bucket === '..'
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'Configure a storage bucket name without a URL or gs:// prefix.'
        });
    }
    if (
        'name' in operation &&
        (typeof operation.name !== 'string' ||
            !operation.name ||
            /[\r\n]/.test(operation.name) ||
            operation.name === '.' ||
            operation.name === '..')
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'A valid object name is required.'
        });
    }
    if (
        'options' in operation &&
        !(
            operation.options === undefined &&
            ['download', 'stream', 'metadata'].includes(operation.kind)
        ) &&
        (!operation.options ||
            typeof operation.options !== 'object' ||
            Array.isArray(operation.options))
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Storage options must be an object.'
        });
    }
    if (operation.kind === 'upload') {
        if (
            operation.options.md5Hash !== undefined &&
            operation.options.md5Hash !== 'auto'
        ) {
            validateStorageMd5(operation.options.md5Hash);
        }
        if (operation.options.metadata !== undefined) {
            validateMetadataUpdate(operation.options.metadata);
        }
        if (
            operation.options.crc32c !== undefined &&
            operation.options.crc32c !== 'auto'
        ) {
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
        if (
            typeof operation.body !== 'string' &&
            !(operation.body instanceof Blob) &&
            !(operation.body instanceof ArrayBuffer) &&
            !(operation.body instanceof Uint8Array)
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message:
                    'Upload data must be a string, Blob, ArrayBuffer, or Uint8Array.'
            });
        }
        const { contentType } = operation.options;
        if (
            contentType !== undefined &&
            (typeof contentType !== 'string' ||
                !contentType.trim() ||
                /[\r\n]/.test(contentType))
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'contentType must be a nonempty HTTP header value.'
            });
        }
    }
    if ('options' in operation && operation.options) {
        const query = operation.options as Record<string, unknown>;
        if (
            query.overrideUnlockedRetention !== undefined &&
            typeof query.overrideUnlockedRetention !== 'boolean'
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'overrideUnlockedRetention must be a boolean.'
            });
        }
        for (const key of [
            'userProject',
            'fields',
            'kmsKeyName',
            'predefinedAcl',
            'origin'
        ] as const) {
            const value = query[key];
            if (
                value !== undefined &&
                (typeof value !== 'string' ||
                    !value.trim() ||
                    /[\r\n]/.test(value))
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: `${key} must be a nonempty string.`
                });
            }
        }
        if (
            query.checksumAlgorithm !== undefined &&
            !['crc32c', 'md5'].includes(String(query.checksumAlgorithm))
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Unknown checksum algorithm.'
            });
        }
        for (const key of [
            'ifGenerationMatch',
            'ifGenerationNotMatch',
            'ifMetagenerationMatch',
            'ifMetagenerationNotMatch',
            'ifSourceGenerationMatch',
            'ifSourceMetagenerationMatch',
            'generation',
            'sourceGeneration'
        ] as const) {
            const value = (operation.options as Record<string, unknown>)[key];
            if (
                value !== undefined &&
                (typeof value !== 'string' || !/^\d+$/.test(value))
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: `${key} must be a nonnegative integer string.`
                });
            }
        }
    }
    if (
        (operation.kind === 'download' || operation.kind === 'stream') &&
        operation.options
    ) {
        const { start, end } = operation.options;
        if (
            operation.options.verifyChecksum !== undefined &&
            typeof operation.options.verifyChecksum !== 'boolean'
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'verifyChecksum must be a boolean.'
            });
        }
        if (
            operation.options.verifyChecksum &&
            (start !== undefined || end !== undefined)
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message:
                    'Checksum verification requires a complete download without a byte range.'
            });
        }
        if (
            (start !== undefined &&
                (!Number.isSafeInteger(start) || start < 0)) ||
            (end !== undefined &&
                (!Number.isSafeInteger(end) ||
                    (end < 0 ? start !== undefined : end < (start ?? 0))))
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message:
                    'Use a nonnegative start/end range or a negative end alone for a suffix range.'
            });
        }
    }
    if (operation.kind === 'resumable') {
        if (operation.options.md5Hash !== undefined) {
            validateStorageMd5(operation.options.md5Hash);
        }
        if (operation.options.crc32c !== undefined) {
            validateStorageCrc32c(operation.options.crc32c);
        }
        const { size, contentType, metadata } = operation.options;
        if (size !== undefined && (!Number.isSafeInteger(size) || size < 0)) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Upload size must be a nonnegative safe integer.'
            });
        }
        if (
            contentType !== undefined &&
            (typeof contentType !== 'string' ||
                !contentType.trim() ||
                /[\r\n]/.test(contentType))
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Invalid upload content type.'
            });
        }
        if (metadata !== undefined) {
            validateMetadataUpdate(metadata);
        }
    }
    if (
        operation.kind === 'restore' &&
        (!operation.options.generation ||
            (operation.options.projection !== undefined &&
                !['full', 'noAcl'].includes(operation.options.projection)) ||
            (operation.options.restoreToken !== undefined &&
                typeof operation.options.restoreToken !== 'string') ||
            (operation.options.copySourceAcl !== undefined &&
                typeof operation.options.copySourceAcl !== 'boolean'))
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Restore requires a generation and valid restore options.'
        });
    }
    if (operation.kind === 'compose') {
        if (
            !Array.isArray(operation.sources) ||
            operation.sources.length < 1 ||
            operation.sources.length > 32
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Compose requires 1 to 32 source objects.'
            });
        }
        for (const source of operation.sources) {
            if (!source || typeof source !== 'object') {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'Invalid compose source.'
                });
            }
            validateStorageOperation(bucket, {
                kind: 'metadata',
                name: source.name,
                options: {
                    generation: source.generation,
                    ifGenerationMatch:
                        source.objectPreconditions?.ifGenerationMatch
                }
            });
        }
        if (operation.options.metadata !== undefined) {
            validateMetadataUpdate(operation.options.metadata);
        }
    }
    if (operation.kind === 'updateMetadata') {
        validateMetadataUpdate(operation.metadata);
    }
    if (operation.kind === 'copy') {
        const destinationBucket =
            operation.options.destinationBucket === undefined
                ? bucket
                : operation.options.destinationBucket;
        validateStorageOperation(destinationBucket, {
            kind: 'metadata',
            name: operation.destination
        });
        if (
            destinationBucket === bucket &&
            operation.destination === operation.name &&
            operation.options.sourceGeneration === undefined &&
            !operation.options.metadata &&
            !operation.options.destinationEncryptionKey &&
            !operation.options.destinationKmsKeyName
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Source and destination must be different objects.'
            });
        }
    }
    if (operation.kind !== 'list') {
        return;
    }
    const {
        maxResults,
        prefix,
        delimiter,
        pageToken,
        versions,
        softDeleted,
        startOffset,
        endOffset,
        matchGlob
    } = operation.options;
    if (
        [
            versions,
            softDeleted,
            operation.options.includeFoldersAsPrefixes,
            operation.options.includeTrailingDelimiter
        ].some((value) => value !== undefined && typeof value !== 'boolean') ||
        (versions && softDeleted)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'versions and softDeleted must be booleans and cannot both be true.'
        });
    }
    if (
        maxResults !== undefined &&
        (!Number.isInteger(maxResults) || maxResults < 1 || maxResults > 1000)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'maxResults must be an integer between 1 and 1000.'
        });
    }
    if (
        [prefix, delimiter, pageToken, startOffset, endOffset, matchGlob].some(
            (value) => value !== undefined && typeof value !== 'string'
        )
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'List filters and pageToken must be strings.'
        });
    }
}

/** @internal Storage needs raw media bodies and binary responses rather than restFetch's JSON/text conversion. */
export async function storageRequest<K extends StorageOperation['kind']>(
    bucket: string,
    accessToken: string,
    request: StorageOperation & { kind: K },
    fetch: typeof globalThis.fetch
): Promise<StorageResponses[K]> {
    const operation: StorageOperation = request;
    validateStorageOperation(bucket, operation);
    if (operation.kind === 'copy') {
        const copied = await copyStorageObject(
            bucket,
            accessToken,
            operation,
            fetch
        );
        return copied as StorageResponses[K];
    }
    const upload =
        operation.kind === 'upload' || operation.kind === 'resumable';
    const base = upload ? 'upload/storage/v1' : 'storage/v1';
    const objectPath =
        'name' in operation && !upload
            ? `/${encodeURIComponent(operation.name)}`
            : '';
    const suffix =
        operation.kind === 'compose'
            ? '/compose'
            : operation.kind === 'restore'
              ? '/restore'
              : '';
    const url = new URL(
        `https://storage.googleapis.com/${base}/b/${encodeURIComponent(bucket)}/o${objectPath}${suffix}`
    );
    const headers: Record<string, string> = {
        Authorization: `Bearer ${accessToken}`
    };
    let uploadBody = operation.kind === 'upload' ? operation.body : undefined;
    let uploadChecksum: string | undefined;
    let uploadMd5: string | undefined;
    if (operation.kind === 'upload') {
        url.searchParams.set('uploadType', 'media');
        url.searchParams.set('name', operation.name);
        headers['Content-Type'] =
            operation.options.contentType ||
            (operation.body instanceof Blob && operation.body.type) ||
            'application/octet-stream';
        if (
            operation.options.crc32c !== undefined ||
            operation.options.metadata !== undefined ||
            operation.options.md5Hash !== undefined
        ) {
            uploadChecksum =
                operation.options.crc32c === 'auto'
                    ? await calculateStorageCrc32c(
                          operation.body,
                          operation.options.crc32cGenerator
                      )
                    : operation.options.crc32c;
            const boundary = `storage-${crypto.randomUUID()}`;
            uploadMd5 =
                operation.options.md5Hash === 'auto'
                    ? await calculateStorageMd5(operation.body)
                    : operation.options.md5Hash;
            uploadBody = createChecksumUploadBody(
                operation.body,
                headers['Content-Type'],
                uploadChecksum,
                boundary,
                {
                    ...operation.options.metadata,
                    ...(uploadMd5 !== undefined && { md5Hash: uploadMd5 })
                }
            );
            url.searchParams.set('uploadType', 'multipart');
            headers['Content-Type'] = `multipart/related; boundary=${boundary}`;
        }
    }
    if (operation.kind === 'resumable') {
        url.searchParams.set('uploadType', 'resumable');
        if (operation.options.origin !== undefined) {
            headers.Origin = operation.options.origin;
        }
        url.searchParams.set('name', operation.name);
        headers['Content-Type'] = 'application/json';
        if (operation.options.contentType !== undefined) {
            headers['X-Upload-Content-Type'] = operation.options.contentType;
        }
        if (operation.options.size !== undefined) {
            headers['X-Upload-Content-Length'] = String(operation.options.size);
        }
    }
    if (operation.kind === 'download' || operation.kind === 'stream') {
        url.searchParams.set('alt', 'media');
        const { start, end } = operation.options ?? {};
        if (start !== undefined || end !== undefined) {
            headers.Range =
                end !== undefined && end < 0
                    ? `bytes=${end}`
                    : `bytes=${start ?? 0}-${end ?? ''}`;
        }
    }
    if (operation.kind === 'updateMetadata' || operation.kind === 'compose') {
        headers['Content-Type'] = 'application/json';
    }
    if ('options' in operation && operation.options) {
        for (const [key, value] of Object.entries(operation.options)) {
            if (
                value !== undefined &&
                [
                    'prefix',
                    'delimiter',
                    'maxResults',
                    'pageToken',
                    'versions',
                    'softDeleted',
                    'startOffset',
                    'endOffset',
                    'matchGlob',
                    'userProject',
                    'fields',
                    'includeFoldersAsPrefixes',
                    'includeTrailingDelimiter',
                    'projection',
                    'predefinedAcl',
                    'destinationPredefinedAcl',
                    'kmsKeyName',
                    'generation',
                    'restoreToken',
                    'overrideUnlockedRetention',
                    'copySourceAcl',
                    'ifGenerationMatch',
                    'ifGenerationNotMatch',
                    'ifMetagenerationMatch',
                    'ifMetagenerationNotMatch'
                ].includes(key)
            ) {
                url.searchParams.set(key, String(value));
            }
        }
    }

    if (operation.kind === 'list' && operation.options.fields) {
        url.searchParams.set(
            'fields',
            `items(name,bucket,generation,size),prefixes,nextPageToken,${operation.options.fields}`
        );
    }

    const response = await storageFetch(
        url.toString(),
        {
            method:
                upload ||
                operation.kind === 'compose' ||
                operation.kind === 'restore'
                    ? 'POST'
                    : operation.kind === 'delete'
                      ? 'DELETE'
                      : operation.kind === 'updateMetadata'
                        ? 'PATCH'
                        : 'GET',
            headers,
            ...(operation.kind === 'upload' && { body: uploadBody }),
            ...(operation.kind === 'updateMetadata' && {
                body: JSON.stringify(
                    storageWritableMetadata(operation.metadata)
                )
            }),
            ...(operation.kind === 'resumable' && {
                body: JSON.stringify({
                    ...storageWritableMetadata(operation.options.metadata),
                    ...(operation.options.md5Hash !== undefined && {
                        md5Hash: operation.options.md5Hash
                    }),
                    ...(operation.options.crc32c !== undefined && {
                        crc32c: operation.options.crc32c
                    }),
                    ...(operation.options.contentType !== undefined && {
                        contentType: operation.options.contentType
                    })
                })
            }),
            ...(operation.kind === 'compose' && {
                body: JSON.stringify({
                    sourceObjects: operation.sources,
                    destination: storageWritableMetadata(
                        operation.options.metadata
                    )
                })
            })
        },
        fetch
    );
    if (operation.kind === 'resumable') {
        const location = response.headers.get('location');
        if (!location) {
            throw new FirebaseEdgeError({
                code: 'storage/internal-error',
                message: 'Missing resumable upload session URI.'
            });
        }
        return location as StorageResponses[K];
    }
    if (operation.kind === 'stream') {
        return (
            operation.options?.verifyChecksum
                ? verifyStorageStream(
                      response,
                      operation.options.checksumAlgorithm,
                      operation.options.crc32cGenerator
                  )
                : response
        ) as StorageResponses[K];
    }
    if (operation.kind === 'delete') {
        return undefined as StorageResponses[K];
    }
    if (operation.kind === 'download') {
        const bytes = await response.arrayBuffer();
        const data = new Uint8Array(bytes);
        if (operation.options?.verifyChecksum) {
            await verifyStorageDownload(
                data,
                response,
                operation.options.checksumAlgorithm,
                operation.options.crc32cGenerator
            );
        }
        return data as StorageResponses[K];
    }
    const data = await readStorageObject(response);
    if (operation.kind === 'list') {
        if (
            (data.items !== undefined && !Array.isArray(data.items)) ||
            (data.prefixes !== undefined &&
                (!Array.isArray(data.prefixes) ||
                    data.prefixes.some(
                        (prefix: unknown) => typeof prefix !== 'string'
                    ))) ||
            (data.nextPageToken !== undefined &&
                typeof data.nextPageToken !== 'string')
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/internal-error',
                message: 'Invalid Storage list response.'
            });
        }
        return {
            files: (data.items ?? []).map(parseStorageMetadata),
            prefixes: data.prefixes ?? [],
            ...(data.nextPageToken !== undefined && {
                nextPageToken: data.nextPageToken
            })
        } as StorageResponses[K];
    }
    const metadata = parseStorageMetadata(data);
    if (operation.kind === 'upload') {
        verifyStorageUpload(uploadChecksum, metadata, uploadMd5);
        const totalBytes = storageUploadBlob(operation.body).size;
        await reportStorageProgress(operation.options.onProgress, {
            bytesTransferred: totalBytes,
            totalBytes,
            complete: true
        });
    }
    return metadata as StorageResponses[K];
}

/** @internal Use metadata checksums so validation is enforced before the object is committed. */
function createChecksumUploadBody(
    body: StorageUploadData,
    contentType: string,
    crc32c: string | undefined,
    boundary: string,
    metadata?: StorageMetadataUpdate & { md5Hash?: string }
): Blob {
    return new Blob([
        `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n`,
        JSON.stringify({
            ...storageWritableMetadata(metadata),
            crc32c,
            contentType
        }),
        `\r\n--${boundary}\r\nContent-Type: ${contentType}\r\n\r\n`,
        body,
        `\r\n--${boundary}--\r\n`
    ]);
}

/** @internal Shared media/JSON transport and error mapping. */
export async function storageFetch(
    url: string,
    init: RequestInit,
    fetch: typeof globalThis.fetch,
    acceptedStatuses: number[] = [],
    notFoundCode = 'object-not-found'
) {
    const response = await fetch(url, init);
    if (!response.ok && !acceptedStatuses.includes(response.status)) {
        const text = await response.text();
        let message = text || `Storage request failed (${response.status}).`;
        try {
            const parsed = JSON.parse(text);
            if (typeof parsed?.error?.message === 'string') {
                message = parsed.error.message;
            }
        } catch {
            /* Preserve non-JSON error bodies. */
        }
        const codes: Record<number, string> = {
            400: 'invalid-argument',
            401: 'unauthenticated',
            403: 'permission-denied',
            404: notFoundCode,
            409: 'conflict',
            412: 'precondition-failed',
            416: 'invalid-range',
            429: 'quota-exceeded'
        };
        throw new FirebaseEdgeError(
            {
                code: `storage/${codes[response.status] ?? 'unknown-error'}`,
                message
            },
            { context: { status: response.status } }
        );
    }
    return response;
}

/** @internal Validate the JSON envelope before interpreting it. */
export async function readStorageObject(
    response: Response
): Promise<Record<string, unknown>> {
    const responseData: unknown = await response.json();
    if (
        !responseData ||
        typeof responseData !== 'object' ||
        Array.isArray(responseData)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/internal-error',
            message: 'Invalid Storage response.'
        });
    }
    return responseData as Record<string, unknown>;
}

/** @internal Complete multi-request server-side copies without buffering media. */
async function copyStorageObject(
    bucket: string,
    accessToken: string,
    operation: Extract<StorageOperation, { kind: 'copy' }>,
    fetch: typeof globalThis.fetch
) {
    const {
        destinationBucket = bucket,
        ifGenerationMatch,
        ifSourceGenerationMatch
    } = operation.options;
    const url = new URL(
        `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}/o/${encodeURIComponent(operation.name)}/rewriteTo/b/${encodeURIComponent(destinationBucket)}/o/${encodeURIComponent(operation.destination)}`
    );
    if (ifGenerationMatch !== undefined) {
        url.searchParams.set('ifGenerationMatch', ifGenerationMatch);
    }
    if (ifSourceGenerationMatch !== undefined) {
        url.searchParams.set(
            'ifSourceGenerationMatch',
            ifSourceGenerationMatch
        );
    }
    for (const key of [
        'sourceGeneration',
        'ifGenerationNotMatch',
        'ifMetagenerationMatch',
        'ifMetagenerationNotMatch',
        'ifSourceMetagenerationMatch'
    ] as const) {
        const value = operation.options[key];
        if (value !== undefined) {
            url.searchParams.set(key, value);
        }
    }
    if (operation.options.destinationKmsKeyName) {
        url.searchParams.set(
            'destinationKmsKeyName',
            operation.options.destinationKmsKeyName
        );
    }
    if (operation.options.predefinedAcl) {
        url.searchParams.set(
            'destinationPredefinedAcl',
            operation.options.predefinedAcl
        );
    }
    if (operation.options.token) {
        url.searchParams.set('rewriteToken', operation.options.token);
    }
    if (operation.options.userProject) {
        url.searchParams.set('userProject', operation.options.userProject);
    }
    const encryptionHeaders =
        operation.options.destinationEncryptionKey === undefined
            ? {}
            : await storageEncryptionHeaders(
                  operation.options.destinationEncryptionKey
              );
    for (;;) {
        const response = await storageFetch(
            url.toString(),
            {
                method: 'POST',
                headers: {
                    ...encryptionHeaders,
                    Authorization: `Bearer ${accessToken}`,
                    ...(operation.options.metadata && {
                        'Content-Type': 'application/json'
                    })
                },
                ...(operation.options.metadata && {
                    body: JSON.stringify(
                        storageWritableMetadata(operation.options.metadata)
                    )
                })
            },
            fetch
        );
        const data = await readStorageObject(response);
        if (data.done === true) {
            return parseStorageMetadata(data.resource);
        }
        if (
            data.done !== false ||
            typeof data.rewriteToken !== 'string' ||
            !data.rewriteToken
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/internal-error',
                message: 'Invalid Storage rewrite response.'
            });
        }
        url.searchParams.set('rewriteToken', data.rewriteToken);
    }
}

/** @internal Only permit writable metadata, including explicit removals. */
function validateMetadataUpdate(metadata: unknown) {
    if (
        !metadata ||
        typeof metadata !== 'object' ||
        Array.isArray(metadata) ||
        Object.keys(metadata).length === 0
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'A nonempty metadata update is required.'
        });
    }
    const fields = [
        'storageClass',
        'customTime',
        'contentType',
        'cacheControl',
        'contentDisposition',
        'contentEncoding',
        'contentLanguage'
    ];
    for (const [key, value] of Object.entries(metadata)) {
        if (
            key === 'retention' &&
            (value === null ||
                (value &&
                    typeof value === 'object' &&
                    'mode' in value &&
                    ['Locked', 'Unlocked'].includes(String(value.mode)) &&
                    'retainUntilTime' in value &&
                    typeof value.retainUntilTime === 'string' &&
                    Number.isFinite(Date.parse(value.retainUntilTime))))
        ) {
            continue;
        }
        if (
            key === 'acl' &&
            (value === null ||
                (Array.isArray(value) &&
                    value.every(
                        (entry) =>
                            entry &&
                            typeof entry.entity === 'string' &&
                            entry.entity.trim() &&
                            ['OWNER', 'READER', 'WRITER'].includes(entry.role)
                    )))
        ) {
            continue;
        }
        if (
            ['temporaryHold', 'eventBasedHold'].includes(key) &&
            typeof value === 'boolean'
        ) {
            continue;
        }
        if (key === 'metadata') {
            if (
                value === null ||
                (typeof value === 'object' &&
                    value !== null &&
                    !Array.isArray(value) &&
                    Object.values(value).every(
                        (item) =>
                            item === null ||
                            typeof item === 'string' ||
                            typeof item === 'boolean' ||
                            (typeof item === 'number' && Number.isFinite(item))
                    ))
            ) {
                continue;
            }
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Custom metadata must contain strings or null values.'
            });
        }
        if (
            !fields.includes(key) ||
            (value !== null &&
                (typeof value !== 'string' || /[\r\n]/.test(value)))
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: `Invalid writable metadata field: ${key}.`
            });
        }
    }
}

/** @internal Admin accepts primitive custom metadata; the REST API stores strings. */
function storageWritableMetadata(
    metadata: StorageMetadataUpdate = {}
): StorageMetadataUpdate {
    if (!metadata.metadata) {
        return metadata;
    }
    return {
        ...metadata,
        metadata: Object.fromEntries(
            Object.entries(metadata.metadata).map(([key, value]) => [
                key,
                value === null ? null : String(value)
            ])
        )
    };
}

/** @internal Preserve API integer strings and additional metadata fields. */
export function parseStorageMetadata(data: unknown): StorageFileMetadata {
    if (
        !data ||
        typeof data !== 'object' ||
        !('name' in data) ||
        typeof data.name !== 'string' ||
        !('bucket' in data) ||
        typeof data.bucket !== 'string' ||
        !('generation' in data) ||
        typeof data.generation !== 'string' ||
        !('size' in data) ||
        typeof data.size !== 'string'
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/internal-error',
            message: 'Invalid Storage object metadata.'
        });
    }
    return data as StorageFileMetadata;
}
