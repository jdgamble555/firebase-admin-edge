import { FirebaseEdgeError } from '../auth/errors.js';
import type { Storage } from './storage.js';
import type { Bucket } from './storage-bucket.js';
import { Acl } from './storage-acl.js';
import {
    storageResult,
    storageData,
    storageUnsupported
} from './storage-results.js';
import {
    storageGeneration,
    storagePreconditions,
    storageCopyOptions
} from './storage-reference-helpers.js';
import { storageUploadBlob } from './storage-checksum.js';
import { validateStorageOperation } from './storage-endpoints.js';
import type {
    FileOptions,
    FileReadOptions,
    SaveOptions,
    DownloadOptions,
    CopyOptions,
    GetSignedUrlOptions,
    PreconditionOptions
} from './storage-reference-types.js';
import type {
    StorageFileMetadata,
    StorageMetadataUpdate,
    StorageResult,
    StorageUploadData,
    StorageDownloadOptions
} from './storage-types.js';
import type { StorageRequestOptions } from './storage-reference-endpoints.js';
import type { SignedPostPolicyOptions } from './storage-reference-signing.js';
import type { StoragePartialUpload } from './storage-upload-stream.js';

export type FileWriteStream<T = StorageFileMetadata> =
    WritableStream<Uint8Array> & {
        result: Promise<StorageResult<T>>;
    };

/** A named object reference with Admin method names and web-native I/O. */
export class File {
    metadata?: StorageFileMetadata;
    readonly generation?: string;
    readonly acl: Acl;
    private engine: Storage;

    constructor(
        readonly bucket: Bucket,
        readonly name: string,
        private readonly options: FileOptions = {}
    ) {
        validateStorageOperation(bucket.name, { kind: 'metadata', name });
        this.generation =
            options.generation === undefined
                ? undefined
                : storageGeneration(options.generation);
        this.engine = bucket.engine.scoped(options);
        this.acl = new Acl(() => this.engine, {
            scope: 'object',
            name,
            generation: this.generation
        });
    }

    get storage() {
        return this.bucket.storage;
    }
    get cloudStorageURI() {
        return new URL(
            `gs://${this.bucket.name}/${this.name.split('/').map(encodeURIComponent).join('/')}`
        );
    }

    private readOptions(options: FileReadOptions = {}): StorageDownloadOptions {
        const generation = options.generation ?? this.generation;
        const {
            generation: requestedGeneration,
            autoCreate,
            ifGenerationMatch,
            ifGenerationNotMatch,
            ifMetagenerationMatch,
            ifMetagenerationNotMatch,
            ...read
        } = options;
        return {
            crc32cGenerator: this.options.crc32cGenerator,
            ...read,
            ...storagePreconditions(this.options.preconditionOpts),
            ...storagePreconditions(options),
            ...(generation !== undefined && {
                generation: storageGeneration(generation)
            }),
            ...(this.options.restoreToken !== undefined &&
                options.restoreToken === undefined && {
                    restoreToken: this.options.restoreToken
                })
        };
    }

    exists(options: FileReadOptions = {}) {
        return storageResult(async () => {
            const result = await this.engine.exists(
                this.name,
                this.readOptions(options)
            );
            return storageData(result);
        });
    }

    getMetadata(options: FileReadOptions = {}) {
        return storageResult(async () => {
            const result = await this.engine.getMetadata(
                this.name,
                this.readOptions(options)
            );
            this.metadata = storageData(result);
            return this.metadata;
        });
    }

    get(options: FileReadOptions = {}) {
        return storageResult(async () => {
            const result = await this.getMetadata(options);
            const { error } = result;
            if (
                error?.code === 'storage/object-not-found' &&
                options.autoCreate
            ) {
                if (
                    this.generation !== undefined ||
                    options.generation !== undefined ||
                    options.softDeleted
                ) {
                    throw error;
                }
                const saved = await this.save('', {
                    userProject: options.userProject,
                    preconditionOpts: { ifGenerationMatch: 0 }
                });
                const { error: saveError } = saved;
                if (saveError?.code === 'storage/precondition-failed') {
                    const existing = await this.getMetadata(options);
                    storageData(existing);
                    return this;
                }
                storageData(saved);
                return this;
            }
            storageData(result);
            return this;
        });
    }

    setMetadata(
        metadata: StorageMetadataUpdate,
        options: FileReadOptions = {}
    ) {
        return storageResult(async () => {
            const result = await this.engine.updateMetadata(
                this.name,
                metadata,
                this.readOptions(options)
            );
            this.metadata = storageData(result);
            return this.metadata;
        });
    }

    download(options: DownloadOptions = {}) {
        return storageResult(async () => {
            if (options.destination !== undefined) {
                storageUnsupported('Downloading to a filesystem path');
            }
            if (options.decompress === false) {
                storageUnsupported('Disabling Fetch content decoding');
            }
            const { destination, validation, decompress, ...read } = options;
            if (
                validation !== undefined &&
                !['crc32c', 'md5', true, false].includes(validation)
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'Unknown checksum validation algorithm.'
                });
            }
            const engine =
                options.encryptionKey === undefined
                    ? this.engine
                    : this.engine.scoped({
                          encryptionKey: options.encryptionKey
                      });
            const result = await engine.download(this.name, {
                ...this.readOptions(read),
                ...(validation !== undefined && {
                    verifyChecksum: validation !== false,
                    ...(validation === 'md5' && {
                        checksumAlgorithm: 'md5' as const
                    })
                })
            });
            return storageData(result);
        });
    }

    createReadStream(
        options: DownloadOptions = {}
    ): ReadableStream<Uint8Array> {
        let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
        let cancelled = false;
        let cancelReason: unknown;
        const file = this;
        return new ReadableStream<Uint8Array>(
            {
                async pull(controller) {
                    try {
                        if (!reader) {
                            if (
                                options.destination !== undefined ||
                                options.decompress === false
                            ) {
                                storageUnsupported(
                                    'Filesystem output or raw compressed Fetch responses'
                                );
                            }
                            const engine =
                                options.encryptionKey === undefined
                                    ? file.engine
                                    : file.engine.scoped({
                                          encryptionKey: options.encryptionKey
                                      });
                            const result = await engine.downloadStream(
                                file.name,
                                {
                                    ...file.readOptions(options),
                                    ...(options.validation !== undefined && {
                                        verifyChecksum:
                                            options.validation !== false,
                                        ...(options.validation === 'md5' && {
                                            checksumAlgorithm: 'md5' as const
                                        })
                                    })
                                }
                            );
                            const response = storageData(result);
                            if (!response.body) {
                                throw new FirebaseEdgeError({
                                    code: 'storage/internal-error',
                                    message: 'Download response has no body.'
                                });
                            }
                            if (cancelled) {
                                await response.body.cancel(cancelReason);
                                return;
                            }
                            reader = response.body.getReader();
                        }
                        const { done, value } = await reader.read();
                        if (cancelled) {
                            return;
                        }
                        if (done) {
                            reader.releaseLock();
                            controller.close();
                            return;
                        }
                        controller.enqueue(value);
                    } catch (cause) {
                        reader?.releaseLock();
                        controller.error(cause);
                    }
                },
                async cancel(reason) {
                    cancelled = true;
                    cancelReason = reason;
                    if (!reader) {
                        return;
                    }
                    try {
                        await reader.cancel(reason);
                    } finally {
                        reader.releaseLock();
                    }
                }
            },
            { highWaterMark: 0 }
        );
    }

    stream(options: DownloadOptions = {}) {
        return this.createReadStream(options);
    }

    save(
        input: StorageUploadData | ReadableStream<Uint8Array>,
        options: SaveOptions & { isPartialUpload: true }
    ): Promise<StorageResult<StoragePartialUpload>>;
    save(
        input: StorageUploadData | ReadableStream<Uint8Array>,
        options?: SaveOptions & { isPartialUpload?: false }
    ): Promise<StorageResult<void>>;
    save(
        input: StorageUploadData | ReadableStream<Uint8Array>,
        options: SaveOptions
    ): Promise<StorageResult<void | StoragePartialUpload>>;
    save(
        input: StorageUploadData | ReadableStream<Uint8Array>,
        options: SaveOptions = {}
    ): Promise<StorageResult<void | StoragePartialUpload>> {
        return storageResult<void | StoragePartialUpload>(async () => {
            const {
                preconditionOpts,
                resumable = true,
                validation,
                gzip,
                timeout,
                uri,
                public: isPublic,
                private: isPrivate,
                onUploadProgress,
                ...upload
            } = options;
            if (
                upload.isPartialUpload &&
                (!resumable || gzip || validation === 'md5')
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message:
                        'Partial uploads require resumable, uncompressed input and CRC32C or disabled validation.'
                });
            }
            upload.crc32cGenerator ??= this.options.crc32cGenerator;
            if (
                (validation !== undefined &&
                    !['crc32c', 'md5', true, false].includes(validation)) ||
                (gzip !== undefined && ![true, false, 'auto'].includes(gzip)) ||
                (isPublic && isPrivate) ||
                (onUploadProgress !== undefined &&
                    typeof onUploadProgress !== 'function')
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message:
                        'Invalid upload validation, compression, ACL, or progress options.'
                });
            }
            if (
                uri !== undefined &&
                upload.sessionUri !== undefined &&
                uri !== upload.sessionUri
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'Conflicting resumable session URIs.'
                });
            }
            if (uri !== undefined) {
                upload.sessionUri = uri;
            }
            if (isPublic || isPrivate) {
                upload.predefinedAcl = isPublic ? 'publicRead' : 'private';
            }
            const originalProgress = upload.onProgress;
            if (onUploadProgress) {
                upload.onProgress = async (progress) => {
                    await originalProgress?.(progress);
                    await onUploadProgress({
                        bytesWritten: progress.bytesTransferred,
                        contentLength: progress.totalBytes
                    });
                };
            }
            const engine =
                timeout !== undefined
                    ? this.engine.scoped({ timeout })
                    : this.engine;
            const preconditions = storagePreconditions(
                preconditionOpts ?? this.options.preconditionOpts
            );
            let body = input;
            const contentType =
                upload.contentType ??
                upload.metadata?.contentType ??
                (input instanceof Blob ? input.type : '');
            const compress =
                gzip === 'auto'
                    ? /^(text\/|application\/(json|javascript|xml|wasm)|.*\+(json|xml|text)$)/i.test(
                          contentType ?? ''
                      )
                    : gzip;
            if (compress) {
                const source =
                    input instanceof ReadableStream
                        ? input
                        : storageUploadBlob(input).stream();
                body = source.pipeThrough(new CompressionStream('gzip'));
                upload.metadata = {
                    ...upload.metadata,
                    contentEncoding: 'gzip'
                };
            }
            if (!resumable) {
                const bytes =
                    body instanceof ReadableStream
                        ? await new Response(body).arrayBuffer()
                        : body;
                const result = await engine.upload(this.name, bytes, {
                    ...upload,
                    contentType:
                        upload.contentType ??
                        upload.metadata?.contentType ??
                        undefined,
                    ...preconditions,
                    ...(validation === false || validation === 'md5'
                        ? { crc32c: undefined }
                        : { crc32c: upload.crc32c ?? 'auto' }),
                    ...(validation === 'md5' && {
                        md5Hash: upload.md5Hash ?? 'auto'
                    })
                });
                this.metadata = storageData(result);
                return;
            }
            const result = await engine.uploadStream(this.name, body, {
                ...upload,
                ...preconditions,
                verifyChecksum: validation !== false && validation !== 'md5',
                ...(validation === 'md5' && {
                    md5Hash: upload.md5Hash ?? 'auto'
                })
            });
            const data = storageData(result);
            if ('complete' in data) {
                return data;
            }
            this.metadata = data;
        });
    }

    upload(
        input: StorageUploadData | ReadableStream<Uint8Array>,
        options: SaveOptions = {}
    ) {
        return this.save(input, options);
    }

    createWriteStream(
        options: SaveOptions & { isPartialUpload: true }
    ): FileWriteStream<StoragePartialUpload>;
    createWriteStream(
        options?: SaveOptions & { isPartialUpload?: false }
    ): FileWriteStream;
    createWriteStream(
        options: SaveOptions
    ): FileWriteStream<StorageFileMetadata | StoragePartialUpload>;
    createWriteStream(
        options: SaveOptions = {}
    ): FileWriteStream<StorageFileMetadata | StoragePartialUpload> {
        if (
            options.highWaterMark !== undefined &&
            (!Number.isFinite(options.highWaterMark) ||
                options.highWaterMark < 0)
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'highWaterMark must be a nonnegative byte count.'
            });
        }
        const strategy =
            options.highWaterMark === undefined
                ? undefined
                : new ByteLengthQueuingStrategy({
                      highWaterMark: options.highWaterMark
                  });
        const bridge = new TransformStream<Uint8Array, Uint8Array>(
            undefined,
            strategy,
            strategy
        );
        const writer = bridge.writable.getWriter();
        const file = this;
        const result = storageResult(async () => {
            const saved = await file.save(bridge.readable, options);
            const checkpoint = storageData(saved);
            return checkpoint ?? file.metadata!;
        });
        void result.then(async ({ error }) => {
            if (error) {
                await bridge.readable.cancel(error).catch(() => {});
            }
        });
        const stream = new WritableStream<Uint8Array>(
            {
                async write(chunk) {
                    await writer.write(chunk);
                },
                async close() {
                    await writer.close();
                    const completed = await result;
                    storageData(completed);
                },
                async abort(reason) {
                    await writer.abort(reason);
                }
            },
            strategy
        );
        return Object.assign(stream, { result });
    }

    createResumableUpload(options: SaveOptions = {}) {
        return storageResult(async () => {
            const {
                preconditionOpts,
                crc32c,
                md5Hash,
                timeout,
                public: isPublic,
                private: isPrivate,
                ...rest
            } = options;
            if (crc32c === 'auto' || md5Hash === 'auto') {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'A session checksum must be precomputed.'
                });
            }
            const engine =
                timeout !== undefined
                    ? this.engine.scoped({ timeout })
                    : this.engine;
            const result = await engine.createResumableUpload(this.name, {
                ...rest,
                crc32c,
                ...(md5Hash !== undefined && { md5Hash }),
                ...((isPublic || isPrivate) && {
                    predefinedAcl: isPublic ? 'publicRead' : 'private'
                }),
                ...storagePreconditions(
                    preconditionOpts ?? this.options.preconditionOpts
                )
            });
            return storageData(result);
        });
    }

    delete(options: FileReadOptions & { ignoreNotFound?: boolean } = {}) {
        return storageResult(async () => {
            const result = await this.engine.delete(
                this.name,
                this.readOptions(options)
            );
            const { error } = result;
            if (
                options.ignoreNotFound &&
                error?.code === 'storage/object-not-found'
            ) {
                return;
            }
            return storageData(result);
        });
    }

    copy(destination: string | File, options: CopyOptions = {}) {
        return storageResult(async () => {
            const target = this.destination(destination);
            const result = await this.engine.copy(this.name, target.name, {
                ...storageCopyOptions(options),
                destinationBucket: target.bucket.name,
                sourceGeneration: this.generation ?? options.sourceGeneration
            });
            target.metadata = storageData(result);
            return target;
        });
    }

    move(destination: string | File, options: CopyOptions = {}) {
        return storageResult(async () => {
            const target = this.destination(destination);
            const result = await this.engine.move(this.name, target.name, {
                ...storageCopyOptions(options),
                destinationBucket: target.bucket.name,
                sourceGeneration: this.generation ?? options.sourceGeneration
            });
            target.metadata = storageData(result);
            return target;
        });
    }

    rename(destination: string | File, options: CopyOptions = {}) {
        return this.move(destination, options);
    }

    moveFileAtomic(
        destination: string | File,
        options: {
            preconditionOpts?: PreconditionOptions;
            userProject?: string;
        } = {}
    ) {
        return storageResult(async () => {
            const target = this.destination(destination);
            if (target.bucket.name !== this.bucket.name) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'Atomic moves require one bucket.'
                });
            }
            const result = await this.engine.referenceAction(
                { kind: 'file', name: this.name },
                {
                    kind: 'atomicMove',
                    destination: target.name,
                    preconditions: {
                        ...storagePreconditions(options.preconditionOpts),
                        ...(options.userProject !== undefined && {
                            userProject: options.userProject
                        })
                    } as Record<string, string>
                }
            );
            target.metadata = storageData(
                result
            ) as unknown as StorageFileMetadata;
            return target;
        });
    }

    rotateEncryptionKey(
        options:
            | string
            | Uint8Array<ArrayBuffer>
            | {
                  encryptionKey?: string | Uint8Array<ArrayBuffer>;
                  kmsKeyName?: string;
                  preconditionOpts?: PreconditionOptions;
              }
    ) {
        return storageResult(async () => {
            const config =
                typeof options === 'string' || options instanceof Uint8Array
                    ? { encryptionKey: options }
                    : options;
            if (!config || (!config.encryptionKey && !config.kmsKeyName)) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'A destination encryption key is required.'
                });
            }
            const result = await this.copy(this, {
                destinationEncryptionKey: config.encryptionKey,
                destinationKmsKeyName: config.kmsKeyName,
                preconditionOpts: config.preconditionOpts
            });
            storageData(result);
            this.engine = this.bucket.engine.scoped({
                encryptionKey: config.encryptionKey,
                kmsKeyName: config.kmsKeyName
            });
            return this;
        });
    }

    private destination(value: string | File): File {
        if (value instanceof File) {
            return value;
        }
        if (typeof value !== 'string') {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Destination must be a File or object name.'
            });
        }
        if (value.startsWith('gs://')) {
            const url = new URL(value);
            return this.storage
                .bucket(url.hostname)
                .file(decodeURIComponent(url.pathname.slice(1)));
        }
        return this.bucket.file(value);
    }

    getSignedUrl(options: GetSignedUrlOptions) {
        return this.engine.referenceSignedUrl(this.name, {
            ...options,
            queryParams: {
                ...options?.queryParams,
                ...(this.generation !== undefined && {
                    generation: this.generation
                })
            }
        });
    }
    generateSignedPostPolicyV2(options: SignedPostPolicyOptions) {
        return this.engine.referencePostPolicy(this.name, 'v2', options);
    }
    generateSignedPostPolicyV4(options: SignedPostPolicyOptions) {
        return this.engine.referencePostPolicy(this.name, 'v4', options);
    }
    getDownloadURL() {
        return this.engine.downloadURL(this.name);
    }
    publicUrl() {
        return `https://storage.googleapis.com/${encodeURIComponent(this.bucket.name)}/${this.name.split('/').map(encodeURIComponent).join('/')}`;
    }

    makePublic() {
        return this.acl.add({ entity: 'allUsers', role: 'READER' });
    }
    makePrivate(
        options: {
            strict?: boolean;
            preconditionOpts?: PreconditionOptions;
            userProject?: string;
            metadata?: StorageMetadataUpdate;
        } = {}
    ) {
        return storageResult(async () => {
            const result = await this.engine.referenceAction(
                { kind: 'file', name: this.name },
                {
                    kind: 'makePrivate',
                    strict: options.strict,
                    ...(options.metadata && {
                        metadata: options.metadata as Record<string, unknown>
                    }),
                    preconditions: this.readOptions({
                        ...storagePreconditions(options.preconditionOpts),
                        ...(options.userProject !== undefined && {
                            userProject: options.userProject
                        })
                    }) as Record<string, string>
                }
            );
            return storageData(result);
        });
    }
    isPublic() {
        return this.engine.objectIsPublic(this.name);
    }

    restore(
        options: PreconditionOptions & {
            projection?: 'full' | 'noAcl';
            generation?: string | number;
            restoreToken?: string;
            preconditionOpts?: PreconditionOptions;
            userProject?: string;
            copySourceAcl?: boolean;
        } = {}
    ) {
        return storageResult(async () => {
            const generation = options.generation ?? this.generation;
            if (generation === undefined) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'Restoration requires a generation.'
                });
            }
            const result = await this.engine.restore(this.name, {
                ...(options.projection !== undefined && {
                    projection: options.projection
                }),
                generation: storageGeneration(generation),
                restoreToken: options.restoreToken ?? this.options.restoreToken,
                ...(options.userProject !== undefined && {
                    userProject: options.userProject
                }),
                ...(options.copySourceAcl !== undefined && {
                    copySourceAcl: options.copySourceAcl
                }),
                ...storagePreconditions(options.preconditionOpts),
                ...storagePreconditions(options)
            });
            const metadata = storageData(result);
            const file = this.bucket.file(this.name, {
                generation: metadata.generation
            });
            file.metadata = metadata;
            return file;
        });
    }

    getExpirationDate() {
        return storageResult(async () => {
            const result = await this.getMetadata();
            const metadata = storageData(result);
            if (!metadata.retentionExpirationTime) {
                throw new FirebaseEdgeError({
                    code: 'storage/no-expiration',
                    message: 'This object has no retention expiration date.'
                });
            }
            return new Date(metadata.retentionExpirationTime);
        });
    }

    setStorageClass(
        storageClass: string,
        options: {
            preconditionOpts?: PreconditionOptions;
            userProject?: string;
        } = {}
    ) {
        return this.copy(this, { ...options, storageClass });
    }
    setUserProject(userProject: string) {
        this.engine = this.engine.scoped({ userProject });
        return this;
    }
    setEncryptionKey(encryptionKey: string | Uint8Array<ArrayBuffer>) {
        this.engine = this.engine.scoped({ encryptionKey });
        return this;
    }
    request(options: StorageRequestOptions) {
        return this.engine.requestResource(
            { kind: 'file', name: this.name },
            options
        );
    }
}

/** Firebase Admin's standalone helper, retaining the package result convention. */
export function getDownloadURL(file: File): Promise<StorageResult<string>> {
    return storageResult(async () => {
        if (!(file instanceof File)) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'getDownloadURL requires a File reference.'
            });
        }
        const result = await file.getDownloadURL();
        return storageData(result);
    });
}
