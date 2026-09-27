import { getToken } from '../auth/google-oauth.js';
import { Bucket } from './storage-bucket.js';
import {
    signStorageReferenceUrl,
    signStoragePostPolicy,
    type SignedPostPolicyOptions
} from './storage-reference-signing.js';
import type { GetSignedUrlOptions } from './storage-reference-types.js';
export type { SignedPostPolicyOptions } from './storage-reference-signing.js';
import { HmacKey } from './storage-hmac-key.js';
import { storageResult, storageData } from './storage-results.js';
import {
    storageReferenceRequest,
    storageDownloadURL,
    storageScopedFetch,
    type StorageRequestOptions,
    type StorageResource
} from './storage-reference-endpoints.js';
import {
    storageReferenceActionOptions,
    type StorageReferenceAction
} from './storage-reference-endpoints.js';
import { storageIsPublic } from './storage-reference-endpoints.js';
import { storageSignBlob } from './storage-reference-endpoints.js';
export { Bucket } from './storage-bucket.js';
export { File, getDownloadURL } from './storage-file.js';
export { Acl } from './storage-acl.js';
export { Iam } from './storage-iam.js';
export { Notification } from './storage-notification.js';
export { HmacKey } from './storage-hmac-key.js';
export { Channel } from './storage-channel.js';
export type {
    BucketOptions,
    FileOptions,
    FileReadOptions,
    SaveOptions,
    DownloadOptions,
    GetFilesOptions,
    CopyOptions,
    GetSignedUrlOptions,
    PreconditionOptions
} from './storage-reference-types.js';
import { FirebaseEdgeError, ensureError } from '../auth/errors.js';
import type {
    ServiceAccount,
    GoogleTokenResponse
} from '../auth/firebase-types.js';
import type { CacheConfig } from '../auth/cache-types.js';
import { signStorageUrl } from './storage-signed-url.js';
import {
    uploadStorageStream,
    type StorageUploadStreamOptions
} from './storage-upload-stream.js';
export type {
    StorageUploadStreamOptions,
    StoragePartialUpload
} from './storage-upload-stream.js';
import type { StoragePartialUpload } from './storage-upload-stream.js';
export type {
    CRC32CValidator,
    CRC32CValidatorGenerator
} from './storage-checksum.js';
import {
    signStorageXmlRequest,
    type StorageXmlRequestOptions
} from './storage-xml-signing.js';
export { signStorageXmlRequest } from './storage-xml-signing.js';
export type { StorageXmlRequestOptions } from './storage-xml-signing.js';
import {
    createStorageRetryFetch,
    type StorageRetryOptions
} from './storage-retry.js';
import {
    specialStorageRequest,
    storageNotificationTopic,
    validateSpecialOperation
} from './storage-special-endpoints.js';
import type {
    StorageSpecialOperation,
    StorageSpecialResponses,
    StorageNotificationConfig,
    StorageManagedFolderOptions,
    StorageManagedFolderDeleteOptions,
    StorageManagedFolderListOptions,
    StorageHmacListOptions,
    StorageAclTarget,
    StorageAclEntry
} from './storage-special-types.js';
export type {
    StorageNotificationConfig,
    StorageNotification,
    StorageManagedFolder,
    StorageManagedFolderOptions,
    StorageManagedFolderDeleteOptions,
    StorageManagedFolderListOptions,
    StorageHmacKey,
    StorageHmacKeyMetadata,
    StorageHmacListOptions,
    StorageAclTarget,
    StorageAclEntry,
    StoragePage,
    StorageResourceListOptions
} from './storage-special-types.js';
export type { StorageRetryOptions } from './storage-retry.js';
export {
    calculateStorageCrc32c,
    calculateStorageMd5
} from './storage-checksum.js';
import {
    resumableRequest,
    type StorageSessionOperation
} from './storage-resumable.js';
import {
    bucketRequest,
    validateBucketOperation
} from './storage-bucket-endpoints.js';
import type {
    StorageBucketOperation,
    StorageBucketResponses,
    StorageBucketOptions,
    StorageBucketListOptions,
    StorageBucketUpdate,
    StorageBucketCreateOptions,
    StorageIamPolicy
} from './storage-bucket-types.js';
export type {
    StorageBucketMetadata,
    StorageBucketOptions,
    StorageBucketListOptions,
    StorageBucketListResult,
    StorageBucketUpdate,
    StorageBucketCreateOptions,
    StorageIamPolicy,
    StorageCorsRule,
    StorageLifecycleRule
} from './storage-bucket-types.js';
import {
    storageRequest,
    validateStorageOperation
} from './storage-endpoints.js';
import type {
    StorageUploadData,
    StorageUploadOptions,
    StorageDeleteOptions,
    StorageListOptions,
    StorageOperation,
    StorageResponses,
    StorageResult,
    StorageMetadataUpdate,
    StorageMetadataOptions,
    StorageCopyOptions,
    StorageSignedUrlOptions,
    StorageFileMetadata,
    StorageReadOptions,
    StorageDownloadOptions,
    StorageResumableOptions,
    StorageChunkOptions,
    StorageUploadProgress,
    StorageComposeSource,
    StorageComposeOptions,
    StorageRestoreOptions,
    StorageDeleteTarget,
    StorageBatchDeleteOptions,
    StorageBatchDeleteResult
} from './storage-types.js';
export type {
    StorageMetadataUpdate,
    StorageMetadataOptions,
    StorageCopyOptions,
    StorageSignedUrlOptions,
    StorageFileMetadata,
    StorageUploadData,
    StorageUploadOptions,
    StorageDeleteOptions,
    StorageListOptions,
    StorageListResult,
    StorageResult,
    StoragePreconditions,
    StorageReadOptions,
    StorageDownloadOptions,
    StorageResumableOptions,
    StorageChunkOptions,
    StorageUploadProgress,
    StorageComposeSource,
    StorageComposeOptions,
    StorageRestoreOptions,
    StorageDeleteTarget,
    StorageBatchDeleteOptions,
    StorageBatchDeleteResult,
    StorageTransferProgress,
    StorageProgressCallback
} from './storage-types.js';

/** Essential bucket object operations for edge runtimes. */
export function getStorage(server: { storage: Storage }): Storage {
    if (!server || !(server.storage instanceof Storage)) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'getStorage requires a configured FirebaseEdgeServer.'
        });
    }
    return server.storage;
}

/** Firebase Admin-style references and lower-level edge Storage operations. */
export class Storage {
    private readonly fetch: typeof globalThis.fetch;
    constructor(
        private readonly serviceAccount: ServiceAccount,
        readonly bucketName?: string,
        fetch: typeof globalThis.fetch = globalThis.fetch,
        private readonly cache?: CacheConfig,
        private readonly cacheName = '__cache',
        retryOptions?: StorageRetryOptions
    ) {
        this.fetch = createStorageRetryFetch(fetch, retryOptions);
    }

    bucket(
        name = this.bucketName,
        options: import('./storage-reference-types.js').BucketOptions = {}
    ): Bucket {
        validateBucketOperation(name, this.serviceAccount.project_id, {
            kind: 'get',
            options: {}
        });
        const bound =
            name === this.bucketName
                ? this
                : new Storage(
                      this.serviceAccount,
                      name,
                      this.fetch,
                      this.cache,
                      this.cacheName,
                      { maxRetries: 0 }
                  );
        return new Bucket(
            this,
            name!,
            options.userProject === undefined
                ? bound
                : bound.scoped({ userProject: options.userProject }),
            options
        );
    }

    hmacKey(accessId: string): HmacKey {
        validateSpecialOperation(
            this.bucketName,
            this.serviceAccount.project_id,
            { kind: 'hmacGet', accessId }
        );
        return new HmacKey(accessId, this);
    }

    /** @internal Admin reference signing keeps absolute expiration semantics. */
    referenceSignedUrl(name: string | undefined, options: GetSignedUrlOptions) {
        return storageResult(() =>
            signStorageReferenceUrl(
                this.serviceAccount,
                this.bucketName,
                name,
                options,
                (value, endpoint) => this.signReferenceBlob(value, endpoint)
            )
        );
    }

    /** @internal Form policies use the same credentials as other signing operations. */
    referencePostPolicy(
        name: string,
        version: 'v2' | 'v4',
        options: SignedPostPolicyOptions
    ) {
        return storageResult(() =>
            signStoragePostPolicy(
                this.serviceAccount,
                this.bucketName,
                name,
                version,
                options,
                (value, endpoint) => this.signReferenceBlob(value, endpoint)
            )
        );
    }

    private async signReferenceBlob(
        value: string,
        endpoint: string
    ): Promise<ArrayBuffer> {
        const result = await this.getAccessToken();
        const token = storageData(result);
        return storageSignBlob(
            this.serviceAccount.client_email,
            token.access_token,
            value,
            endpoint,
            this.fetch
        );
    }

    /** @internal Bind reference billing/encryption without duplicating endpoint logic. */
    scoped(options: {
        userProject?: string;
        encryptionKey?: string | Uint8Array<ArrayBuffer>;
        kmsKeyName?: string;
        timeout?: number;
    }): Storage {
        const fetch = storageScopedFetch(this.fetch, options);
        return new Storage(
            this.serviceAccount,
            this.bucketName,
            fetch,
            this.cache,
            this.cacheName,
            { maxRetries: 0 }
        );
    }

    /** @internal Authenticate reference requests using the same token cache. */
    requestResource(resource: StorageResource, options: StorageRequestOptions) {
        return storageResult(async () => {
            const result = await this.getAccessToken();
            const token = storageData(result);
            return storageReferenceRequest(
                this.bucketName,
                token.access_token,
                resource,
                options,
                this.fetch
            );
        });
    }

    /** @internal Named advanced operations delegate their request construction to endpoints. */
    referenceAction(resource: StorageResource, action: StorageReferenceAction) {
        return storageResult(async () => {
            const options = storageReferenceActionOptions(action);
            const result = await this.requestResource(resource, options);
            return storageData(result);
        });
    }

    /** @internal Firebase download URLs require Firebase-specific metadata. */
    downloadURL(name: string) {
        return storageResult(async () => {
            validateStorageOperation(this.bucketName, {
                kind: 'metadata',
                name
            });
            const result = await this.getAccessToken();
            const token = storageData(result);
            return storageDownloadURL(
                this.bucketName,
                name,
                token.access_token,
                this.fetch
            );
        });
    }

    /** @internal Anonymous probes must bypass OAuth. */
    objectIsPublic(name: string) {
        return storageResult(() =>
            storageIsPublic(this.bucketName, name, this.fetch)
        );
    }

    upload(
        name: string,
        body: StorageUploadData,
        options: StorageUploadOptions = {}
    ) {
        return this.run({ kind: 'upload', name, body, options });
    }

    download(name: string, options?: StorageDownloadOptions) {
        return this.run({
            kind: 'download',
            name,
            ...(options !== undefined && { options })
        });
    }

    uploadStream(
        name: string,
        body: StorageUploadData | ReadableStream<Uint8Array>,
        options: StorageUploadStreamOptions & { isPartialUpload: true }
    ): Promise<StorageResult<StoragePartialUpload>>;
    uploadStream(
        name: string,
        body: StorageUploadData | ReadableStream<Uint8Array>,
        options?: StorageUploadStreamOptions & { isPartialUpload?: false }
    ): Promise<StorageResult<StorageFileMetadata>>;
    uploadStream(
        name: string,
        body: StorageUploadData | ReadableStream<Uint8Array>,
        options: StorageUploadStreamOptions
    ): Promise<StorageResult<StorageFileMetadata | StoragePartialUpload>>;
    async uploadStream(
        name: string,
        body: StorageUploadData | ReadableStream<Uint8Array>,
        options: StorageUploadStreamOptions = {}
    ): Promise<StorageResult<StorageFileMetadata | StoragePartialUpload>> {
        try {
            validateStorageOperation(this.bucketName, {
                kind: 'metadata',
                name
            });
            const data = await uploadStorageStream(this, name, body, options);
            return { error: null, data };
        } catch (cause) {
            return { error: storageError(cause), data: null };
        }
    }

    getMetadata(name: string, options?: StorageReadOptions) {
        return this.run({
            kind: 'metadata',
            name,
            ...(options !== undefined && { options })
        });
    }

    /** Return a Fetch Response whose body can be streamed directly to the caller. */
    downloadStream(name: string, options?: StorageDownloadOptions) {
        return this.run({
            kind: 'stream',
            name,
            ...(options !== undefined && { options })
        });
    }

    createResumableUpload(name: string, options: StorageResumableOptions = {}) {
        return this.run({ kind: 'resumable', name, options });
    }

    uploadChunk(
        sessionUri: string,
        body: StorageUploadData,
        options: StorageChunkOptions
    ) {
        return this.runSession(sessionUri, { kind: 'chunk', body, options });
    }

    getUploadStatus(sessionUri: string, totalSize?: number) {
        return this.runSession(sessionUri, { kind: 'status', totalSize });
    }

    cancelUpload(sessionUri: string) {
        return this.runSession(sessionUri, { kind: 'cancel' });
    }

    compose(
        destination: string,
        sources: StorageComposeSource[],
        options: StorageComposeOptions = {}
    ) {
        return this.run({
            kind: 'compose',
            name: destination,
            sources,
            options
        });
    }

    restore(name: string, options: StorageRestoreOptions) {
        return this.run({ kind: 'restore', name, options });
    }

    /** Bounded parallel deletion; preserve each object's error without stopping other deletions. */
    async deleteFiles(
        targets: Array<string | StorageDeleteTarget>,
        options: StorageBatchDeleteOptions = {}
    ): Promise<StorageResult<StorageBatchDeleteResult>> {
        try {
            if (
                !Array.isArray(targets) ||
                !options ||
                typeof options !== 'object' ||
                Array.isArray(options)
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message:
                        'Provide an array of delete targets and an options object.'
                });
            }
            const { concurrency = 5, ignoreNotFound = false } = options;
            if (
                !Number.isInteger(concurrency) ||
                concurrency < 1 ||
                concurrency > 32 ||
                typeof ignoreNotFound !== 'boolean'
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message:
                        'concurrency must be an integer from 1 to 32 and ignoreNotFound a boolean.'
                });
            }
            const files = targets.map((target) =>
                typeof target === 'string' ? { name: target } : target
            );
            for (const target of files) {
                if (
                    !target ||
                    typeof target !== 'object' ||
                    Array.isArray(target)
                ) {
                    throw new FirebaseEdgeError({
                        code: 'storage/invalid-argument',
                        message: 'Invalid delete target.'
                    });
                }
                const { name, ...preconditions } = target;
                validateStorageOperation(this.bucketName, {
                    kind: 'delete',
                    name,
                    options: preconditions
                });
            }
            const results: StorageBatchDeleteResult['results'] = new Array(
                files.length
            );
            let next = 0;
            const worker = async () => {
                while (next < files.length) {
                    const index = next++;
                    const { name, ...preconditions } = files[index]!;
                    const { error } = await this.delete(name, preconditions);
                    results[index] = {
                        name,
                        ...(preconditions.generation !== undefined && {
                            generation: preconditions.generation
                        }),
                        error:
                            ignoreNotFound &&
                            error?.code === 'storage/object-not-found'
                                ? null
                                : error
                    };
                }
            };
            await Promise.all(
                Array.from(
                    { length: Math.min(concurrency, files.length) },
                    worker
                )
            );
            return { error: null, data: { results } };
        } catch (cause) {
            return { error: storageError(cause), data: null };
        }
    }

    getBucketMetadata(options: StorageBucketOptions = {}) {
        return this.runBucket({ kind: 'get', options });
    }

    createNotification(config: StorageNotificationConfig) {
        return storageResult(async () => {
            const topic = storageNotificationTopic(
                this.serviceAccount.project_id,
                config?.topic
            );
            const result = await this.runSpecial({
                kind: 'notificationCreate',
                config: { ...config, topic }
            });
            return storageData(result);
        });
    }

    listNotifications() {
        return this.runSpecial({ kind: 'notificationList' });
    }

    getNotification(id: string) {
        return this.runSpecial({ kind: 'notificationGet', id });
    }

    deleteNotification(id: string) {
        return this.runSpecial({ kind: 'notificationDelete', id });
    }

    createManagedFolder(name: string) {
        return this.runSpecial({ kind: 'folderCreate', name });
    }

    getManagedFolder(name: string, options: StorageManagedFolderOptions = {}) {
        return this.runSpecial({ kind: 'folderGet', name, options });
    }

    listManagedFolders(options: StorageManagedFolderListOptions = {}) {
        return this.runSpecial({ kind: 'folderList', options });
    }

    deleteManagedFolder(
        name: string,
        options: StorageManagedFolderDeleteOptions = {}
    ) {
        return this.runSpecial({ kind: 'folderDelete', name, options });
    }

    getManagedFolderIamPolicy(name: string) {
        return this.runSpecial({ kind: 'folderGetIam', name });
    }

    setManagedFolderIamPolicy(name: string, policy: StorageIamPolicy) {
        return this.runSpecial({ kind: 'folderSetIam', name, policy });
    }

    testManagedFolderIamPermissions(name: string, permissions: string[]) {
        return this.runSpecial({ kind: 'folderTestIam', name, permissions });
    }

    createHmacKey(serviceAccountEmail: string) {
        return this.runSpecial({ kind: 'hmacCreate', serviceAccountEmail });
    }

    listHmacKeys(options: StorageHmacListOptions = {}) {
        return this.runSpecial({ kind: 'hmacList', options });
    }

    getHmacKey(accessId: string) {
        return this.runSpecial({ kind: 'hmacGet', accessId });
    }

    updateHmacKey(
        accessId: string,
        state: 'ACTIVE' | 'INACTIVE',
        etag?: string
    ) {
        return this.runSpecial({
            kind: 'hmacUpdate',
            accessId,
            state,
            ...(etag !== undefined && { etag })
        });
    }

    deleteHmacKey(accessId: string) {
        return this.runSpecial({ kind: 'hmacDelete', accessId });
    }

    listAcl(target: StorageAclTarget) {
        return this.runSpecial({ kind: 'aclList', target });
    }

    getAcl(target: StorageAclTarget, entity: string) {
        return this.runSpecial({ kind: 'aclGet', target, entity });
    }

    createAcl(target: StorageAclTarget, entry: StorageAclEntry) {
        return this.runSpecial({ kind: 'aclCreate', target, entry });
    }

    updateAcl(target: StorageAclTarget, entry: StorageAclEntry) {
        return this.runSpecial({ kind: 'aclUpdate', target, entry });
    }

    deleteAcl(target: StorageAclTarget, entity: string) {
        return this.runSpecial({ kind: 'aclDelete', target, entity });
    }

    updateBucketMetadata(
        metadata: StorageBucketUpdate,
        options: StorageBucketOptions = {}
    ) {
        return this.runBucket({ kind: 'update', metadata, options });
    }

    createBucket(metadata: StorageBucketCreateOptions) {
        return this.runBucket({ kind: 'create', metadata });
    }

    deleteBucket(options: StorageBucketOptions = {}) {
        return this.runBucket({ kind: 'delete', options });
    }

    /** Irreversibly lock the existing bucket retention policy. */
    lockRetentionPolicy(ifMetagenerationMatch: string) {
        return this.runBucket({
            kind: 'lockRetention',
            options: { ifMetagenerationMatch }
        });
    }

    async signXmlRequest(
        options: StorageXmlRequestOptions
    ): Promise<StorageResult<Request>> {
        try {
            const data = await signStorageXmlRequest(
                this.serviceAccount,
                this.bucketName,
                options
            );
            return { error: null, data };
        } catch (cause) {
            return { error: storageError(cause), data: null };
        }
    }

    listBuckets(options: StorageBucketListOptions = {}) {
        return this.runBucket({ kind: 'list', options });
    }

    getIamPolicy(options?: {
        requestedPolicyVersion?: 1 | 3;
        userProject?: string;
    }) {
        return this.runBucket({ kind: 'getIam', ...options });
    }

    setIamPolicy(policy: StorageIamPolicy) {
        return this.runBucket({ kind: 'setIam', policy });
    }

    testIamPermissions(permissions: string[]) {
        return this.runBucket({ kind: 'testIam', permissions });
    }

    delete(name: string, options: StorageDeleteOptions = {}) {
        return this.run({ kind: 'delete', name, options });
    }

    listFiles(options: StorageListOptions = {}) {
        return this.run({ kind: 'list', options });
    }

    async getSignedUrl(
        name: string,
        options: StorageSignedUrlOptions
    ): Promise<StorageResult<string>> {
        try {
            const data = await signStorageUrl(
                this.serviceAccount,
                this.bucketName,
                name,
                options
            );
            return { error: null, data };
        } catch (cause) {
            return { error: storageError(cause), data: null };
        }
    }

    updateMetadata(
        name: string,
        metadata: StorageMetadataUpdate,
        options: StorageMetadataOptions = {}
    ) {
        return this.run({ kind: 'updateMetadata', name, metadata, options });
    }

    async exists(
        name: string,
        options?: StorageReadOptions
    ): Promise<StorageResult<boolean>> {
        const { error } = await this.getMetadata(name, options);
        if (error?.code === 'storage/object-not-found') {
            return { error: null, data: false };
        }
        if (error) {
            return { error, data: null };
        }
        return { error: null, data: true };
    }

    copy(name: string, destination: string, options: StorageCopyOptions = {}) {
        return this.run({ kind: 'copy', name, destination, options });
    }

    /** Copy then delete, protecting the source against concurrent replacement. */
    async move(
        name: string,
        destination: string,
        options: StorageCopyOptions = {}
    ): Promise<StorageResult<StorageFileMetadata>> {
        try {
            if (
                options &&
                (options.destinationBucket === undefined ||
                    options.destinationBucket === this.bucketName) &&
                name === destination
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message:
                        'A move requires different source and destination objects.'
                });
            }
            validateStorageOperation(this.bucketName, {
                kind: 'copy',
                name,
                destination,
                options
            });
            const { error: metadataError, data: source } =
                await this.getMetadata(
                    name,
                    options.sourceGeneration === undefined
                        ? undefined
                        : { generation: options.sourceGeneration }
                );
            if (metadataError) {
                return { error: metadataError, data: null };
            }
            if (
                options.ifSourceGenerationMatch !== undefined &&
                options.ifSourceGenerationMatch !== source.generation
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/precondition-failed',
                    message: 'The source generation does not match.'
                });
            }

            const { error: copyError, data: copied } = await this.copy(
                name,
                destination,
                { ...options, ifSourceGenerationMatch: source.generation }
            );
            if (copyError) {
                return { error: copyError, data: null };
            }

            const { error: deleteError } = await this.delete(name, {
                ifGenerationMatch: source.generation,
                ...(options.sourceGeneration !== undefined && {
                    generation: options.sourceGeneration
                })
            });
            if (deleteError) {
                throw new FirebaseEdgeError(
                    {
                        code: 'storage/move-incomplete',
                        message:
                            'The destination was copied, but the source could not be deleted.'
                    },
                    {
                        cause: deleteError,
                        context: {
                            sourceBucket: this.bucketName,
                            sourceName: name,
                            sourceGeneration: source.generation,
                            destinationBucket: copied.bucket,
                            destinationName: copied.name,
                            destinationGeneration: copied.generation
                        }
                    }
                );
            }
            return { error: null, data: copied };
        } catch (cause) {
            return { error: storageError(cause), data: null };
        }
    }

    private async runSession<K extends StorageSessionOperation['kind']>(
        sessionUri: string,
        operation: StorageSessionOperation & { kind: K }
    ): Promise<
        StorageResult<K extends 'cancel' ? void : StorageUploadProgress>
    > {
        try {
            const data = await resumableRequest<K>(
                sessionUri,
                operation,
                this.fetch
            );
            return { error: null, data };
        } catch (cause) {
            return { error: storageError(cause), data: null };
        }
    }

    private async runSpecial<K extends StorageSpecialOperation['kind']>(
        operation: StorageSpecialOperation & { kind: K }
    ): Promise<StorageResult<StorageSpecialResponses[K]>> {
        try {
            validateSpecialOperation(
                this.bucketName,
                this.serviceAccount.project_id,
                operation
            );
            const { error, data } = await this.getAccessToken();
            if (error) {
                return { error, data: null };
            }
            const response = await specialStorageRequest<K>(
                this.bucketName,
                this.serviceAccount.project_id,
                data.access_token,
                operation,
                this.fetch
            );
            return { error: null, data: response };
        } catch (cause) {
            return { error: storageError(cause), data: null };
        }
    }

    private async runBucket<K extends StorageBucketOperation['kind']>(
        operation: StorageBucketOperation & { kind: K }
    ): Promise<StorageResult<StorageBucketResponses[K]>> {
        try {
            validateBucketOperation(
                this.bucketName,
                this.serviceAccount.project_id,
                operation
            );
            const { error, data } = await this.getAccessToken();
            if (error) {
                return { error, data: null };
            }
            const response = await bucketRequest<K>(
                this.bucketName,
                this.serviceAccount.project_id,
                data.access_token,
                operation,
                this.fetch
            );
            return { error: null, data: response };
        } catch (cause) {
            return { error: storageError(cause), data: null };
        }
    }

    private async getAccessToken() {
        const key = `${this.cacheName}:storage:${this.serviceAccount.client_email}`;
        const cached = await this.cache?.getCache<GoogleTokenResponse>(key);
        if (cached?.access_token) {
            return { error: null, data: cached };
        }
        const { error, data } = await getToken(this.serviceAccount, this.fetch);
        if (error) {
            return { error, data: null };
        }
        const ttlMs = (data.expires_in - 60) * 1000;
        if (Number.isFinite(ttlMs) && ttlMs > 0) {
            await this.cache?.setCache(key, data, ttlMs);
        }
        return { error: null, data };
    }

    private async run<K extends StorageOperation['kind']>(
        operation: StorageOperation & { kind: K }
    ): Promise<StorageResult<StorageResponses[K]>> {
        try {
            const bucket = this.bucketName;
            validateStorageOperation(bucket, operation);

            const { error, data } = await this.getAccessToken();
            if (error) {
                return { error, data: null };
            }

            const response = await storageRequest<K>(
                bucket,
                data.access_token,
                operation,
                this.fetch
            );
            return { error: null, data: response };
        } catch (cause) {
            return { error: storageError(cause), data: null };
        }
    }
}

/** @internal Keep all public methods on the same error convention. */
function storageError(cause: unknown): FirebaseEdgeError {
    if (cause instanceof FirebaseEdgeError) {
        return cause;
    }
    return new FirebaseEdgeError(
        {
            code: 'storage/internal-error',
            message: 'Storage operation failed.'
        },
        { cause: ensureError(cause) }
    );
}
