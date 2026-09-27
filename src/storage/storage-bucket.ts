import { FirebaseEdgeError } from '../auth/errors.js';
import type { Storage } from './storage.js';
import { File } from './storage-file.js';
import { Acl } from './storage-acl.js';
import { Iam } from './storage-iam.js';
import { Notification } from './storage-notification.js';
import { Channel } from './storage-channel.js';
import {
    storageResult,
    storageData,
    storageUnsupported
} from './storage-results.js';
import {
    storagePreconditions,
    storageGeneration,
    storageLoggingPolicy
} from './storage-reference-helpers.js';
import type {
    FileOptions,
    BucketOptions,
    GetFilesOptions,
    SaveOptions,
    PreconditionOptions,
    GetSignedUrlOptions
} from './storage-reference-types.js';
import type {
    StorageBucketMetadata,
    StorageBucketCreateOptions,
    StorageBucketUpdate,
    StorageCorsRule,
    StorageLifecycleRule
} from './storage-bucket-types.js';
import type {
    StorageComposeOptions,
    StorageUploadData
} from './storage-types.js';
import type { StorageRequestOptions } from './storage-reference-endpoints.js';
import type { StorageNotificationConfig } from './storage-special-types.js';

export interface GetFilesData {
    files: File[];
    prefixes: string[];
    nextQuery?: GetFilesOptions;
}

/** A bucket reference; object operations are accessed through file(name). */
export class Bucket {
    metadata?: StorageBucketMetadata;
    readonly acl: Acl & { default: Acl };
    readonly iam: Iam;
    constructor(
        readonly storage: Storage,
        readonly name: string,
        public engine: Storage,
        private readonly options: BucketOptions = {}
    ) {
        this.acl = Object.assign(
            new Acl(() => this.engine, { scope: 'bucket' }),
            { default: new Acl(() => this.engine, { scope: 'defaultObject' }) }
        );
        this.iam = new Iam(() => this.engine);
    }
    get cloudStorageURI() {
        return new URL(`gs://${this.name}`);
    }
    getId() {
        return this.name;
    }
    file(name: string, options: FileOptions = {}) {
        return new File(this, name, {
            crc32cGenerator: this.options.crc32cGenerator,
            kmsKeyName: this.options.kmsKeyName,
            preconditionOpts: this.options.preconditionOpts,
            ...options
        });
    }
    notification(id: string) {
        return new Notification(this, id, this.engine);
    }

    getMetadata(options: PreconditionOptions = {}) {
        return storageResult(async () => {
            const result = await this.engine.getBucketMetadata({
                ...storagePreconditions(this.options.preconditionOpts),
                ...storagePreconditions(options),
                ...(this.options.generation !== undefined && {
                    generation: storageGeneration(this.options.generation)
                }),
                ...(this.options.softDeleted !== undefined && {
                    softDeleted: this.options.softDeleted
                })
            });
            this.metadata = storageData(result);
            return this.metadata;
        });
    }
    get(
        options: {
            autoCreate?: boolean;
            userProject?: string;
        } & Partial<StorageBucketCreateOptions> = {}
    ) {
        return storageResult(async () => {
            const { error } = await this.getMetadata({
                ...(options.userProject !== undefined && {
                    userProject: options.userProject
                })
            });
            if (
                error?.code === 'storage/bucket-not-found' &&
                options.autoCreate
            ) {
                const { autoCreate, userProject, ...createOptions } = options;
                const result = await this.create({
                    ...createOptions,
                    location: options.location ?? 'US'
                });
                return storageData(result);
            }
            if (error) {
                throw error;
            }
            return this;
        });
    }
    async exists(options: PreconditionOptions = {}) {
        const { error } = await this.getMetadata(options);
        if (error?.code === 'storage/bucket-not-found') {
            return { error: null, data: false } as const;
        }
        if (error) {
            return { error, data: null } as const;
        }
        return { error: null, data: true } as const;
    }
    create(options: StorageBucketCreateOptions = { location: 'US' }) {
        return storageResult(async () => {
            const result = await this.engine.createBucket(options);
            this.metadata = storageData(result);
            return this;
        });
    }
    setMetadata(
        metadata: StorageBucketUpdate,
        options: PreconditionOptions = {}
    ) {
        return storageResult(async () => {
            const result = await this.engine.updateBucketMetadata(
                metadata,
                storagePreconditions(options)
            );
            this.metadata = storageData(result);
            return this.metadata;
        });
    }
    delete(options: PreconditionOptions & { ignoreNotFound?: boolean } = {}) {
        return storageResult(async () => {
            const result = await this.engine.deleteBucket(
                storagePreconditions(options)
            );
            const { error } = result;
            if (
                options.ignoreNotFound &&
                error?.code === 'storage/bucket-not-found'
            ) {
                return;
            }
            return storageData(result);
        });
    }

    getFiles(options: GetFilesOptions = {}) {
        return storageResult(async (): Promise<GetFilesData> => {
            const {
                autoPaginate = true,
                maxApiCalls = Infinity,
                ...query
            } = options;
            if (
                typeof autoPaginate !== 'boolean' ||
                !(
                    maxApiCalls === Infinity ||
                    (Number.isInteger(maxApiCalls) && maxApiCalls > 0)
                )
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'Invalid pagination options.'
                });
            }
            const files: File[] = [];
            const prefixes = new Set<string>();
            let pageToken = query.pageToken;
            const seen = new Set<string>();
            let calls = 0;
            do {
                if (pageToken && seen.has(pageToken)) {
                    throw new FirebaseEdgeError({
                        code: 'storage/internal-error',
                        message: 'Storage returned a repeated page token.'
                    });
                }
                if (pageToken) {
                    seen.add(pageToken);
                }
                const result = await this.engine.listFiles({
                    ...query,
                    pageToken
                });
                const page = storageData(result);
                for (const prefix of page.prefixes ?? []) {
                    prefixes.add(prefix);
                }
                for (const metadata of page.files) {
                    const file = this.file(
                        metadata.name,
                        query.versions || query.softDeleted
                            ? {
                                  generation: metadata.generation,
                                  restoreToken: metadata.restoreToken
                              }
                            : {}
                    );
                    file.metadata = metadata;
                    files.push(file);
                }
                pageToken = page.nextPageToken;
                calls++;
            } while (pageToken && autoPaginate && calls < maxApiCalls);
            return {
                files,
                prefixes: [...prefixes],
                ...(pageToken && { nextQuery: { ...options, pageToken } })
            };
        });
    }

    getFilesStream(options: GetFilesOptions = {}): ReadableStream<File> {
        let query: GetFilesOptions | undefined = {
            ...options,
            autoPaginate: false
        };
        let pending: File[] = [];
        const bucket = this;
        const seen = new Set<string>();
        let calls = 0;
        let cancelled = false;
        return new ReadableStream<File>(
            {
                async pull(controller) {
                    try {
                        while (!pending.length && query) {
                            if (query.pageToken && seen.has(query.pageToken)) {
                                throw new FirebaseEdgeError({
                                    code: 'storage/internal-error',
                                    message: 'Repeated file page token.'
                                });
                            }
                            if (query.pageToken) {
                                seen.add(query.pageToken);
                            }
                            const result = await bucket.getFiles(query);
                            if (cancelled) {
                                return;
                            }

                            const { files, nextQuery } = storageData(result);
                            pending = files;
                            calls++;
                            query =
                                calls < (options.maxApiCalls ?? Infinity)
                                    ? nextQuery
                                    : undefined;
                        }
                        if (!pending.length) {
                            controller.close();
                            return;
                        }
                        controller.enqueue(pending.shift()!);
                    } catch (cause) {
                        if (cancelled) {
                            return;
                        }
                        controller.error(cause);
                    }
                },
                cancel() {
                    cancelled = true;
                    query = undefined;
                    pending = [];
                }
            },
            { highWaterMark: 0 }
        );
    }

    upload(
        input:
            | Exclude<StorageUploadData, string>
            | ReadableStream<Uint8Array>
            | string,
        options: SaveOptions & {
            destination?: string | File;
            encryptionKey?: string | Uint8Array<ArrayBuffer>;
        } = {}
    ) {
        return storageResult(async () => {
            if (typeof input === 'string') {
                storageUnsupported(
                    'Uploading from a filesystem path; use file.save(text) for strings'
                );
            }
            const destination =
                options.destination ??
                (typeof globalThis.File !== 'undefined' &&
                input instanceof globalThis.File
                    ? input.name
                    : undefined);
            if (!destination) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message:
                        'A destination is required for byte/stream uploads.'
                });
            }
            const file =
                destination instanceof File
                    ? destination
                    : this.file(destination, {
                          encryptionKey: options.encryptionKey,
                          kmsKeyName: options.kmsKeyName
                      });
            if (
                destination instanceof File &&
                options.encryptionKey !== undefined
            ) {
                file.setEncryptionKey(options.encryptionKey);
            }
            const result = await file.save(input, options);
            storageData(result);
            return file;
        });
    }

    deleteFiles(
        options: GetFilesOptions &
            PreconditionOptions & {
                force?: boolean;
                concurrency?: number;
            } = {}
    ) {
        return storageResult(async () => {
            const {
                force = false,
                concurrency,
                ifGenerationMatch,
                ifGenerationNotMatch,
                ifMetagenerationMatch,
                ifMetagenerationNotMatch,
                ...query
            } = options;
            const preconditions = storagePreconditions(options);
            const result = await this.getFiles(query);
            const { files } = storageData(result);
            const deleted = await this.engine.deleteFiles(
                files.map((file) => ({
                    ...preconditions,
                    name: file.name,
                    generation: file.generation
                })),
                { concurrency, ignoreNotFound: force }
            );
            const data = storageData(deleted);
            const failures = data.results.flatMap(({ error }) =>
                error ? [error] : []
            );
            if (failures.length) {
                throw new FirebaseEdgeError(
                    {
                        code: 'storage/batch-incomplete',
                        message: 'Some objects could not be deleted.'
                    },
                    { context: { failures: failures.length } }
                );
            }
        });
    }

    combine(
        sources: Array<string | File>,
        destination: string | File,
        options: Omit<StorageComposeOptions, keyof PreconditionOptions> &
            PreconditionOptions = {}
    ) {
        return storageResult(async () => {
            const target =
                destination instanceof File
                    ? destination
                    : this.file(destination);
            if (
                target.bucket.name !== this.name ||
                sources.some(
                    (source) =>
                        source instanceof File &&
                        source.bucket.name !== this.name
                )
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'Composition requires one bucket.'
                });
            }
            const result = await this.engine.compose(
                target.name,
                sources.map((source) =>
                    typeof source === 'string'
                        ? { name: source }
                        : { name: source.name, generation: source.generation }
                ),
                {
                    ...options,
                    ...storagePreconditions(options)
                } as StorageComposeOptions
            );
            target.metadata = storageData(result);
            return target;
        });
    }

    getLabels(options: { userProject?: string } = {}) {
        return storageResult(async () => {
            const result = await this.getMetadata(options);
            return storageData(result).labels ?? {};
        });
    }
    setLabels(
        labels: Record<string, string | null>,
        options: PreconditionOptions = {}
    ) {
        return this.setMetadata({ labels }, options);
    }
    deleteLabels(
        labels?: string | string[],
        options: PreconditionOptions = {}
    ) {
        return storageResult(async () => {
            const result = await this.getMetadata(options);
            const metadata = storageData(result);
            const keys =
                labels === undefined
                    ? Object.keys(metadata.labels ?? {})
                    : typeof labels === 'string'
                      ? [labels]
                      : labels;
            const updated = await this.setLabels(
                Object.fromEntries(keys.map((key) => [key, null])),
                { ifMetagenerationMatch: metadata.metageneration, ...options }
            );
            return storageData(updated);
        });
    }
    setCorsConfiguration(
        cors: StorageCorsRule[],
        options: PreconditionOptions = {}
    ) {
        return this.setMetadata({ cors }, options);
    }
    setStorageClass(storageClass: string, options: PreconditionOptions = {}) {
        return this.setMetadata({ storageClass }, options);
    }
    setRetentionPeriod(
        seconds: string | number,
        options: PreconditionOptions = {}
    ) {
        return storageResult(async () => {
            const result = await this.setMetadata(
                {
                    retentionPolicy: {
                        retentionPeriod: storageGeneration(seconds)
                    }
                },
                options
            );
            return storageData(result);
        });
    }
    removeRetentionPeriod(options: PreconditionOptions = {}) {
        return this.setMetadata({ retentionPolicy: null }, options);
    }
    lock(metageneration: string | number) {
        return storageResult(async () => {
            const result = await this.engine.lockRetentionPolicy(
                storageGeneration(metageneration)
            );
            return storageData(result);
        });
    }
    enableRequesterPays(options: PreconditionOptions = {}) {
        return this.setMetadata({ billing: { requesterPays: true } }, options);
    }
    disableRequesterPays(options: PreconditionOptions = {}) {
        return this.setMetadata({ billing: { requesterPays: false } }, options);
    }
    enableLogging(
        options: {
            bucket?: string | Bucket;
            prefix: string;
        } & PreconditionOptions
    ) {
        return storageResult(async () => {
            if (!options || typeof options.prefix !== 'string') {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'Logging requires an object-name prefix.'
                });
            }
            const destination =
                options.bucket === undefined
                    ? this
                    : typeof options.bucket === 'string'
                      ? this.storage.bucket(options.bucket)
                      : options.bucket;
            for (let attempt = 0; attempt < 3; attempt++) {
                const current = await destination.iam.getPolicy();
                const policy = storageLoggingPolicy(storageData(current));
                if (!policy) {
                    break;
                }
                const { error } = await destination.iam.setPolicy(policy);
                if (!error) {
                    break;
                }
                if (
                    attempt === 2 ||
                    ![
                        'storage/conflict',
                        'storage/precondition-failed'
                    ].includes(error.code ?? '')
                ) {
                    throw error;
                }
            }
            const result = await this.setMetadata(
                {
                    logging: {
                        logBucket: destination.name,
                        logObjectPrefix: options.prefix
                    }
                },
                storagePreconditions(options)
            );
            return storageData(result);
        });
    }
    restore(options: {
        generation: string | number;
        projection?: 'full' | 'noAcl';
    }) {
        return storageResult(async () => {
            const result = await this.engine.referenceAction(
                { kind: 'bucket' },
                {
                    kind: 'restoreBucket',
                    ...(options.projection !== undefined && {
                        projection: options.projection
                    }),
                    generation: storageGeneration(options.generation)
                }
            );
            this.metadata = storageData(
                result
            ) as unknown as StorageBucketMetadata;
            return this;
        });
    }
    createChannel(
        id: string,
        config: {
            address: string;
            type?: 'web_hook';
            token?: string;
            expiration?: string;
        },
        options: { userProject?: string } = {}
    ) {
        return storageResult(async () => {
            const engine =
                options.userProject === undefined
                    ? this.engine
                    : this.engine.scoped(options);
            const result = await engine.referenceAction(
                { kind: 'bucket' },
                { kind: 'watch', id, config }
            );
            const metadata = storageData(result);
            if (typeof metadata.resourceId !== 'string') {
                throw new FirebaseEdgeError({
                    code: 'storage/internal-error',
                    message: 'Missing channel resource ID.'
                });
            }
            return new Channel(id, metadata.resourceId, engine);
        });
    }
    addLifecycleRule(
        rules: StorageLifecycleRule | StorageLifecycleRule[],
        options: { append?: boolean } = {}
    ) {
        return storageResult(async () => {
            const result = await this.getMetadata();
            const metadata = storageData(result);
            const previous =
                options.append === false
                    ? []
                    : (metadata.lifecycle?.rule ?? []);
            const updated = await this.setMetadata(
                {
                    lifecycle: {
                        rule: [
                            ...previous,
                            ...(Array.isArray(rules) ? rules : [rules])
                        ]
                    }
                },
                { ifMetagenerationMatch: metadata.metageneration }
            );
            return storageData(updated);
        });
    }

    createNotification(
        topic: string,
        options: Omit<StorageNotificationConfig, 'topic' | 'payload_format'> & {
            payloadFormat?: 'JSON_API_V1' | 'NONE';
            eventTypes?: StorageNotificationConfig['event_types'];
            objectNamePrefix?: string;
            customAttributes?: Record<string, string>;
            userProject?: string;
        } = {}
    ) {
        return storageResult(async () => {
            const engine =
                options.userProject === undefined
                    ? this.engine
                    : this.engine.scoped({ userProject: options.userProject });
            const result = await engine.createNotification({
                topic: topic.startsWith('//pubsub.googleapis.com/')
                    ? topic
                    : `//pubsub.googleapis.com/${topic}`,
                payload_format: options.payloadFormat ?? 'JSON_API_V1',
                event_types: options.eventTypes ?? options.event_types,
                object_name_prefix:
                    options.objectNamePrefix ?? options.object_name_prefix,
                custom_attributes:
                    options.customAttributes ?? options.custom_attributes
            });
            const metadata = storageData(result);
            const notification = new Notification(this, metadata.id, engine);
            notification.metadata = metadata;
            return notification;
        });
    }
    getNotifications(options: { userProject?: string } = {}) {
        return storageResult(async () => {
            const engine =
                options.userProject === undefined
                    ? this.engine
                    : this.engine.scoped(options);
            const result = await engine.listNotifications();
            return storageData(result).items.map((metadata) => {
                const notification = new Notification(
                    this,
                    metadata.id,
                    engine
                );
                notification.metadata = metadata;
                return notification;
            });
        });
    }
    makePublic(options: { includeFiles?: boolean; force?: boolean } = {}) {
        return storageResult(async () => {
            const result = await this.acl.add({
                entity: 'allUsers',
                role: 'READER'
            });
            storageData(result);
            const defaults = await this.acl.default.add({
                entity: 'allUsers',
                role: 'READER'
            });
            storageData(defaults);
            return this.updateFileVisibility(true, options);
        });
    }
    makePrivate(
        options: {
            includeFiles?: boolean;
            force?: boolean;
            preconditionOpts?: PreconditionOptions;
            userProject?: string;
            metadata?: StorageBucketUpdate;
        } = {}
    ) {
        return storageResult(async () => {
            const result = await this.engine.referenceAction(
                { kind: 'bucket' },
                {
                    kind: 'makePrivate',
                    ...(options.metadata && {
                        metadata: options.metadata as Record<string, unknown>
                    }),
                    preconditions: storagePreconditions({
                        ...options.preconditionOpts,
                        ...(options.userProject !== undefined && {
                            userProject: options.userProject
                        })
                    }) as Record<string, string>
                }
            );
            storageData(result);
            return this.updateFileVisibility(false, options);
        });
    }
    private async updateFileVisibility(
        isPublic: boolean,
        options: { includeFiles?: boolean; force?: boolean }
    ): Promise<File[]> {
        if (!options.includeFiles) {
            return [];
        }
        const result = await this.getFiles();
        const { files } = storageData(result);
        const failures: unknown[] = [];
        for (const file of files) {
            const { error } = isPublic
                ? await file.makePublic()
                : await file.makePrivate();
            if (!error) {
                continue;
            }
            if (!options.force) {
                throw error;
            }
            failures.push(error);
        }
        if (failures.length) {
            throw new FirebaseEdgeError(
                {
                    code: 'storage/batch-incomplete',
                    message: 'Some object ACL updates failed.'
                },
                { context: { failures: failures.length } }
            );
        }
        return files;
    }
    getSignedUrl(options: GetSignedUrlOptions) {
        return this.engine.referenceSignedUrl(undefined, options);
    }
    setUserProject(userProject: string) {
        this.engine = this.engine.scoped({ userProject });
        return this;
    }
    request(options: StorageRequestOptions) {
        return this.engine.requestResource({ kind: 'bucket' }, options);
    }
}
