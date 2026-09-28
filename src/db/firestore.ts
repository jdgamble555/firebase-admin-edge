import {
    type FirestoreResult,
    firestoreResult,
    firestoreData
} from './firestore-results.js';
export type { FirestoreResult } from './firestore-results.js';
import { traceFirestoreOperation } from './firestore-telemetry.js';
import type { FirestoreOpenTelemetryOptions } from './firestore-settings.js';
export { setLogFunction, GrpcStatus } from './firestore-logging.js';
export type * from './firestore-types.js';
import { PipelineSource, type PipelineResponse } from './pipeline.js';
export * as Pipelines from './pipeline.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';
export { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { CacheConfig } from '../auth/cache-types.js';
import type {
    ServiceAccount,
    GoogleTokenResponse
} from '../auth/firebase-types.js';
import { getToken } from '../auth/google-oauth.js';
import {
    getDocument,
    executePipeline,
    streamPipeline,
    runQuery,
    createDocumentName,
    commitWrites,
    batchWrite,
    beginTransaction,
    rollbackTransaction,
    runAggregate,
    batchGetDocuments,
    listCollectionIds,
    listDocumentPaths,
    streamQuery,
    partitionQuery,
    configureFirestoreFetch,
    streamQueryRows,
    type QueryRow
} from './firestore-endpoints.js';
import { WriteBatch } from './write-batch.js';
import { Transaction } from './transaction.js';
import { BulkWriter, type BulkWriterOptions } from './bulk-writer.js';
import { Timestamp } from './timestamp.js';
import { CollectionGroup } from './collection-group.js';
import { BundleBuilder } from './bundle-builder.js';
import { deleteRecursively } from './recursive-delete.js';
export { CollectionGroup } from './collection-group.js';
export { QueryPartition } from './query-partition.js';
export { BundleBuilder } from './bundle-builder.js';
export type { BulkWriterOptions } from './bulk-writer.js';
import {
    DocumentSnapshot,
    QueryDocumentSnapshot
} from './document-snapshot.js';
import {
    normalizeSnapshotDocument,
    normalizeSnapshotTimestamp,
    type SnapshotDocument,
    type SnapshotTimestamp
} from './firestore-document.js';
export type {
    SnapshotDocument,
    SnapshotTimestamp
} from './firestore-document.js';
import { validateFieldPath, type QueryOptions } from './query-request.js';
import { validateSettings, type Settings } from './firestore-settings.js';
export type {
    Settings,
    FirestoreOpenTelemetryOptions
} from './firestore-settings.js';
import { FieldPath } from './field-path.js';
import type { ExplainOptions } from './explain.js';
export type {
    ExplainOptions,
    ExplainResults,
    ExplainMetrics,
    PlanSummary,
    ExecutionStats
} from './explain.js';
export type { DocumentChange } from './query.js';
export type { SnapshotListenOptions } from './snapshot-listener.js';
import type { FirestoreDocument } from './firestore-document.js';
import type { DocumentData } from './firestore-document.js';
import type { AggregateSpec, AggregateData } from './aggregate.js';
import type { WriteOperation, WriteResult } from './write-request.js';
import { CollectionReference } from './collection-reference.js';
import { DocumentReference } from './document-reference.js';
export { DocumentReference } from './document-reference.js';
export { CollectionReference } from './collection-reference.js';
export { Query, QuerySnapshot } from './query.js';
export { DocumentSnapshot } from './document-snapshot.js';
export { QueryDocumentSnapshot } from './query-document-snapshot.js';
export type { WhereFilterOp } from './query.js';
export type { DocumentData } from './firestore-document.js';
export { WriteBatch } from './write-batch.js';
export { WriteResult } from './write-request.js';
export type { SetOptions, Precondition } from './write-batch.js';
export { Transaction } from './transaction.js';
export { BulkWriter, BulkWriterError } from './bulk-writer.js';
export { Timestamp } from './timestamp.js';
export { VectorValue } from './vector-value.js';
export { VectorQuery, VectorQuerySnapshot } from './vector-query.js';
export type { VectorQueryOptions } from './vector-query.js';
export { GeoPoint } from './geo-point.js';
export { Bytes } from './bytes.js';
export { FieldPath } from './field-path.js';
export { FieldValue } from './field-value.js';
export { Filter } from './filter.js';
export {
    AggregateField,
    AggregateQuery,
    AggregateQuerySnapshot
} from './aggregate.js';
export type {
    AggregateSpec,
    AggregateData,
    AggregateType,
    AggregateFieldType,
    AggregateSpecData
} from './aggregate.js';
export type { FirestoreDataConverter } from './firestore-converter.js';
export interface ReadOptions {
    fieldMask?: (string | FieldPath)[];
}
export interface ReadWriteTransactionOptions {
    readOnly?: false;
    maxAttempts?: number;
}
export interface ReadOnlyTransactionOptions {
    readOnly: true;
    readTime?: Timestamp;
}

export interface FirestoreOptions {
    databaseId?: string;
    fetch?: typeof globalThis.fetch;
    cache?: CacheConfig;
    cacheName?: string;
}

/** Service-account Firestore operations for edge runtimes. */
export class Firestore {
    private _databaseId: string;
    private fetch?: typeof globalThis.fetch;
    private cache?: CacheConfig;
    private cacheName: string;
    private telemetry?: FirestoreOpenTelemetryOptions;
    /** @internal Share operation tracing across references, queries, and writes. */
    _trace<T>(name: string, operation: () => Promise<T>): Promise<T> {
        return traceFirestoreOperation(name, this.telemetry, operation);
    }

    /** @internal Pipeline streams participate in termination and cancellation. */
    async *_streamPipeline(
        request: object,
        signal: AbortSignal,
        readTime?: Timestamp
    ): AsyncGenerator<Partial<FirestoreDocument>> {
        this.assertActive();
        const controller = new AbortController();
        this.streams.add(controller);
        const combined = AbortSignal.any([signal, controller.signal]);
        try {
            const token = await this.getCachedToken();
            combined.throwIfAborted();
            yield* streamPipeline(
                this.projectId,
                this.databaseId,
                request,
                token.access_token,
                this.fetch,
                combined,
                readTime
            );
        } finally {
            this.streams.delete(controller);
        }
    }
    pipeline(): PipelineSource {
        this.assertActive();
        return new PipelineSource(this);
    }
    /** @internal Coordinate authenticated pipeline execution. */
    async _executePipeline(
        request: object,
        transaction?: string,
        readTime?: Timestamp
    ): Promise<PipelineResponse> {
        const token = await this.getCachedToken();
        return executePipeline(
            this.projectId,
            this.databaseId,
            request,
            token.access_token,
            this.fetch,
            transaction,
            readTime
        );
    }

    snapshot_(
        documentName: string,
        readTime?: SnapshotTimestamp,
        encoding?: 'json' | 'protobufJS'
    ): DocumentSnapshot;
    snapshot_(
        document: SnapshotDocument,
        readTime: SnapshotTimestamp,
        encoding?: 'json' | 'protobufJS'
    ): QueryDocumentSnapshot;
    snapshot_(
        documentOrName: SnapshotDocument | string,
        readTime?: SnapshotTimestamp,
        encoding: 'json' | 'protobufJS' = 'protobufJS'
    ): DocumentSnapshot {
        if (encoding !== 'json' && encoding !== 'protobufJS')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message:
                    'Unsupported snapshot encoding. Expected json or protobufJS.'
            });
        this.assertActive();
        const time =
            readTime === undefined
                ? Timestamp.now()
                : normalizeSnapshotTimestamp(readTime, encoding);
        if (typeof documentOrName === 'string')
            return new DocumentSnapshot(
                this._reference(documentOrName),
                undefined,
                time
            );
        const document = normalizeSnapshotDocument(documentOrName, encoding);
        document.readTime = time.toString();
        return new QueryDocumentSnapshot(
            this._reference(document.name),
            document
        );
    }
    private readonly referenceDatabases = new Map<string, Firestore>();
    get projectId(): string {
        return this.serviceAccountKey.project_id;
    }
    get databaseId(): string {
        return this._databaseId;
    }
    /** @internal Serialization option. */
    _useBigInt = false;
    /** @internal Decode fully qualified references, including other databases. */
    _reference(name: string): DocumentReference {
        const match =
            /^projects\/([^/]+)\/databases\/([^/]+)\/documents\/(.+)$/.exec(
                name
            );
        if (!match)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid document reference.'
            });
        const key = `${match[1]}/${match[2]}`;
        const db =
            match[1] === this.projectId && match[2] === this.databaseId
                ? this
                : (this.referenceDatabases.get(key) ??
                  new Firestore(
                      { ...this.serviceAccountKey, project_id: match[1]! },
                      {
                          databaseId: match[2],
                          fetch: this.fetch,
                          cache: this.cache,
                          cacheName: this.cacheName
                      }
                  ));
        if (db !== this) this.referenceDatabases.set(key, db);
        db.telemetry = this.telemetry;
        db._useBigInt = this._useBigInt;
        db._ignoreUndefinedProperties = this._ignoreUndefinedProperties;
        return db.documentReference(match[3]!);
    }
    private started = false;
    private configured = false;
    private terminated = false;
    private readonly streams = new Set<AbortController>();
    private readonly snapshotListeners = new Set<() => void>();
    /** @internal Register polling cleanup and return a deregistration function. */
    _registerSnapshotListener(stop: () => void): () => void {
        this.assertActive();
        this.snapshotListeners.add(stop);
        return () => {
            this.snapshotListeners.delete(stop);
        };
    }
    /** @internal Used by write serialization. */
    _ignoreUndefinedProperties = false;
    private implicitOrderBy = false;
    get alwaysUseImplicitOrderBy(): boolean {
        return this.implicitOrderBy;
    }
    settings(settings: Settings): void {
        if (this.started || this.configured || this.terminated)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.FAILED_PRECONDITION,
                message:
                    'settings() must be called once, before using Firestore.'
            });
        validateSettings(settings);
        const transport =
            settings.host !== undefined ||
            settings.ssl !== undefined ||
            settings.port !== undefined ||
            settings.openTelemetry !== undefined
                ? configureFirestoreFetch(
                      this.fetch ?? globalThis.fetch,
                      settings.host ?? 'firestore.googleapis.com',
                      settings.ssl,
                      settings.port,
                      settings.openTelemetry
                  )
                : this.fetch;
        this.serviceAccountKey = {
            ...this.serviceAccountKey,
            ...settings.credentials,
            ...(settings.projectId ? { project_id: settings.projectId } : {})
        };
        this._databaseId = settings.databaseId ?? this._databaseId;
        this.fetch = transport;
        this.telemetry = settings.openTelemetry;
        this._ignoreUndefinedProperties =
            settings.ignoreUndefinedProperties ?? false;
        this._useBigInt = settings.useBigInt ?? false;
        this.implicitOrderBy = settings.alwaysUseImplicitOrderBy ?? false;
        this.configured = true;
    }
    toJSON(): { projectId: string } {
        return { projectId: this.serviceAccountKey.project_id };
    }
    async terminate(): Promise<FirestoreResult<void>> {
        return firestoreResult(async () => {
            this.terminated = true;
            for (const stop of this.snapshotListeners) {
                stop();
            }
            this.snapshotListeners.clear();
            for (const controller of this.streams) {
                controller.abort(
                    new FirebaseEdgeError({
                        ...FirestoreErrorInfo.FAILED_PRECONDITION,
                        message: 'Firestore has been terminated.'
                    })
                );
            }
            this.streams.clear();
        });
    }
    bundle(name?: string): BundleBuilder {
        this.assertActive();
        return new BundleBuilder(name);
    }
    async recursiveDelete(
        ref: DocumentReference<any> | CollectionReference<any>,
        bulkWriter?: BulkWriter
    ): Promise<FirestoreResult<void>> {
        return firestoreResult(async () => {
            return this._trace('Firestore.recursiveDelete', async () => {
                this.assertActive();
                if (
                    !(
                        ref instanceof DocumentReference ||
                        ref instanceof CollectionReference
                    ) ||
                    ref.firestore !== this ||
                    (bulkWriter !== undefined &&
                        (!(bulkWriter instanceof BulkWriter) ||
                            bulkWriter.firestore !== this))
                ) {
                    throw new FirebaseEdgeError({
                        ...FirestoreErrorInfo.INVALID_ARGUMENT,
                        message:
                            'Reference and BulkWriter must belong to this Firestore instance.'
                    });
                }
                const writer = bulkWriter ?? this.bulkWriter();
                try {
                    await deleteRecursively(ref, writer);
                } finally {
                    if (!bulkWriter) {
                        await writer.close().then(firestoreData);
                    }
                }
            });
        });
    }
    collectionGroup(collectionId: string): CollectionGroup {
        this.assertActive();
        return new CollectionGroup(this, collectionId, (path, options) =>
            this._query(path, options)
        );
    }
    async getAll<
        T = DocumentData,
        DbModelType extends DocumentData = DocumentData
    >(
        ...referencesOrOptions: (
            | DocumentReference<T, DbModelType>
            | ReadOptions
        )[]
    ): Promise<FirestoreResult<DocumentSnapshot<T, DbModelType>[]>> {
        return firestoreResult(async () => {
            return this._trace('Firestore.getAll', async () => {
                return this._getAll(referencesOrOptions);
            });
        });
    }
    /** @internal Shared bulk read validation for transactions. */
    async _getAll<
        T = DocumentData,
        DbModelType extends DocumentData = DocumentData
    >(
        referencesOrOptions: (
            | DocumentReference<T, DbModelType>
            | ReadOptions
        )[],
        transaction?: string
    ): Promise<DocumentSnapshot<T, DbModelType>[]> {
        const args = [...referencesOrOptions];
        const last = args.at(-1);
        const options =
            last && !(last instanceof DocumentReference)
                ? (args.pop() as ReadOptions)
                : undefined;
        if (
            !args.length ||
            args.some(
                (ref) =>
                    !(ref instanceof DocumentReference) ||
                    ref.firestore !== this
            )
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message:
                    'getAll requires document references belonging to this Firestore instance.'
            });
        if (
            options?.fieldMask !== undefined &&
            !Array.isArray(options.fieldMask)
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'fieldMask must be an array.'
            });
        const fields = options?.fieldMask?.map((field) => {
            if (!(field instanceof FieldPath)) validateFieldPath(field);
            return field.toString();
        });
        const refs = args as DocumentReference<T, DbModelType>[];
        const token = await this.getCachedToken();
        const readTime = Timestamp.now();
        const documents = await batchGetDocuments(
            this.serviceAccountKey.project_id,
            this._databaseId,
            refs.map((ref) => ref.path),
            token.access_token,
            this.fetch,
            fields,
            ...(transaction ? [transaction] : [])
        );
        return refs.map(
            (ref, index) =>
                new DocumentSnapshot(
                    ref,
                    documents[index],
                    (documents as { readTimes?: Timestamp[] }).readTimes?.[
                        index
                    ] ?? readTime
                )
        );
    }
    listCollections(): Promise<FirestoreResult<CollectionReference[]>> {
        return firestoreResult(async () => {
            return this._trace('Firestore.listCollections', async () => {
                return this._listCollections('');
            });
        });
    }
    /** @internal */
    async _listCollections(path: string): Promise<CollectionReference[]> {
        const token = await this.getCachedToken();
        const ids = await listCollectionIds(
            this.serviceAccountKey.project_id,
            this._databaseId,
            path,
            token.access_token,
            this.fetch
        );
        return ids.map((id) => this.collection(path ? `${path}/${id}` : id));
    }
    /** @internal */
    async _listDocuments(path: string): Promise<string[]> {
        const token = await this.getCachedToken();
        return listDocumentPaths(
            this.serviceAccountKey.project_id,
            this._databaseId,
            path,
            token.access_token,
            this.fetch
        );
    }
    /** @internal */
    async _query(
        path: string,
        options: QueryOptions,
        transaction?: string
    ): Promise<FirestoreDocument[]> {
        const token = await this.getCachedToken();
        return runQuery(
            this.serviceAccountKey.project_id,
            this._databaseId,
            path,
            options,
            token.access_token,
            this.fetch,
            ...(transaction ? [transaction] : [])
        );
    }
    /** @internal */
    async *_streamQuery(
        path: string,
        options: QueryOptions,
        signal: AbortSignal
    ): AsyncGenerator<FirestoreDocument> {
        this.assertActive();
        const controller = new AbortController();
        this.streams.add(controller);
        const combined = AbortSignal.any([signal, controller.signal]);
        try {
            const token = await this.getCachedToken();
            combined.throwIfAborted();
            yield* streamQuery(
                this.serviceAccountKey.project_id,
                this._databaseId,
                path,
                options,
                token.access_token,
                this.fetch,
                combined
            );
        } finally {
            this.streams.delete(controller);
        }
    }
    batch(): WriteBatch {
        this.assertActive();
        return new WriteBatch(this, (writes) => this._commit(writes));
    }
    /** @internal Explain streams participate in termination and cancellation. */
    async *_explainQuery(
        path: string,
        options: QueryOptions,
        explain: ExplainOptions,
        signal: AbortSignal
    ): AsyncGenerator<QueryRow> {
        this.assertActive();
        const controller = new AbortController();
        const combined = AbortSignal.any([signal, controller.signal]);
        this.streams.add(controller);
        try {
            const token = await this.getCachedToken();
            combined.throwIfAborted();
            yield* streamQueryRows(
                this.projectId,
                this.databaseId,
                path,
                options,
                token.access_token,
                this.fetch,
                combined,
                explain
            );
        } finally {
            this.streams.delete(controller);
        }
    }
    bulkWriter(options?: BulkWriterOptions): BulkWriter {
        this.assertActive();
        return new BulkWriter(this, options);
    }
    async runTransaction<T>(
        updateFunction: (transaction: Transaction) => Promise<T>,
        options: ReadWriteTransactionOptions | ReadOnlyTransactionOptions = {}
    ): Promise<FirestoreResult<T>> {
        return firestoreResult(async () => {
            return this._trace('Firestore.runTransaction', async () => {
                if (
                    !options ||
                    typeof options !== 'object' ||
                    Array.isArray(options) ||
                    (options.readOnly !== undefined &&
                        typeof options.readOnly !== 'boolean') ||
                    ('readTime' in options &&
                        options.readTime !== undefined &&
                        (options.readOnly !== true ||
                            !(options.readTime instanceof Timestamp))) ||
                    (options.readOnly === true && 'maxAttempts' in options)
                ) {
                    throw new FirebaseEdgeError({
                        ...FirestoreErrorInfo.INVALID_ARGUMENT,
                        message: 'Invalid transaction options.'
                    });
                }
                const attempts = options.readOnly
                    ? 1
                    : (options.maxAttempts ?? 5);
                if (
                    typeof updateFunction !== 'function' ||
                    !Number.isInteger(attempts) ||
                    attempts < 1
                ) {
                    throw new FirebaseEdgeError({
                        ...FirestoreErrorInfo.INVALID_ARGUMENT,
                        message:
                            'A transaction callback and positive maxAttempts are required.'
                    });
                }
                const token = await this.getCachedToken();
                for (let attempt = 1; ; attempt++) {
                    let id: string | undefined;
                    let transaction: Transaction | undefined;
                    try {
                        id = await beginTransaction(
                            this.serviceAccountKey.project_id,
                            this._databaseId,
                            token.access_token,
                            this.fetch,
                            ...(options.readOnly ? ([options] as const) : [])
                        );
                        const transactionId = id;
                        transaction = new Transaction(
                            this,
                            async (ref) => {
                                this.assertActive();
                                const document = await getDocument(
                                    this.serviceAccountKey.project_id,
                                    this._databaseId,
                                    ref.path,
                                    token.access_token,
                                    this.fetch,
                                    transactionId
                                );
                                return new DocumentSnapshot(ref, document);
                            },
                            async (writes) => {
                                this.assertActive();
                                if (options.readOnly) {
                                    await rollbackTransaction(
                                        this.serviceAccountKey.project_id,
                                        this._databaseId,
                                        transactionId,
                                        token.access_token,
                                        this.fetch
                                    );
                                    return [];
                                }
                                return commitWrites(
                                    this.serviceAccountKey.project_id,
                                    this._databaseId,
                                    writes,
                                    token.access_token,
                                    this.fetch,
                                    transactionId
                                );
                            },
                            options.readOnly,
                            transactionId
                        );
                        const result = await updateFunction(transaction);
                        await transaction._commit();
                        return result;
                    } catch (error) {
                        transaction?._close();
                        try {
                            if (id) {
                                await rollbackTransaction(
                                    this.serviceAccountKey.project_id,
                                    this._databaseId,
                                    id,
                                    token.access_token,
                                    this.fetch
                                );
                            }
                        } catch {
                            /* Preserve the original transaction failure. */
                        }
                        if (
                            !(
                                [
                                    'firestore/aborted',
                                    'firestore/cancelled',
                                    'firestore/unknown',
                                    'firestore/deadline-exceeded',
                                    'firestore/internal',
                                    'firestore/unavailable',
                                    'firestore/unauthenticated',
                                    'firestore/resource-exhausted'
                                ].includes(
                                    (error as { code?: string })?.code ?? ''
                                ) ||
                                ((error as { code?: string })?.code ===
                                    'firestore/invalid-argument' &&
                                    error instanceof Error &&
                                    /transaction has expired/.test(
                                        error.message
                                    ))
                            ) ||
                            attempt >= attempts
                        ) {
                            throw error;
                        }
                        await new Promise((resolve) =>
                            setTimeout(
                                resolve,
                                Math.min(10 * 2 ** (attempt - 1), 1000)
                            )
                        );
                    }
                }
            });
        });
    }
    /** @internal */
    _documentName(path: string): string {
        return createDocumentName(
            this.serviceAccountKey.project_id,
            this._databaseId,
            path
        );
    }
    /** @internal */
    async _partitionQuery(
        collectionId: string,
        count: number
    ): Promise<string[]> {
        const token = await this.getCachedToken();
        return partitionQuery(
            this.serviceAccountKey.project_id,
            this._databaseId,
            collectionId,
            count,
            token.access_token,
            this.fetch
        );
    }
    /** @internal */
    async _batchWrite(
        writes: WriteOperation[]
    ): Promise<(WriteResult | FirebaseEdgeError)[]> {
        const token = await this.getCachedToken();
        return batchWrite(
            this.serviceAccountKey.project_id,
            this._databaseId,
            writes,
            token.access_token,
            this.fetch
        );
    }
    /** @internal */
    async _commit(writes: WriteOperation[]): Promise<WriteResult[]> {
        const token = await this.getCachedToken();
        return commitWrites(
            this.serviceAccountKey.project_id,
            this._databaseId,
            writes,
            token.access_token,
            this.fetch
        );
    }
    /** @internal */
    async _aggregate(
        path: string,
        options: QueryOptions,
        spec: AggregateSpec,
        transaction?: string,
        explain?: ExplainOptions
    ): Promise<AggregateData> {
        const token = await this.getCachedToken();
        return runAggregate(
            this.serviceAccountKey.project_id,
            this._databaseId,
            path,
            options,
            spec,
            token.access_token,
            this.fetch,
            ...((explain
                ? [transaction, explain]
                : transaction
                  ? [transaction]
                  : []) as [string?, ExplainOptions?])
        );
    }
    constructor(
        private serviceAccountKey: ServiceAccount,
        options: FirestoreOptions = {}
    ) {
        const {
            databaseId = '(default)',
            fetch,
            cache,
            cacheName = '__cache'
        } = options;
        if (!serviceAccountKey?.project_id) {
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'A service account project_id is required.'
            });
        }
        if (!databaseId || databaseId.includes('/')) {
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'A valid Firestore database ID is required.'
            });
        }

        this._databaseId = databaseId;
        this.fetch = fetch;
        this.cache = cache;
        this.cacheName = cacheName;
    }

    collection(path: string): CollectionReference {
        this.assertActive();
        return new CollectionReference(this, path, (collectionPath, options) =>
            this._query(collectionPath, options)
        );
    }

    doc(path: string): DocumentReference {
        this.assertActive();
        return this.documentReference(path);
    }
    private documentReference(path: string): DocumentReference {
        return new DocumentReference(this, path, async (documentPath) => {
            const token = await this.getCachedToken();
            return getDocument(
                this.serviceAccountKey.project_id,
                this._databaseId,
                documentPath,
                token.access_token,
                this.fetch
            );
        });
    }

    private async getCachedToken(): Promise<GoogleTokenResponse> {
        this.assertActive();
        const cacheKey = `${this.cacheName}:firestore:${this.serviceAccountKey.client_email}`;
        const cached =
            await this.cache?.getCache<GoogleTokenResponse>(cacheKey);
        this.assertActive();
        if (cached?.access_token) {
            return cached;
        }
        const { data, error } = await getToken(
            this.serviceAccountKey,
            this.fetch
        );
        this.assertActive();
        if (error) {
            throw error;
        }
        if (!data?.access_token) {
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.UNAUTHENTICATED,
                message: 'No service account access token returned.'
            });
        }
        const ttlMs = (data.expires_in - 60) * 1000;
        if (Number.isFinite(ttlMs) && ttlMs > 0) {
            await this.cache?.setCache(cacheKey, data, ttlMs);
        }
        this.assertActive();
        return data;
    }
    private assertActive(): void {
        if (this.terminated)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.FAILED_PRECONDITION,
                message: 'Firestore has been terminated.'
            });
        this.started = true;
    }
}
