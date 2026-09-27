import {
    type FirestoreResult,
    firestoreResult,
    firestoreData
} from './firestore-results.js';
import { queryPipeline } from './pipeline-query.js';
import type { Pipeline } from './pipeline.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { Firestore } from './firestore.js';
import {
    listenByPolling,
    type SnapshotListenOptions,
    type SnapshotCallback,
    type SnapshotErrorCallback
} from './snapshot-listener.js';
import type { FirestoreDocument, DocumentData } from './firestore-document.js';
import { DocumentSnapshot } from './document-snapshot.js';
import {
    validateConverter,
    type FirestoreDataConverter
} from './firestore-converter.js';
import { QueryDocumentSnapshot } from './query-document-snapshot.js';
export { QueryDocumentSnapshot } from './query-document-snapshot.js';
import {
    OPERATORS,
    encodeValue,
    validateFieldPath,
    normalizedOrders,
    type QueryOptions,
    type WhereFilterOp
} from './query-request.js';
export type { WhereFilterOp } from './query-request.js';
import { Filter } from './filter.js';
import { FieldPath, parseFieldPath } from './field-path.js';
import { Timestamp } from './timestamp.js';
import { valueEquals } from './value-equality.js';
import {
    validateExplainOptions,
    type ExplainOptions,
    type ExplainMetrics,
    type ExplainResults
} from './explain.js';
import { VectorQuery, type VectorQueryOptions } from './vector-query.js';
import { VectorValue } from './vector-value.js';
import { buildStructuredQuery } from './query-request.js';
import {
    AggregateField,
    AggregateQuery,
    type AggregateSpec
} from './aggregate.js';

export class QuerySnapshot<
    T = DocumentData,
    DbModelType extends DocumentData = DocumentData
> {
    isEqual(other: unknown): boolean {
        return (
            other instanceof QuerySnapshot &&
            this.query.isEqual(other.query) &&
            this.docs.length === other.docs.length &&
            this.docs.every((doc, index) => doc.isEqual(other.docs[index]))
        );
    }
    docChanges(): DocumentChange<T, DbModelType>[] {
        if (this.changes) return this.changes.map((change) => ({ ...change }));
        return this.docs.map((doc, newIndex) => ({
            type: 'added',
            doc,
            oldIndex: -1,
            newIndex
        }));
    }
    readonly size: number;
    readonly empty: boolean;
    constructor(
        readonly query: Query<T, DbModelType>,
        readonly docs: QueryDocumentSnapshot<T, DbModelType>[],
        readonly readTime: Timestamp = docs[0]?.readTime ?? Timestamp.now(),
        private readonly changes?: DocumentChange<T, DbModelType>[]
    ) {
        this.size = docs.length;
        this.empty = docs.length === 0;
    }
    forEach(
        callback: (document: QueryDocumentSnapshot<T, DbModelType>) => void,
        thisArg?: unknown
    ): void {
        if (typeof callback !== 'function')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected a callback function.'
            });
        for (const document of this.docs) callback.call(thisArg, document);
    }
}
export interface DocumentChange<
    T = DocumentData,
    DbModelType extends DocumentData = DocumentData
> {
    readonly type: 'added' | 'modified' | 'removed';
    readonly doc: QueryDocumentSnapshot<T, DbModelType>;
    readonly oldIndex: number;
    readonly newIndex: number;
}

/** Compute indices against the list after each preceding change is applied. */
function queryChanges<T, DbModelType extends DocumentData>(
    before: QueryDocumentSnapshot<T, DbModelType>[],
    after: QueryDocumentSnapshot<T, DbModelType>[]
): DocumentChange<T, DbModelType>[] {
    const current = [...before];
    const paths = new Set(after.map((doc) => doc.ref.path));
    const changes: DocumentChange<T, DbModelType>[] = [];
    for (let index = current.length - 1; index >= 0; index--) {
        const doc = current[index]!;
        if (paths.has(doc.ref.path)) continue;
        changes.push({ type: 'removed', doc, oldIndex: index, newIndex: -1 });
        current.splice(index, 1);
    }
    for (const [newIndex, doc] of after.entries()) {
        const oldIndex = current.findIndex(
            (previous) => previous.ref.path === doc.ref.path
        );
        if (oldIndex === newIndex && doc.isEqual(current[oldIndex])) continue;
        if (oldIndex >= 0) current.splice(oldIndex, 1);
        current.splice(newIndex, 0, doc);
        changes.push({
            type: oldIndex < 0 ? 'added' : 'modified',
            doc,
            oldIndex,
            newIndex
        });
    }
    return changes;
}

export type QueryExecutor = (
    path: string,
    options: QueryOptions
) => Promise<FirestoreDocument[]>;

/** Immutable, read-only Firestore query. Obtain one from firestore.collection(). */
export class Query<
    T = DocumentData,
    DbModelType extends DocumentData = DocumentData
> {
    /** @internal Translate query state for PipelineSource.createFrom(). */
    _pipeline(): Pipeline {
        return queryPipeline(this.firestore, this.collectionPath, this.options);
    }

    onSnapshot(
        next: SnapshotCallback<QuerySnapshot<T, DbModelType>>,
        error?: SnapshotErrorCallback,
        options?: SnapshotListenOptions
    ): () => void;
    onSnapshot(
        options: SnapshotListenOptions,
        next: SnapshotCallback<QuerySnapshot<T, DbModelType>>,
        error?: SnapshotErrorCallback
    ): () => void;
    onSnapshot(
        first:
            | SnapshotListenOptions
            | SnapshotCallback<QuerySnapshot<T, DbModelType>>,
        second?:
            | SnapshotCallback<QuerySnapshot<T, DbModelType>>
            | SnapshotErrorCallback,
        third?: SnapshotListenOptions | SnapshotErrorCallback
    ): () => void {
        return listenByPolling(
            this.firestore,
            () => this.get().then(firestoreData),
            (current, previous) => {
                if (previous?.isEqual(current)) return undefined;
                if (!previous) return current;
                return new QuerySnapshot(
                    this,
                    current.docs,
                    current.readTime,
                    queryChanges(previous.docs, current.docs)
                );
            },
            first,
            second,
            third
        );
    }
    findNearest(options: VectorQueryOptions): VectorQuery<T, DbModelType>;
    findNearest(
        vectorField: string | FieldPath,
        queryVector: VectorValue | number[],
        options: Omit<VectorQueryOptions, 'vectorField' | 'queryVector'>
    ): VectorQuery<T, DbModelType>;
    findNearest(
        fieldOrOptions: VectorQueryOptions | string | FieldPath,
        queryVector?: VectorValue | number[],
        options?: Omit<VectorQueryOptions, 'vectorField' | 'queryVector'>
    ): VectorQuery<T, DbModelType> {
        const config =
            typeof fieldOrOptions === 'string' ||
            fieldOrOptions instanceof FieldPath
                ? {
                      ...options!,
                      vectorField: fieldOrOptions,
                      queryVector: queryVector!
                  }
                : fieldOrOptions;
        return new VectorQuery(this, config);
    }
    /** @internal Keep filters and converters when adding a nearest-neighbor stage. */
    _withNearest(
        nearest: NonNullable<QueryOptions['nearest']>
    ): Query<T, DbModelType> {
        return this.withOptions({ nearest });
    }
    async explain(
        options: ExplainOptions = {}
    ): Promise<FirestoreResult<ExplainResults<QuerySnapshot<T, DbModelType>>>> {
        return firestoreResult(async () => {
            return this.firestore._trace('Query.explain', async () => {
                validateExplainOptions(options);
                if (this.options.last && !this.options.orders?.length) {
                    throw new FirebaseEdgeError({
                        ...FirestoreErrorInfo.FAILED_PRECONDITION,
                        message: 'limitToLast requires at least one orderBy.'
                    });
                }
                const abort = new AbortController();
                const docs: QueryDocumentSnapshot<T, DbModelType>[] = [];
                let metrics: ExplainMetrics | undefined;
                let readTime: Timestamp | undefined;
                for await (const row of this.firestore._explainQuery(
                    this.collectionPath,
                    this.options,
                    options,
                    abort.signal
                )) {
                    if (row.document) {
                        docs.push(this.snapshot(row.document));
                    }
                    if (row.metrics) {
                        metrics = row.metrics;
                    }
                    if (row.readTime) {
                        readTime = Timestamp.fromString(row.readTime);
                    }
                }
                if (!metrics) {
                    throw new FirebaseEdgeError({
                        ...FirestoreErrorInfo.INVALID_RESPONSE,
                        message: 'No explain metrics returned.'
                    });
                }
                if (this.options.last) {
                    docs.reverse();
                }
                return {
                    metrics,
                    snapshot: options.analyze
                        ? new QuerySnapshot(this, docs, readTime)
                        : null
                };
            });
        });
    }
    explainStream(options: ExplainOptions = {}): ReadableStream<{
        document?: QueryDocumentSnapshot<T, DbModelType>;
        metrics?: ExplainMetrics;
    }> {
        validateExplainOptions(options);
        if (this.options.last)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.FAILED_PRECONDITION,
                message: 'limitToLast queries cannot be streamed.'
            });
        const abort = new AbortController();
        const source = this.firestore._explainQuery(
            this.collectionPath,
            this.options,
            options,
            abort.signal
        );
        return new ReadableStream({
            pull: async (controller) => {
                try {
                    for (;;) {
                        const next = await source.next();
                        if (next.done) {
                            controller.close();
                            return;
                        }
                        const row = next.value;
                        if (!row.document && !row.metrics) continue;
                        controller.enqueue({
                            ...(row.document
                                ? { document: this.snapshot(row.document) }
                                : {}),
                            ...(row.metrics ? { metrics: row.metrics } : {})
                        });
                        return;
                    }
                } catch (error) {
                    abort.abort();
                    try {
                        await source.return(undefined);
                    } catch {
                        /* Preserve the read failure. */
                    }
                    controller.error(error);
                }
            },
            cancel: async () => {
                abort.abort();
                await source.return(undefined);
            }
        });
    }
    isEqual(other: unknown): boolean {
        return (
            other instanceof Query &&
            this.firestore === other.firestore &&
            this.collectionPath === other.collectionPath &&
            this.converter === other.converter &&
            valueEquals(this._bundledQuery(), other._bundledQuery())
        );
    }
    /** @internal Bundle queries keep their logical order, including limitToLast. */
    _bundledQuery() {
        const segments = this.collectionPath.split('/');
        const collectionId = segments.pop()!;
        const parent = this.firestore._documentName(segments.join('/'));
        return {
            parent,
            structuredQuery: buildStructuredQuery(
                collectionId,
                { ...this.options, last: false },
                parent
            ),
            limitType: this.options.last ? 'LAST' : 'FIRST'
        };
    }
    count(): AggregateQuery<{ count: AggregateField<number> }, T, DbModelType> {
        return this.aggregate({ count: AggregateField.count() });
    }
    aggregate<S extends AggregateSpec>(
        spec: S
    ): AggregateQuery<S, T, DbModelType> {
        return new AggregateQuery(this, spec, (fields, transaction, explain) =>
            this.firestore._aggregate(
                this.collectionPath,
                this.options,
                fields,
                ...((explain
                    ? [transaction, explain]
                    : transaction
                      ? [transaction]
                      : []) as [string?, ExplainOptions?])
            )
        );
    }
    /** @internal */
    constructor(
        readonly firestore: Firestore,
        protected readonly collectionPath: string,
        protected readonly execute: QueryExecutor,
        private readonly options: QueryOptions = {},
        readonly converter: FirestoreDataConverter<T, DbModelType> | null = null
    ) {
        if (firestore.alwaysUseImplicitOrderBy)
            this.options = { ...options, alwaysUseImplicitOrderBy: true };
    }

    where(filter: Filter): Query<T, DbModelType>;
    where(
        fieldPath: string | FieldPath,
        opStr: WhereFilterOp,
        value: unknown
    ): Query<T, DbModelType>;
    where(
        field: string | FieldPath | Filter,
        opStr?: WhereFilterOp,
        value?: unknown
    ): Query<T, DbModelType> {
        if (field instanceof Filter)
            return this.withOptions({
                compositeFilters: [
                    ...(this.options.compositeFilters ?? []),
                    field.node
                ]
            });
        if (field instanceof FieldPath)
            return this.where(Filter.where(field, opStr!, value));
        const fieldPath = field;
        validateFieldPath(fieldPath);
        if (!opStr || !Object.hasOwn(OPERATORS, opStr))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid Firestore query operator.'
            });
        if (
            ['in', 'not-in', 'array-contains-any'].includes(opStr) &&
            (!Array.isArray(value) ||
                !value.length ||
                value.length > (opStr === 'not-in' ? 10 : 30))
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message:
                    'Query operator requires a non-empty array within the Firestore value limit.'
            });
        return this.withOptions({
            filters: [
                ...(this.options.filters ?? []),
                { field: fieldPath, operator: opStr, value: encodeValue(value) }
            ]
        });
    }

    orderBy(
        field: string | FieldPath,
        directionStr: 'asc' | 'desc' = 'asc'
    ): Query<T, DbModelType> {
        if (!(field instanceof FieldPath)) validateFieldPath(field);
        const fieldPath = field.toString();
        if (directionStr !== 'asc' && directionStr !== 'desc')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid query order direction.'
            });
        if (this.options.start || this.options.end)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.FAILED_PRECONDITION,
                message: 'Set orderBy before cursor bounds.'
            });
        return this.withOptions({
            orders: [
                ...(this.options.orders ?? []),
                { field: fieldPath, direction: directionStr }
            ]
        });
    }

    limit(limit: number): Query<T, DbModelType> {
        if (!Number.isSafeInteger(limit) || limit <= 0 || limit > 2147483647)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Query limit must be a positive 32-bit integer.'
            });
        return this.withOptions({
            limit,
            ...(this.options.last ? { last: false } : {})
        });
    }

    limitToLast(limit: number): Query<T, DbModelType> {
        return this.limit(limit).withOptions({ last: true });
    }

    offset(offset: number): Query<T, DbModelType> {
        if (!Number.isSafeInteger(offset) || offset < 0 || offset > 2147483647)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Query offset must be a non-negative 32-bit integer.'
            });
        return this.withOptions({ offset });
    }

    select(...fieldPaths: (string | FieldPath)[]): Query {
        for (const field of fieldPaths)
            if (!(field instanceof FieldPath)) validateFieldPath(field);
        return this.withOptions({
            fields: fieldPaths.map((field) => field.toString())
        }) as unknown as Query;
    }

    startAt(...fieldValues: unknown[]): Query<T, DbModelType> {
        return this.withCursor('start', true, fieldValues);
    }
    startAfter(...fieldValues: unknown[]): Query<T, DbModelType> {
        return this.withCursor('start', false, fieldValues);
    }
    endAt(...fieldValues: unknown[]): Query<T, DbModelType> {
        return this.withCursor('end', false, fieldValues);
    }
    endBefore(...fieldValues: unknown[]): Query<T, DbModelType> {
        return this.withCursor('end', true, fieldValues);
    }

    async get(): Promise<FirestoreResult<QuerySnapshot<T, DbModelType>>> {
        return firestoreResult(async () => {
            return this.firestore._trace('Query.get', async () => {
                return this._get();
            });
        });
    }
    /** @internal Transaction-bound query reads. */
    async _get(transaction?: string): Promise<QuerySnapshot<T, DbModelType>> {
        if (this.options.last && !this.options.orders?.length)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.FAILED_PRECONDITION,
                message: 'limitToLast requires at least one orderBy.'
            });
        const startedAt = Timestamp.now();
        const documents = transaction
            ? await this.firestore._query(
                  this.collectionPath,
                  this.options,
                  transaction
              )
            : await this.execute(this.collectionPath, this.options);
        const docs = documents.map((document) => this.snapshot(document));
        if (this.options.last) docs.reverse();
        const readTime = (
            documents as FirestoreDocument[] & { readTime?: string }
        ).readTime;
        return new QuerySnapshot(
            this,
            docs,
            readTime
                ? Timestamp.fromString(readTime)
                : (docs[0]?.readTime ?? startedAt)
        );
    }

    withConverter<U, NewDbModelType extends DocumentData = DocumentData>(
        converter: FirestoreDataConverter<U, NewDbModelType>
    ): Query<U, NewDbModelType>;
    withConverter(converter: null): Query;
    withConverter<U, NewDbModelType extends DocumentData = DocumentData>(
        converter: FirestoreDataConverter<U, NewDbModelType> | null
    ): Query<U, NewDbModelType>;
    withConverter<U, NewDbModelType extends DocumentData = DocumentData>(
        converter: FirestoreDataConverter<U, NewDbModelType> | null
    ): Query<U, NewDbModelType> {
        validateConverter(converter);
        return new Query(
            this.firestore,
            this.collectionPath,
            this.execute,
            this.options,
            converter
        );
    }

    stream(): ReadableStream<QueryDocumentSnapshot<T, DbModelType>> {
        if (this.options.last)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.FAILED_PRECONDITION,
                message: 'limitToLast queries cannot be streamed.'
            });
        const abort = new AbortController();
        const source = this.firestore._streamQuery(
            this.collectionPath,
            this.options,
            abort.signal
        );
        return new ReadableStream<QueryDocumentSnapshot<T, DbModelType>>({
            pull: async (controller) => {
                try {
                    const next = await source.next();
                    if (next.done) {
                        controller.close();
                        return;
                    }
                    controller.enqueue(this.snapshot(next.value));
                } catch (error) {
                    abort.abort();
                    try {
                        await source.return(undefined);
                    } catch {
                        /* Preserve the original stream failure. */
                    }
                    controller.error(error);
                }
            },
            cancel: async () => {
                abort.abort();
                await source.return(undefined);
            }
        });
    }

    private snapshot(
        document: FirestoreDocument
    ): QueryDocumentSnapshot<T, DbModelType> {
        const ref = this.firestore
            .doc(
                document.name.split('/documents/').slice(1).join('/documents/')
            )
            .withConverter(this.converter);
        return new QueryDocumentSnapshot(ref, document);
    }

    private withOptions(options: Partial<QueryOptions>): Query<T, DbModelType> {
        return new Query(
            this.firestore,
            this.collectionPath,
            this.execute,
            {
                ...this.options,
                ...options
            },
            this.converter
        );
    }

    private withCursor(
        side: 'start' | 'end',
        before: boolean,
        values: unknown[]
    ): Query<T, DbModelType> {
        if (values[0] instanceof DocumentSnapshot) {
            const snapshot = values[0];
            if (values.length !== 1 || !snapshot.exists)
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.INVALID_ARGUMENT,
                    message:
                        'Snapshot cursors require one existing document snapshot.'
                });
            if (snapshot.ref.firestore !== this.firestore)
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.INVALID_ARGUMENT,
                    message: 'Snapshot must belong to this Firestore instance.'
                });
            const orders = normalizedOrders(this.options);
            const encoded = orders.map((order) => {
                if (order.field === '__name__')
                    return encodeValue(snapshot.ref);
                const value = snapshot._getValue(
                    new FieldPath(...parseFieldPath(order.field))
                );
                if (value === undefined)
                    throw new FirebaseEdgeError({
                        ...FirestoreErrorInfo.INVALID_ARGUMENT,
                        message: `Snapshot is missing ordered field ${order.field}.`
                    });
                return value;
            });
            return this.withOptions({
                orders,
                [side]: { values: encoded, before }
            });
        }
        if (
            !values.length ||
            values.length > (this.options.orders?.length ?? 0)
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message:
                    'Cursor values require matching explicit orderBy fields.'
            });
        return this.withOptions({
            [side]: {
                values: values.map((value) => encodeValue(value)),
                before
            }
        });
    }
}
