import { type FirestoreResult, firestoreResult } from './firestore-results.js';
import { Query } from './query.js';
import type { Firestore } from './firestore.js';
import type { CollectionReference } from './collection-reference.js';
import { DocumentReference } from './document-reference.js';
import { FieldPath, parseFieldPath } from './field-path.js';
import {
    decodeFields,
    type FirestoreDocument,
    type DocumentData
} from './firestore-document.js';
import { VectorValue } from './vector-value.js';
import { Timestamp } from './timestamp.js';
import { valueEquals } from './value-equality.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';
import {
    Expression,
    Field,
    AliasedExpression,
    FunctionExpression,
    Ordering,
    field,
    selectionMap,
    encodePipelineValue,
    type PipelineValue,
    type Selectable
} from './pipeline-expression.js';
export * from './pipeline-expression.js';
export interface PipelineStage {
    name: string;
    args: PipelineValue[];
    options?: Record<string, PipelineValue>;
}
export interface PipelineExecuteOptions {
    rawOptions?: Record<string, unknown>;
    readTime?: Timestamp;
    indexMode?: string;
    explainOptions?: {
        mode: 'execute' | 'explain' | 'analyze';
        outputFormat?: 'json' | 'text';
    };
}
export interface PipelineResponse {
    results: Partial<FirestoreDocument>[];
    executionTime: string;
    explainStats?: { data?: unknown };
}
export class PipelineSource {
    constructor(readonly firestore: Firestore) {}
    createFrom(query: Query<any, any>): Pipeline {
        if (!(query instanceof Query) || query.firestore !== this.firestore)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Query must belong to this Firestore.'
            });
        return query._pipeline();
    }
    collection(collection: string | CollectionReference): Pipeline {
        const ref =
            typeof collection === 'string'
                ? this.firestore.collection(collection)
                : collection;
        if (
            !(ref instanceof Query) ||
            typeof (ref as CollectionReference).path !== 'string' ||
            ref.firestore !== this.firestore
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Collection must belong to this Firestore.'
            });
        return new Pipeline(this.firestore).rawStage('collection', [
            new Expression({ referenceValue: '/' + ref.path })
        ]);
    }
    collectionGroup(collectionId: string): Pipeline {
        this.firestore.collectionGroup(collectionId);
        return new Pipeline(this.firestore).rawStage('collection_group', [
            new Expression({ referenceValue: '' }),
            collectionId
        ]);
    }
    database(): Pipeline {
        return new Pipeline(this.firestore).rawStage('database', []);
    }
    documents(...documents: (string | DocumentReference)[]): Pipeline {
        const refs = documents.map((document) =>
            typeof document === 'string'
                ? this.firestore.doc(document)
                : document
        );
        if (
            !refs.length ||
            refs.some(
                (ref) =>
                    !(ref instanceof DocumentReference) ||
                    ref.firestore !== this.firestore
            )
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected documents belonging to this Firestore.'
            });
        return new Pipeline(this.firestore).rawStage(
            'documents',
            refs.map(
                (ref) => new Expression({ referenceValue: '/' + ref.path })
            )
        );
    }
}
export class Pipeline {
    private readonly stages: PipelineStage[];
    constructor(
        readonly firestore: Firestore,
        stages: PipelineStage[] = []
    ) {
        this.stages = structuredClone(stages);
    }
    rawStage(
        name: string,
        params: unknown[],
        options: Record<string, unknown> = {}
    ): Pipeline {
        if (
            typeof name !== 'string' ||
            !name ||
            !Array.isArray(params) ||
            !options ||
            typeof options !== 'object' ||
            Array.isArray(options)
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid pipeline stage.'
            });
        return new Pipeline(this.firestore, [
            ...this.stages,
            {
                name,
                args: params.map(encodePipelineValue),
                options: Object.fromEntries(
                    Object.entries(options).map(([key, value]) => [
                        key,
                        encodePipelineValue(value)
                    ])
                )
            }
        ]);
    }
    where(condition: Expression): Pipeline {
        if (!(condition instanceof Expression))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected a pipeline expression.'
            });
        return this.rawStage('where', [condition]);
    }
    select(...fields: Selectable[]): Pipeline {
        return this.rawStage('select', [selectionMap(fields)]);
    }
    addFields(...fields: Selectable[]): Pipeline {
        return this.rawStage('add_fields', [selectionMap(fields)]);
    }
    define(...fields: Selectable[]): Pipeline {
        return this.rawStage('let', [selectionMap(fields)]);
    }
    removeFields(...fields: (string | Field)[]): Pipeline {
        return this.rawStage(
            'remove_fields',
            fields.map((value) =>
                typeof value === 'string' ? field(value) : value
            )
        );
    }
    distinct(...fields: Selectable[]): Pipeline {
        return this.rawStage('distinct', [selectionMap(fields)]);
    }
    aggregate(
        first:
            | Selectable
            | { accumulators: Selectable[]; groups?: Selectable[] },
        ...rest: Selectable[]
    ): Pipeline {
        const options =
            typeof first === 'object' &&
            first !== null &&
            'accumulators' in first
                ? first
                : { accumulators: [first as Selectable, ...rest] };
        return this.rawStage('aggregate', [
            selectionMap(options.accumulators),
            selectionMap(options.groups ?? [])
        ]);
    }
    sort(...orderings: Ordering[]): Pipeline {
        if (
            !orderings.length ||
            orderings.some((ordering) => !(ordering instanceof Ordering))
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected pipeline orderings.'
            });
        return this.rawStage('sort', orderings);
    }
    limit(count: number): Pipeline {
        return this.countStage('limit', count);
    }
    offset(count: number): Pipeline {
        return this.countStage('offset', count);
    }
    private countStage(name: string, count: number): Pipeline {
        if (!Number.isSafeInteger(count) || count < 0)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected a nonnegative integer.'
            });
        return this.rawStage(name, [count]);
    }
    replaceWith(map: unknown): Pipeline {
        return this.rawStage('replace_with', [map, 'full_replace']);
    }
    union(other: Pipeline): Pipeline {
        if (!(other instanceof Pipeline) || other.firestore !== this.firestore)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Pipeline must belong to this Firestore.'
            });
        return this.rawStage('union', [
            new Expression({ pipelineValue: other._request().pipeline })
        ]);
    }
    unnest(selection: AliasedExpression, indexField?: string): Pipeline {
        if (!(selection instanceof AliasedExpression))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Unnest requires an aliased expression.'
            });
        return this.rawStage(
            'unnest',
            [selection.expr, field(selection.alias)],
            indexField ? { index_field: field(indexField) } : {}
        );
    }
    sample(
        value: number | { documents?: number; percentage?: number }
    ): Pipeline {
        const rate =
            typeof value === 'number'
                ? value
                : (value?.documents ?? value?.percentage);
        const mode =
            typeof value === 'number' || value?.documents !== undefined
                ? 'documents'
                : 'percent';
        if (
            typeof rate !== 'number' ||
            !Number.isFinite(rate) ||
            rate < 0 ||
            (mode === 'percent' ? rate > 100 : !Number.isSafeInteger(rate))
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid sample size.'
            });
        return this.rawStage('sample', [rate, mode]);
    }
    findNearest(options: {
        field: string | Field;
        vectorValue: number[] | VectorValue | Expression;
        distanceMeasure: 'euclidean' | 'cosine' | 'dot_product';
        limit?: number;
        distanceField?: string;
    }): Pipeline {
        const vector = Array.isArray(options.vectorValue)
            ? new VectorValue(options.vectorValue)
            : options.vectorValue;
        return this.rawStage(
            'find_nearest',
            [
                typeof options.field === 'string'
                    ? field(options.field)
                    : options.field,
                vector,
                options.distanceMeasure
            ],
            {
                ...(options.limit !== undefined
                    ? { limit: options.limit }
                    : {}),
                ...(options.distanceField
                    ? { distance_field: field(options.distanceField) }
                    : {})
            }
        );
    }
    search(options: Record<string, unknown>): Pipeline {
        const normalized = Object.fromEntries(
            Object.entries(options).map(([key, value]) => [
                key.replace(/[A-Z]/g, (letter) => '_' + letter.toLowerCase()),
                value
            ])
        );
        if (typeof options.query === 'string')
            normalized.query = new FunctionExpression('document_matches', [
                options.query
            ]);
        return this.rawStage('search', [], normalized);
    }
    delete(): Pipeline {
        return this.rawStage('delete', []);
    }
    update(fields: Selectable[]): Pipeline {
        return this.rawStage('update', [selectionMap(fields)]);
    }
    toArrayExpression(): FunctionExpression {
        return new FunctionExpression('array', [
            new Expression({ pipelineValue: this._request().pipeline })
        ]);
    }
    toScalarExpression(): FunctionExpression {
        return new FunctionExpression('scalar', [
            new Expression({ pipelineValue: this._request().pipeline })
        ]);
    }
    /** @internal Encoded state, defensively copied for endpoint use. */
    _request(options: PipelineExecuteOptions = {}): {
        pipeline: { stages: PipelineStage[] };
        options: Record<string, PipelineValue>;
    } {
        if (!this.stages.length)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'A pipeline requires a source.'
            });
        return {
            pipeline: { stages: structuredClone(this.stages) },
            options: Object.fromEntries(
                Object.entries({
                    ...(options.indexMode
                        ? { index_mode: options.indexMode }
                        : {}),
                    ...(options.explainOptions
                        ? {
                              explain_options: {
                                  mode: options.explainOptions.mode,
                                  ...(options.explainOptions.outputFormat
                                      ? {
                                            output_format:
                                                options.explainOptions
                                                    .outputFormat
                                        }
                                      : {})
                              }
                          }
                        : {}),
                    ...options.rawOptions
                }).map(([key, value]) => [key, encodePipelineValue(value)])
            )
        };
    }
    /** @internal Classify known mutation stages for transaction guards. */
    get _hasWrites(): boolean {
        return this.stages.some(
            (stage) => stage.name === 'update' || stage.name === 'delete'
        );
    }
    execute(
        options: PipelineExecuteOptions = {}
    ): Promise<FirestoreResult<PipelineSnapshot>> {
        return firestoreResult(async () => {
            return this._execute(options);
        });
    }
    /** @internal Execute in a server transaction. */
    async _execute(
        options: PipelineExecuteOptions = {},
        transaction?: string
    ): Promise<PipelineSnapshot> {
        const result = await this.firestore._executePipeline(
            this._request(options),
            transaction,
            options.readTime
        );
        return new PipelineSnapshot(
            this,
            result.results.map(
                (document) => new PipelineResult(this.firestore, document)
            ),
            Timestamp.fromString(result.executionTime),
            result.explainStats
                ? new ExplainStats(result.explainStats.data)
                : undefined
        );
    }
    stream(
        options: PipelineExecuteOptions = {}
    ): ReadableStream<PipelineResult> {
        const abort = new AbortController();
        const source = this.firestore._streamPipeline(
            this._request(options),
            abort.signal,
            options.readTime
        );
        let cancelled = false;
        return new ReadableStream({
            pull: async (controller) => {
                try {
                    const next = await source.next();
                    if (cancelled) return;
                    if (next.done) {
                        controller.close();
                        return;
                    }
                    controller.enqueue(
                        new PipelineResult(this.firestore, next.value)
                    );
                } catch (error) {
                    abort.abort();
                    try {
                        await source.return(undefined);
                    } catch {
                        /* Preserve the original failure. */
                    }
                    if (!cancelled) controller.error(error);
                }
            },
            cancel: async () => {
                cancelled = true;
                abort.abort();
                await source.return(undefined);
            }
        });
    }
}
export class PipelineSnapshot {
    constructor(
        readonly pipeline: Pipeline,
        readonly results: PipelineResult[],
        readonly executionTime: Timestamp,
        readonly explainStats?: ExplainStats
    ) {}
}
export class PipelineResult {
    private readonly document: Partial<FirestoreDocument>;
    readonly ref?: DocumentReference;
    readonly createTime?: Timestamp;
    readonly updateTime?: Timestamp;
    constructor(
        private readonly firestore: Firestore,
        document: Partial<FirestoreDocument>
    ) {
        this.document = structuredClone(document);
        this.ref = document.name
            ? firestore._reference(document.name)
            : undefined;
        this.createTime = document.createTime
            ? Timestamp.fromString(document.createTime)
            : undefined;
        this.updateTime = document.updateTime
            ? Timestamp.fromString(document.updateTime)
            : undefined;
    }
    get id(): string | undefined {
        return this.ref?.id;
    }
    data(): DocumentData {
        return decodeFields(this.document.fields, this.firestore);
    }
    get(path: string | FieldPath): unknown {
        const segments =
            path instanceof FieldPath ? path.segments : parseFieldPath(path);
        let value: unknown = this.data();
        for (const segment of segments) {
            if (
                !value ||
                typeof value !== 'object' ||
                !Object.prototype.hasOwnProperty.call(value, segment)
            )
                return undefined;
            value = (value as Record<string, unknown>)[segment];
        }
        return value;
    }
    isEqual(other: unknown): boolean {
        return (
            other instanceof PipelineResult &&
            this.firestore === other.firestore &&
            this.document.name === other.document.name &&
            valueEquals(this.document.fields, other.document.fields)
        );
    }
}

export class ExplainStats {
    constructor(private readonly raw: unknown) {}
    get rawMessage(): unknown {
        return structuredClone(this.raw);
    }
    get text(): string {
        if (
            !this.raw ||
            typeof this.raw !== 'object' ||
            typeof (this.raw as { value?: unknown }).value !== 'string'
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Unsupported explain stats. Inspect rawMessage.'
            });
        return (this.raw as { value: string }).value;
    }
    get json(): unknown {
        return JSON.parse(this.text);
    }
}
