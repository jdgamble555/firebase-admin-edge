import {
    type FirestoreResult,
    firestoreResult,
    firestoreData
} from './firestore-results.js';
import { QuerySnapshot, type DocumentChange, type Query } from './query.js';
import type { QueryDocumentSnapshot } from './query-document-snapshot.js';
import type { DocumentData } from './firestore-document.js';
import { FieldPath } from './field-path.js';
import { VectorValue } from './vector-value.js';
import { encodeValue, validateFieldPath } from './query-request.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';
import type { Timestamp } from './timestamp.js';
import type { ExplainOptions, ExplainResults } from './explain.js';

export interface VectorQueryOptions {
    vectorField: string | FieldPath;
    queryVector: VectorValue | number[];
    limit: number;
    distanceMeasure: 'EUCLIDEAN' | 'COSINE' | 'DOT_PRODUCT';
    distanceResultField?: string | FieldPath;
    distanceThreshold?: number;
}
export class VectorQuery<
    T = DocumentData,
    DbModelType extends DocumentData = DocumentData
> {
    private readonly executable: Query<T, DbModelType>;
    /** @internal Obtain from Query.findNearest(). */
    constructor(
        readonly query: Query<T, DbModelType>,
        options: VectorQueryOptions
    ) {
        if (
            !options ||
            !Number.isInteger(options.limit) ||
            options.limit < 1 ||
            options.limit > 1000 ||
            !['EUCLIDEAN', 'COSINE', 'DOT_PRODUCT'].includes(
                options.distanceMeasure
            ) ||
            (options.distanceThreshold !== undefined &&
                !Number.isFinite(options.distanceThreshold))
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid vector query options.'
            });
        if (!(options.vectorField instanceof FieldPath))
            validateFieldPath(options.vectorField);
        if (
            options.distanceResultField !== undefined &&
            !(options.distanceResultField instanceof FieldPath)
        )
            validateFieldPath(options.distanceResultField);
        const vector =
            options.queryVector instanceof VectorValue
                ? options.queryVector
                : new VectorValue(options.queryVector);
        if (!vector.toArray().length)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'A query vector must not be empty.'
            });
        this.executable = query._withNearest({
            vectorField: { fieldPath: options.vectorField.toString() },
            queryVector: encodeValue(vector),
            limit: options.limit,
            distanceMeasure: options.distanceMeasure,
            ...(options.distanceResultField !== undefined
                ? {
                      distanceResultField:
                          options.distanceResultField.toString()
                  }
                : {}),
            ...(options.distanceThreshold !== undefined
                ? { distanceThreshold: options.distanceThreshold }
                : {})
        });
    }
    async get(): Promise<FirestoreResult<VectorQuerySnapshot<T, DbModelType>>> {
        return firestoreResult(async () => {
            const snapshot = await this.executable.get().then(firestoreData);
            return new VectorQuerySnapshot(
                this,
                snapshot.docs,
                snapshot.readTime
            );
        });
    }
    isEqual(other: unknown): boolean {
        return (
            other instanceof VectorQuery &&
            this.executable.isEqual(other.executable)
        );
    }
    async explain(
        options?: ExplainOptions
    ): Promise<
        FirestoreResult<ExplainResults<VectorQuerySnapshot<T, DbModelType>>>
    > {
        return firestoreResult(async () => {
            const result = await this.executable
                .explain(options)
                .then(firestoreData);
            return {
                metrics: result.metrics,
                snapshot: result.snapshot
                    ? new VectorQuerySnapshot(
                          this,
                          result.snapshot.docs,
                          result.snapshot.readTime
                      )
                    : null
            };
        });
    }
}
export class VectorQuerySnapshot<
    T = DocumentData,
    DbModelType extends DocumentData = DocumentData
> {
    readonly size: number;
    readonly empty: boolean;
    /** @internal Obtain from VectorQuery.get(). */
    constructor(
        readonly query: VectorQuery<T, DbModelType>,
        readonly docs: QueryDocumentSnapshot<T, DbModelType>[],
        readonly readTime: Timestamp
    ) {
        this.size = docs.length;
        this.empty = !docs.length;
    }
    docChanges(): DocumentChange<T, DbModelType>[] {
        return new QuerySnapshot(
            this.query.query,
            this.docs,
            this.readTime
        ).docChanges();
    }
    forEach(
        callback: (doc: QueryDocumentSnapshot<T, DbModelType>) => void,
        thisArg?: unknown
    ): void {
        if (typeof callback !== 'function')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected a callback function.'
            });
        for (const doc of this.docs) callback.call(thisArg, doc);
    }
    isEqual(other: unknown): boolean {
        return (
            other instanceof VectorQuerySnapshot &&
            this.query.isEqual(other.query) &&
            this.docs.length === other.docs.length &&
            this.docs.every((doc, i) => doc.isEqual(other.docs[i]))
        );
    }
}
