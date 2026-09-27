import {
    type FirestoreResult,
    firestoreResult,
    firestoreData
} from './firestore-results.js';
import type {
    WithFieldValue,
    PartialWithFieldValue,
    UpdateData
} from './firestore-types.js';
import { Pipeline, type PipelineSnapshot } from './pipeline.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { Firestore, ReadOptions } from './firestore.js';
import { Query, type QuerySnapshot } from './query.js';
import {
    AggregateQuery,
    type AggregateSpec,
    type AggregateQuerySnapshot
} from './aggregate.js';
import { DocumentReference } from './document-reference.js';
import { FieldPath } from './field-path.js';
import { normalizeUpdateArguments } from './write-request.js';
import type { DocumentSnapshot } from './document-snapshot.js';
import type { DocumentData } from './firestore-document.js';
import {
    WriteBatch,
    type SetOptions,
    type Precondition
} from './write-batch.js';
import type { WriteOperation, WriteResult } from './write-request.js';

export class Transaction {
    execute(pipeline: Pipeline): Promise<FirestoreResult<PipelineSnapshot>> {
        return firestoreResult(async () => {
            this.assertOpen();
            if (this.written || this.pipelineWritten || !this.transactionId) {
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.FAILED_PRECONDITION,
                    message:
                        'Pipeline reads require an active transaction before writes.'
                });
            }
            if (
                !(pipeline instanceof Pipeline) ||
                pipeline.firestore !== this.firestore
            ) {
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.INVALID_ARGUMENT,
                    message: 'Pipeline must belong to this Firestore.'
                });
            }
            if (pipeline._hasWrites && this.readOnly) {
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.FAILED_PRECONDITION,
                    message:
                        'Read-only transactions cannot execute mutation pipelines.'
                });
            }
            if (pipeline._hasWrites) {
                this.pipelineWritten = true;
            }
            const result = pipeline._execute({}, this.transactionId);
            this.reads.push(result);
            void result.catch(() => {});
            return result;
        });
    }

    private readonly batch: WriteBatch;
    private written = false;
    private pipelineWritten = false;
    private closed = false;
    private readonly reads: Promise<unknown>[] = [];
    /** @internal Use firestore.runTransaction(). */
    constructor(
        readonly firestore: Firestore,
        private readonly read: (
            ref: DocumentReference<any>
        ) => Promise<DocumentSnapshot<any>>,
        private readonly commitWrites: (
            writes: WriteOperation[]
        ) => Promise<WriteResult[]>,
        private readonly readOnly = false,
        private readonly transactionId?: string
    ) {
        this.batch = new WriteBatch(firestore, commitWrites);
    }
    get<T, DbModelType extends DocumentData = DocumentData>(
        ref: DocumentReference<T, DbModelType>
    ): Promise<FirestoreResult<DocumentSnapshot<T, DbModelType>>>;
    get<T, DbModelType extends DocumentData = DocumentData>(
        ref: Query<T, DbModelType>
    ): Promise<FirestoreResult<QuerySnapshot<T, DbModelType>>>;
    get<S extends AggregateSpec, T, DbModelType extends DocumentData>(
        ref: AggregateQuery<S, T, DbModelType>
    ): Promise<FirestoreResult<AggregateQuerySnapshot<S, T, DbModelType>>>;
    get<T, DbModelType extends DocumentData = DocumentData>(
        ref:
            | DocumentReference<T, DbModelType>
            | Query<T, DbModelType>
            | AggregateQuery<any, any, any>
    ): Promise<
        FirestoreResult<
            | DocumentSnapshot<T, DbModelType>
            | QuerySnapshot<T, DbModelType>
            | AggregateQuerySnapshot<any, any, any>
        >
    > {
        return firestoreResult(async () => {
            this.assertOpen();
            if (this.written || this.pipelineWritten) {
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.FAILED_PRECONDITION,
                    message: 'Transaction reads must precede writes.'
                });
            }
            const owner =
                ref instanceof AggregateQuery
                    ? ref.query.firestore
                    : ref?.firestore;
            if (
                !(
                    ref instanceof DocumentReference ||
                    ref instanceof Query ||
                    ref instanceof AggregateQuery
                ) ||
                owner !== this.firestore
            ) {
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.INVALID_ARGUMENT,
                    message:
                        'DocumentReference must belong to this Firestore instance.'
                });
            }
            if (!(ref instanceof DocumentReference) && !this.transactionId) {
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.FAILED_PRECONDITION,
                    message: 'A server transaction is required.'
                });
            }
            const result =
                ref instanceof DocumentReference
                    ? this.read(ref)
                    : ref._get(this.transactionId);
            this.reads.push(result);
            void result.catch(() => {});
            return result;
        });
    }
    getAll<T = DocumentData, DbModelType extends DocumentData = DocumentData>(
        ...refs: (DocumentReference<T, DbModelType> | ReadOptions)[]
    ): Promise<FirestoreResult<DocumentSnapshot<T, DbModelType>[]>> {
        return firestoreResult(async () => {
            this.assertOpen();
            if (this.written || this.pipelineWritten) {
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.FAILED_PRECONDITION,
                    message: 'Transaction reads must precede writes.'
                });
            }
            if (!this.transactionId) {
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.FAILED_PRECONDITION,
                    message: 'A server transaction is required.'
                });
            }
            const result = this.firestore._getAll(refs, this.transactionId);
            this.reads.push(result);
            void result.catch(() => {});
            return result;
        });
    }
    create<T, DbModelType extends DocumentData = DocumentData>(
        ref: DocumentReference<T, DbModelType>,
        data: WithFieldValue<T>
    ): this {
        this.assertWritable();
        this.batch.create(ref, data);
        this.written = true;
        return this;
    }
    set<T, DbModelType extends DocumentData = DocumentData>(
        ref: DocumentReference<T, DbModelType>,
        data: WithFieldValue<T>
    ): this;
    set<T, DbModelType extends DocumentData = DocumentData>(
        ref: DocumentReference<T, DbModelType>,
        data: PartialWithFieldValue<T>,
        options: SetOptions
    ): this;
    set<T, DbModelType extends DocumentData = DocumentData>(
        ref: DocumentReference<T, DbModelType>,
        data: PartialWithFieldValue<T>,
        options?: SetOptions
    ): this {
        this.assertWritable();
        if (options === undefined)
            this.batch.set(ref, data as WithFieldValue<T>);
        else this.batch.set(ref, data, options);
        this.written = true;
        return this;
    }
    update<T, DbModelType extends DocumentData>(
        ref: DocumentReference<T, DbModelType>,
        data: UpdateData<DbModelType>,
        precondition?: Precondition
    ): this;
    update(
        ref: DocumentReference<any>,
        field: string | FieldPath,
        value: unknown,
        ...moreFieldsOrPrecondition: unknown[]
    ): this;
    update(
        ref: DocumentReference<any>,
        data: DocumentData | string | FieldPath,
        ...args: unknown[]
    ): this {
        this.assertWritable();
        const update = normalizeUpdateArguments(data, args);
        this.batch.update(ref, update.data, update.precondition);
        this.written = true;
        return this;
    }
    delete(ref: DocumentReference<any>, precondition?: Precondition): this {
        this.assertWritable();
        this.batch.delete(ref, precondition);
        this.written = true;
        return this;
    }
    /** @internal */
    async _commit(): Promise<void> {
        this.assertOpen();
        this.closed = true;
        await Promise.all(this.reads);
        if (!this.written) {
            await this.commitWrites([]);
            return;
        }
        await this.batch.commit().then(firestoreData);
    }
    /** @internal */
    _close(): void {
        this.closed = true;
    }
    private assertOpen(): void {
        if (this.closed)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.FAILED_PRECONDITION,
                message: 'Transaction is closed.'
            });
    }
    private assertWritable(): void {
        this.assertOpen();
        if (this.readOnly)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.FAILED_PRECONDITION,
                message: 'Read-only transactions cannot write.'
            });
    }
}
