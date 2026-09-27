import { type FirestoreResult, firestoreResult } from './firestore-results.js';
import type {
    WithFieldValue,
    PartialWithFieldValue,
    UpdateData
} from './firestore-types.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { Firestore } from './firestore.js';
import { DocumentReference } from './document-reference.js';
import { FieldPath } from './field-path.js';
import { normalizeUpdateArguments } from './write-request.js';
import type { DocumentData } from './firestore-document.js';
import {
    prepareWrite,
    type WriteOperation,
    type WriteResult,
    type SetOptions,
    type Precondition
} from './write-request.js';
export type { WriteResult, SetOptions, Precondition } from './write-request.js';

export class WriteBatch {
    private writes: WriteOperation[] = [];
    private committed = false;
    /** @internal Use firestore.batch(). */
    constructor(
        readonly firestore: Firestore,
        private readonly execute: (
            writes: WriteOperation[]
        ) => Promise<WriteResult[]>
    ) {}
    create<T, DbModelType extends DocumentData = DocumentData>(
        ref: DocumentReference<T, DbModelType>,
        data: WithFieldValue<T>
    ): this {
        return this.add(ref, 'create', data);
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
        return this.add(ref, 'set', data, options);
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
        const update = normalizeUpdateArguments(data, args);
        return this.add(
            ref,
            'update',
            update.data,
            undefined,
            update.precondition
        );
    }
    delete(ref: DocumentReference<any>, precondition?: Precondition): this {
        return this.add(ref, 'delete', undefined, undefined, precondition);
    }
    async commit(): Promise<FirestoreResult<WriteResult[]>> {
        return firestoreResult(async () => {
            return this.firestore._trace('WriteBatch.commit', async () => {
                if (this.committed) {
                    throw new FirebaseEdgeError({
                        ...FirestoreErrorInfo.FAILED_PRECONDITION,
                        message: 'WriteBatch has already been committed.'
                    });
                }
                this.committed = true;
                if (!this.writes.length) {
                    return [];
                }
                return this.execute(this.writes);
            });
        });
    }
    private add(
        ref: DocumentReference<any>,
        kind: WriteOperation['kind'],
        data?: unknown,
        options?: SetOptions,
        precondition?: Precondition
    ): this {
        if (this.committed)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.FAILED_PRECONDITION,
                message: 'WriteBatch has already been committed.'
            });
        if (
            !(ref instanceof DocumentReference) ||
            ref.firestore !== this.firestore
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message:
                    'DocumentReference must belong to this Firestore instance.'
            });
        if (this.writes.length >= 500)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'A batch supports at most 500 writes.'
            });
        const converted =
            kind === 'create' || kind === 'set'
                ? ref._toFirestore(data, options)
                : (data as DocumentData | undefined);
        this.writes.push(
            prepareWrite(ref, kind, converted, options, precondition)
        );
        return this;
    }
}
