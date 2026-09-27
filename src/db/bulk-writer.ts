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

const ERROR_CODES: Readonly<Record<string, number>> = {
    'firestore/aborted': 10,
    'firestore/unavailable': 14,
    'firestore/permission-denied': 7,
    'firestore/not-found': 5,
    'firestore/already-exists': 6,
    'firestore/failed-precondition': 9,
    'firestore/resource-exhausted': 8,
    'firestore/invalid-argument': 3,
    'firestore/deadline-exceeded': 4,
    'firestore/unauthenticated': 16,
    'firestore/cancelled': 1,
    'firestore/unknown': 2,
    'firestore/out-of-range': 11,
    'firestore/unimplemented': 12,
    'firestore/internal': 13,
    'firestore/data-loss': 15
};
export interface BulkWriterOptions {
    throttling?:
        | boolean
        | { initialOpsPerSecond?: number; maxOpsPerSecond?: number };
}

export class BulkWriterError extends Error {
    constructor(
        readonly code: number,
        message: string,
        readonly documentRef: DocumentReference<any>,
        readonly operationType: 'create' | 'set' | 'update' | 'delete',
        readonly failedAttempts: number
    ) {
        super(message);
        this.name = 'BulkWriterError';
    }
}

/** Independent writes run concurrently; writes to the same document stay ordered. */
export class BulkWriter {
    private readonly initialRate: number;
    private readonly maximumRate: number;
    private readonly startedAt = Date.now();
    private nextSlot = 0;
    private closed = false;
    private ready: {
        operation: WriteOperation;
        resolve: (result: WriteResult) => void;
        reject: (error: unknown) => void;
    }[] = [];
    private activeRequests = 0;
    private scheduled = false;
    private pending = new Set<Promise<unknown>>();
    private tails = new Map<string, Promise<unknown>>();
    private errorHandler?: (error: BulkWriterError) => boolean;
    private resultHandler?: (
        ref: DocumentReference<any>,
        result: WriteResult
    ) => void;
    /** @internal Use firestore.bulkWriter(). */
    constructor(
        readonly firestore: Firestore,
        options: BulkWriterOptions = {}
    ) {
        if (
            !options ||
            typeof options !== 'object' ||
            Array.isArray(options) ||
            (options.throttling !== undefined &&
                typeof options.throttling !== 'boolean' &&
                (typeof options.throttling !== 'object' ||
                    !options.throttling ||
                    Array.isArray(options.throttling)))
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid BulkWriter options.'
            });
        const config =
            typeof options.throttling === 'object' ? options.throttling : {};
        for (const rate of [config.initialOpsPerSecond, config.maxOpsPerSecond])
            if (rate !== undefined && (!Number.isFinite(rate) || rate <= 0))
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.INVALID_ARGUMENT,
                    message: 'BulkWriter rates must be positive finite numbers.'
                });
        if (
            config.initialOpsPerSecond !== undefined &&
            config.maxOpsPerSecond !== undefined &&
            config.initialOpsPerSecond > config.maxOpsPerSecond
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Initial rate must not exceed maximum rate.'
            });
        this.maximumRate =
            options.throttling === false
                ? Infinity
                : (config.maxOpsPerSecond ?? Infinity);
        this.initialRate =
            options.throttling === false
                ? Infinity
                : Math.min(config.initialOpsPerSecond ?? 500, this.maximumRate);
    }
    create<T, DbModelType extends DocumentData = DocumentData>(
        ref: DocumentReference<T, DbModelType>,
        data: WithFieldValue<T>
    ): Promise<FirestoreResult<WriteResult>> {
        return firestoreResult(async () => {
            return this.enqueue(ref, 'create', data);
        });
    }
    set<T, DbModelType extends DocumentData = DocumentData>(
        ref: DocumentReference<T, DbModelType>,
        data: WithFieldValue<T>
    ): Promise<FirestoreResult<WriteResult>>;
    set<T, DbModelType extends DocumentData = DocumentData>(
        ref: DocumentReference<T, DbModelType>,
        data: PartialWithFieldValue<T>,
        options: SetOptions
    ): Promise<FirestoreResult<WriteResult>>;
    set<T, DbModelType extends DocumentData = DocumentData>(
        ref: DocumentReference<T, DbModelType>,
        data: PartialWithFieldValue<T>,
        options?: SetOptions
    ): Promise<FirestoreResult<WriteResult>> {
        return firestoreResult(async () => {
            return this.enqueue(ref, 'set', data, options);
        });
    }
    update<T, DbModelType extends DocumentData>(
        ref: DocumentReference<T, DbModelType>,
        data: UpdateData<DbModelType>,
        precondition?: Precondition
    ): Promise<FirestoreResult<WriteResult>>;
    update(
        ref: DocumentReference<any>,
        field: string | FieldPath,
        value: unknown,
        ...moreFieldsOrPrecondition: unknown[]
    ): Promise<FirestoreResult<WriteResult>>;
    update(
        ref: DocumentReference<any>,
        data: DocumentData | string | FieldPath,
        ...args: unknown[]
    ): Promise<FirestoreResult<WriteResult>> {
        return firestoreResult(async () => {
            const update = normalizeUpdateArguments(data, args);
            return this.enqueue(
                ref,
                'update',
                update.data,
                undefined,
                update.precondition
            );
        });
    }
    delete(
        ref: DocumentReference<any>,
        precondition?: Precondition
    ): Promise<FirestoreResult<WriteResult>> {
        return firestoreResult(async () => {
            return this.enqueue(
                ref,
                'delete',
                undefined,
                undefined,
                precondition
            );
        });
    }
    onWriteError(callback: (error: BulkWriterError) => boolean): void {
        if (typeof callback !== 'function')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected an error callback.'
            });
        this.errorHandler = callback;
    }
    onWriteResult(
        callback: (ref: DocumentReference<any>, result: WriteResult) => void
    ): void {
        if (typeof callback !== 'function')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected a result callback.'
            });
        this.resultHandler = callback;
    }
    async flush(): Promise<FirestoreResult<void>> {
        return firestoreResult(async () => {
            await Promise.allSettled([...this.pending]);
        });
    }
    async close(): Promise<FirestoreResult<void>> {
        return firestoreResult(async () => {
            this.closed = true;
            await this.flush().then(firestoreData);
        });
    }
    private enqueue(
        ref: DocumentReference<any>,
        kind: WriteOperation['kind'],
        data?: unknown,
        options?: SetOptions,
        precondition?: Precondition
    ): Promise<WriteResult> {
        if (this.closed)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.FAILED_PRECONDITION,
                message: 'BulkWriter is closed.'
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
        const converted =
            kind === 'create' || kind === 'set'
                ? ref._toFirestore(data, options)
                : (data as DocumentData | undefined);
        const operation = prepareWrite(
            ref,
            kind,
            converted,
            options,
            precondition
        );
        const previous = this.tails.get(ref.path) ?? Promise.resolve();
        const result = previous.then(() => this.perform(ref, operation));
        const settled = result.then(
            () => {},
            () => {}
        );
        this.tails.set(ref.path, settled);
        this.pending.add(settled);
        void settled.then(() => {
            this.pending.delete(settled);
            if (this.tails.get(ref.path) === settled)
                this.tails.delete(ref.path);
        });
        return result;
    }
    private async perform(
        ref: DocumentReference<any>,
        operation: WriteOperation
    ): Promise<WriteResult> {
        return this.firestore._trace('BulkWriter.perform', async () => {
            let attempts = 0;
            for (;;) {
                let result: WriteResult;
                try {
                    result = await this.submit(operation);
                } catch (cause) {
                    attempts++;
                    const code =
                        ERROR_CODES[(cause as { code?: string })?.code ?? ''] ??
                        2;
                    const error = new BulkWriterError(
                        code,
                        cause instanceof Error ? cause.message : String(cause),
                        ref,
                        operation.kind,
                        attempts
                    );
                    const retry = this.errorHandler
                        ? this.errorHandler(error)
                        : ([10, 14].includes(code) ||
                              (operation.kind === 'delete' && code === 13)) &&
                          attempts < 10;
                    if (!retry) throw error;
                    await new Promise((resolve) =>
                        setTimeout(
                            resolve,
                            Math.min(10 * 2 ** (attempts - 1), 1000)
                        )
                    );
                    continue;
                }
                this.resultHandler?.(ref, result);
                return result;
            }
        });
    }
    private submit(operation: WriteOperation): Promise<WriteResult> {
        return new Promise((resolve, reject) => {
            this.ready.push({ operation, resolve, reject });
            if (this.scheduled) return;
            this.scheduled = true;
            void Promise.resolve().then(() => {
                this.scheduled = false;
                this.drain();
            });
        });
    }
    private drain(): void {
        // Small configured rates retain individual pacing; normal rates pack 20 writes.
        const batchSize = this.initialRate < 20 ? 1 : 20;
        while (this.ready.length && this.activeRequests < 10) {
            const batch = this.ready.splice(0, batchSize);
            this.activeRequests++;
            void this.dispatch(batch);
        }
    }
    private async dispatch(batch: BulkWriter['ready']): Promise<void> {
        try {
            await this.throttle(batch.length);
            const results = await this.firestore._batchWrite(
                batch.map((entry) => entry.operation)
            );
            if (results.length !== batch.length)
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.INVALID_RESPONSE,
                    message: 'Incomplete bulk write results.'
                });
            for (const [index, entry] of batch.entries()) {
                const result = results[index]!;
                if (result instanceof Error) entry.reject(result);
                else entry.resolve(result);
            }
        } catch (error) {
            for (const entry of batch) entry.reject(error);
        } finally {
            this.activeRequests--;
            this.drain();
        }
    }
    private async throttle(count: number): Promise<void> {
        if (this.maximumRate === Infinity && this.initialRate === Infinity)
            return;
        const now = Date.now();
        const slot = Math.max(now, this.nextSlot);
        const rate = Math.min(
            this.maximumRate,
            this.initialRate *
                1.5 ** Math.floor((slot - this.startedAt) / 300000)
        );
        this.nextSlot = slot + (count * 1000) / rate;
        if (slot <= now) return;
        await new Promise((resolve) =>
            setTimeout(resolve, Math.ceil(slot - now))
        );
    }
}
