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
import type { Firestore } from './firestore.js';
import {
    listenByPolling,
    type SnapshotListenOptions,
    type SnapshotCallback,
    type SnapshotErrorCallback
} from './snapshot-listener.js';
import { DocumentSnapshot } from './document-snapshot.js';
import { Timestamp } from './timestamp.js';
import { FieldPath } from './field-path.js';
import { normalizeUpdateArguments } from './write-request.js';
import type { CollectionReference } from './collection-reference.js';
import type { FirestoreDocument } from './firestore-document.js';
import { validatePath } from './firestore-path.js';
import type { DocumentData } from './firestore-document.js';
import type { SetOptions, Precondition, WriteResult } from './write-request.js';
import {
    validateConverter,
    type FirestoreDataConverter
} from './firestore-converter.js';

export type DocumentExecutor = (
    path: string
) => Promise<FirestoreDocument | undefined>;

/** A document location with read access and collection navigation. */
export class DocumentReference<
    T = DocumentData,
    DbModelType extends DocumentData = DocumentData
> {
    onSnapshot(
        next: SnapshotCallback<DocumentSnapshot<T, DbModelType>>,
        error?: SnapshotErrorCallback,
        options?: SnapshotListenOptions
    ): () => void;
    onSnapshot(
        options: SnapshotListenOptions,
        next: SnapshotCallback<DocumentSnapshot<T, DbModelType>>,
        error?: SnapshotErrorCallback
    ): () => void;
    onSnapshot(
        first:
            | SnapshotListenOptions
            | SnapshotCallback<DocumentSnapshot<T, DbModelType>>,
        second?:
            | SnapshotCallback<DocumentSnapshot<T, DbModelType>>
            | SnapshotErrorCallback,
        third?: SnapshotListenOptions | SnapshotErrorCallback
    ): () => void {
        return listenByPolling(
            this.firestore,
            () => this.get().then(firestoreData),
            (current, previous) =>
                previous?.isEqual(current) ? undefined : current,
            first,
            second,
            third
        );
    }
    async create(
        data: WithFieldValue<T>
    ): Promise<FirestoreResult<WriteResult>> {
        return firestoreResult(async () => {
            return this.firestore._trace(
                'DocumentReference.create',
                async () => {
                    const results = await this.firestore
                        .batch()
                        .create(this, data)
                        .commit()
                        .then(firestoreData);
                    return results[0]!;
                }
            );
        });
    }
    set(data: WithFieldValue<T>): Promise<FirestoreResult<WriteResult>>;
    set(
        data: PartialWithFieldValue<T>,
        options: SetOptions
    ): Promise<FirestoreResult<WriteResult>>;
    async set(
        data: PartialWithFieldValue<T>,
        options?: SetOptions
    ): Promise<FirestoreResult<WriteResult>> {
        return firestoreResult(async () => {
            return this.firestore._trace('DocumentReference.set', async () => {
                const batch = this.firestore.batch();
                if (options === undefined) {
                    batch.set(this, data as WithFieldValue<T>);
                } else {
                    batch.set(this, data, options);
                }
                const results = await batch.commit().then(firestoreData);
                return results[0]!;
            });
        });
    }
    update(
        data: UpdateData<DbModelType>,
        precondition?: Precondition
    ): Promise<FirestoreResult<WriteResult>>;
    update(
        field: string | FieldPath,
        value: unknown,
        ...moreFieldsOrPrecondition: unknown[]
    ): Promise<FirestoreResult<WriteResult>>;
    async update(
        data: DocumentData | string | FieldPath,
        ...args: unknown[]
    ): Promise<FirestoreResult<WriteResult>> {
        return firestoreResult(async () => {
            return this.firestore._trace(
                'DocumentReference.update',
                async () => {
                    const update = normalizeUpdateArguments(data, args);
                    const results = await this.firestore
                        .batch()
                        .update(this, update.data, update.precondition)
                        .commit()
                        .then(firestoreData);
                    return results[0]!;
                }
            );
        });
    }
    async delete(
        precondition?: Precondition
    ): Promise<FirestoreResult<WriteResult>> {
        return firestoreResult(async () => {
            return this.firestore._trace(
                'DocumentReference.delete',
                async () => {
                    const results = await this.firestore
                        .batch()
                        .delete(this, precondition)
                        .commit()
                        .then(firestoreData);
                    return results[0]!;
                }
            );
        });
    }
    readonly id: string;

    /** @internal Obtain references from firestore.doc() or collection.doc(). */
    constructor(
        readonly firestore: Firestore,
        readonly path: string,
        private readonly execute: DocumentExecutor,
        readonly converter: FirestoreDataConverter<T, DbModelType> | null = null
    ) {
        validatePath(path, true);
        this.id = path.split('/').at(-1)!;
    }

    get parent(): CollectionReference<T, DbModelType> {
        return this.firestore
            .collection(this.path.slice(0, this.path.lastIndexOf('/')))
            .withConverter(this.converter);
    }

    collection(collectionPath: string): CollectionReference {
        validatePath(collectionPath, false);
        return this.firestore.collection(`${this.path}/${collectionPath}`);
    }

    async get(): Promise<FirestoreResult<DocumentSnapshot<T, DbModelType>>> {
        return firestoreResult(async () => {
            return this.firestore._trace('DocumentReference.get', async () => {
                const readTime = Timestamp.now();
                const document = await this.execute(this.path);
                return new DocumentSnapshot(this, document, readTime);
            });
        });
    }

    isEqual(other: DocumentReference<any>): boolean {
        if (!(other instanceof DocumentReference)) return false;
        return (
            this.firestore === other.firestore &&
            this.path === other.path &&
            this.converter === other.converter
        );
    }

    withConverter<U, NewDbModelType extends DocumentData = DocumentData>(
        converter: FirestoreDataConverter<U, NewDbModelType>
    ): DocumentReference<U, NewDbModelType>;
    withConverter(converter: null): DocumentReference;
    withConverter<U, NewDbModelType extends DocumentData = DocumentData>(
        converter: FirestoreDataConverter<U, NewDbModelType> | null
    ): DocumentReference<U, NewDbModelType>;
    withConverter<U, NewDbModelType extends DocumentData = DocumentData>(
        converter: FirestoreDataConverter<U, NewDbModelType> | null
    ): DocumentReference<U, NewDbModelType> {
        validateConverter(converter);
        return new DocumentReference(
            this.firestore,
            this.path,
            this.execute,
            converter
        );
    }
    listCollections(): Promise<FirestoreResult<CollectionReference[]>> {
        return firestoreResult(async () => {
            return this.firestore._trace(
                'DocumentReference.listCollections',
                async () => {
                    return this.firestore._listCollections(this.path);
                }
            );
        });
    }
    /** @internal Updates deliberately bypass converters, matching Admin Firestore. */
    _toFirestore(
        data: PartialWithFieldValue<T>,
        options?: SetOptions
    ): DocumentData {
        if (!this.converter) return data as DocumentData;
        if (options === undefined)
            return this.converter.toFirestore(data as WithFieldValue<T>);
        return this.converter.toFirestore(data, options);
    }
}
