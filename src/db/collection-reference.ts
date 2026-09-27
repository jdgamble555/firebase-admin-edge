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
import { Query, type QueryExecutor } from './query.js';
import { validatePath } from './firestore-path.js';
import type { Firestore, DocumentReference } from './firestore.js';
import type { DocumentData } from './firestore-document.js';
import {
    validateConverter,
    type FirestoreDataConverter
} from './firestore-converter.js';
import { autoId } from './firestore-path.js';

/** A collection reference is also an unfiltered query. */
export class CollectionReference<
    T = DocumentData,
    DbModelType extends DocumentData = DocumentData
> extends Query<T, DbModelType> {
    readonly id: string;
    readonly parent: DocumentReference | null;
    /** @internal Obtain collection references from firestore.collection(). */
    constructor(
        firestore: Firestore,
        readonly path: string,
        execute: QueryExecutor,
        converter: FirestoreDataConverter<T, DbModelType> | null = null
    ) {
        validatePath(path, false);
        super(firestore, path, execute, {}, converter);
        const segments = path.split('/');
        this.id = segments.pop()!;
        this.parent = segments.length
            ? firestore.doc(segments.join('/'))
            : null;
    }

    doc(documentPath: string = autoId()): DocumentReference<T, DbModelType> {
        validatePath(documentPath, false);
        return this.firestore
            .doc(`${this.path}/${documentPath}`)
            .withConverter(this.converter);
    }
    async add(
        data: WithFieldValue<T>
    ): Promise<FirestoreResult<DocumentReference<T, DbModelType>>> {
        return firestoreResult(async () => {
            const ref = this.doc();
            await ref.create(data).then(firestoreData);
            return ref;
        });
    }
    async listDocuments(): Promise<
        FirestoreResult<DocumentReference<T, DbModelType>[]>
    > {
        return firestoreResult(async () => {
            const paths = await this.firestore._listDocuments(this.path);
            return paths.map((path) =>
                this.firestore.doc(path).withConverter(this.converter)
            );
        });
    }
    override withConverter<
        U,
        NewDbModelType extends DocumentData = DocumentData
    >(
        converter: FirestoreDataConverter<U, NewDbModelType>
    ): CollectionReference<U, NewDbModelType>;
    override withConverter(converter: null): CollectionReference;
    override withConverter<
        U,
        NewDbModelType extends DocumentData = DocumentData
    >(
        converter: FirestoreDataConverter<U, NewDbModelType> | null
    ): CollectionReference<U, NewDbModelType>;
    override withConverter<
        U,
        NewDbModelType extends DocumentData = DocumentData
    >(
        converter: FirestoreDataConverter<U, NewDbModelType> | null
    ): CollectionReference<U, NewDbModelType> {
        validateConverter(converter);
        return new CollectionReference(
            this.firestore,
            this.path,
            this.execute,
            converter
        );
    }
}
