import { Query, type QueryExecutor } from './query.js';
import type { Firestore } from './firestore.js';
import type { DocumentData } from './firestore-document.js';
import {
    validateConverter,
    type FirestoreDataConverter
} from './firestore-converter.js';
import { FieldPath } from './field-path.js';
import { QueryPartition } from './query-partition.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';

export class CollectionGroup<
    T = DocumentData,
    DbModelType extends DocumentData = DocumentData
> extends Query<T, DbModelType> {
    /** @internal Use firestore.collectionGroup(). */
    constructor(
        firestore: Firestore,
        collectionId: string,
        execute: QueryExecutor,
        converter: FirestoreDataConverter<T, DbModelType> | null = null
    ) {
        if (
            typeof collectionId !== 'string' ||
            !collectionId ||
            collectionId.includes('/') ||
            ['.', '..'].includes(collectionId)
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'A collection group requires a single collection ID.'
            });
        super(
            firestore,
            collectionId,
            execute,
            { allDescendants: true },
            converter
        );
    }
    async *getPartitions(
        desiredPartitionCount: number
    ): AsyncGenerator<QueryPartition<T, DbModelType>> {
        if (
            !Number.isSafeInteger(desiredPartitionCount) ||
            desiredPartitionCount < 1
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Partition count must be a positive safe integer.'
            });
        const paths =
            desiredPartitionCount === 1
                ? []
                : await this.firestore._partitionQuery(
                      this.collectionPath,
                      desiredPartitionCount
                  );
        const query = this.orderBy(FieldPath.documentId());
        let start: string | undefined;
        for (const end of paths) {
            yield new QueryPartition(query, start, end);
            start = end;
        }
        yield new QueryPartition(query, start, undefined);
    }
    override withConverter<
        U,
        NewDbModelType extends DocumentData = DocumentData
    >(
        converter: FirestoreDataConverter<U, NewDbModelType>
    ): CollectionGroup<U, NewDbModelType>;
    override withConverter(converter: null): CollectionGroup;
    override withConverter<
        U,
        NewDbModelType extends DocumentData = DocumentData
    >(
        converter: FirestoreDataConverter<U, NewDbModelType> | null
    ): CollectionGroup<U, NewDbModelType>;
    override withConverter<
        U,
        NewDbModelType extends DocumentData = DocumentData
    >(
        converter: FirestoreDataConverter<U, NewDbModelType> | null
    ): CollectionGroup<U, NewDbModelType> {
        validateConverter(converter);
        return new CollectionGroup(
            this.firestore,
            this.collectionPath,
            this.execute,
            converter
        );
    }
}
