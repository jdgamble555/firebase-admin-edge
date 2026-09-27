import type {
    WithFieldValue,
    PartialWithFieldValue
} from './firestore-types.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { DocumentData } from './firestore-document.js';
import type { QueryDocumentSnapshot } from './query-document-snapshot.js';
import type { SetOptions } from './write-request.js';

export interface FirestoreDataConverter<
    T,
    DbModelType extends DocumentData = DocumentData
> {
    toFirestore(model: WithFieldValue<T>): WithFieldValue<DbModelType>;
    toFirestore(
        model: PartialWithFieldValue<T>,
        options: SetOptions
    ): PartialWithFieldValue<DbModelType>;
    fromFirestore(snapshot: QueryDocumentSnapshot): T;
}

export function validateConverter<T, DbModelType extends DocumentData>(
    converter: FirestoreDataConverter<T, DbModelType> | null
): void {
    if (converter === null) return;
    if (
        !converter ||
        typeof converter.toFirestore !== 'function' ||
        typeof converter.fromFirestore !== 'function'
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message:
                'A converter requires toFirestore and fromFirestore methods.'
        });
}
