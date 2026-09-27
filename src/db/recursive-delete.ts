import { firestoreData } from './firestore-results.js';
import { DocumentReference } from './document-reference.js';
import type { CollectionReference } from './collection-reference.js';
import type { BulkWriter } from './bulk-writer.js';
import { FirebaseEdgeError, ensureError } from '../auth/errors.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';

/** @internal Enumerate missing ancestor documents too, so orphaned children are deleted. */
export async function deleteRecursively(
    ref: DocumentReference<any> | CollectionReference<any>,
    writer: BulkWriter
): Promise<void> {
    const queue: (DocumentReference<any> | CollectionReference<any>)[] = [ref];
    let failures = 0;
    let lastError: unknown;
    for (let index = 0; index < queue.length; index++) {
        const current = queue[index]!;
        try {
            const children =
                current instanceof DocumentReference
                    ? await current.listCollections().then(firestoreData)
                    : await current.listDocuments().then(firestoreData);
            queue.push(...children);
        } catch (error) {
            failures++;
            lastError = error;
        }
        if (!(current instanceof DocumentReference)) continue;
        try {
            await writer.delete(current).then(firestoreData);
        } catch (error) {
            failures++;
            lastError = error;
        }
    }
    if (failures)
        throw new FirebaseEdgeError(
            {
                ...FirestoreErrorInfo.UNKNOWN,
                message: `${failures} recursive delete operation(s) failed. Last error: ${lastError instanceof Error ? lastError.message : String(lastError)}`
            },
            { cause: ensureError(lastError) }
        );
}
