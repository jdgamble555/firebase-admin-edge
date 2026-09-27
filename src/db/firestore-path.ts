import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
export function validatePath(path: string, document: boolean): void {
    if (typeof path !== 'string' || !path.length)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Firestore path must be a non-empty string.'
        });
    const segments = path.split('/');
    if (
        segments.some(
            (segment) => !segment || segment === '.' || segment === '..'
        )
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Firestore path contains an invalid segment.'
        });
    if ((segments.length % 2 === 0) !== document)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: `Expected a Firestore ${document ? 'document' : 'collection'} path.`
        });
}

/** @internal Generate an unbiased, cryptographically random Firestore document ID. */
export function autoId(): string {
    const alphabet =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let id = '';
    while (id.length < 20) {
        const bytes = crypto.getRandomValues(new Uint8Array(40));
        for (const byte of bytes) {
            if (byte >= 248) continue;
            id += alphabet[byte % 62];
            if (id.length === 20) return id;
        }
    }
    return id;
}
