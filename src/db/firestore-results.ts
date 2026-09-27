import { ensureError } from '../auth/errors.js';

export type FirestoreResult<T> =
    | { error: null; data: T }
    | { error: Error; data: null };

/** @internal Keep public async failures in the package result convention. */
export async function firestoreResult<T>(
    operation: () => Promise<T>
): Promise<FirestoreResult<T>> {
    try {
        const data = await operation();
        return { error: null, data };
    } catch (cause) {
        return { error: ensureError(cause), data: null };
    }
}

/** @internal Unwrap composed operations inside a result boundary or listener. */
export function firestoreData<T>({ error, data }: FirestoreResult<T>): T {
    if (error) {
        throw error;
    }
    return data;
}
