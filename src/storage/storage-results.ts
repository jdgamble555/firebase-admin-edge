import { FirebaseEdgeError, ensureError } from '../auth/errors.js';
import type { StorageResult } from './storage-types.js';

/** @internal Adapt composed operations to the package result convention. */
export async function storageResult<T>(
    operation: () => Promise<T>
): Promise<StorageResult<T>> {
    try {
        const data = await operation();
        return { error: null, data };
    } catch (cause) {
        const error =
            cause instanceof FirebaseEdgeError
                ? cause
                : new FirebaseEdgeError(
                      {
                          code: 'storage/internal-error',
                          message: 'Storage operation failed.'
                      },
                      { cause: ensureError(cause) }
                  );
        return { error, data: null };
    }
}

/** @internal Unwrap only inside an operation whose boundary restores StorageResult. */
export function storageData<T>({ error, data }: StorageResult<T>): T {
    if (error) {
        throw error;
    }
    return data;
}

/** @internal Report unsupported Node-specific features rather than silently ignoring them. */
export function storageUnsupported(feature: string): never {
    throw new FirebaseEdgeError({
        code: 'storage/unsupported-operation',
        message: `${feature} is not available in edge runtimes.`
    });
}
