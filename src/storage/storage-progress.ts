import { FirebaseEdgeError, ensureError } from '../auth/errors.js';
import type {
    StorageProgressCallback,
    StorageTransferProgress
} from './storage-types.js';

/** @internal Call progress observers after the server acknowledges bytes. */
export async function reportStorageProgress(
    callback: StorageProgressCallback | undefined,
    progress: StorageTransferProgress
) {
    if (!callback) {
        return;
    }
    try {
        await callback(progress);
    } catch (cause) {
        throw new FirebaseEdgeError(
            {
                code: 'storage/progress-callback-failed',
                message:
                    'Upload progress callback failed after the server acknowledged the request.'
            },
            { cause: ensureError(cause), context: { ...progress } }
        );
    }
}
