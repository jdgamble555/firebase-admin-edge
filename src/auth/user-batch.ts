import { FirebaseEdgeError, FirebaseAdminAuthErrorInfo } from './errors.js';
import { validateUserUid } from './user-request.js';

export interface FirebaseArrayIndexError {
    index: number;
    error: FirebaseEdgeError;
}
export interface DeleteUsersResult {
    successCount: number;
    failureCount: number;
    errors: FirebaseArrayIndexError[];
}
export interface UserImportResult extends DeleteUsersResult {}
export interface BatchUserError {
    index: number;
    message?: string;
}

/** Validate the entire delete batch before making any changes. */
export function validateDeleteUsers(uids: string[]): FirebaseEdgeError | null {
    if (!Array.isArray(uids) || uids.length > 1000) {
        return new FirebaseEdgeError({
            ...FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT,
            message: 'uids must be an array of at most 1000 UIDs.'
        });
    }
    for (const uid of uids) {
        const error = validateUserUid(uid);
        if (error) return error;
    }
    return null;
}

/** Merge API failures with local import failures, retaining original input indices. */
export function createBatchUserResult(
    indices: number[],
    failures: BatchUserError[] = [],
    localErrors: FirebaseArrayIndexError[] = [],
    operation: 'delete' | 'import' = 'delete'
): DeleteUsersResult {
    if (!Array.isArray(failures))
        throw new Error('Invalid batch error response.');
    const errors = [...localErrors];
    const seen = new Set<number>();
    for (const failure of failures) {
        if (
            !failure ||
            !Number.isInteger(failure.index) ||
            indices[failure.index] === undefined ||
            seen.has(failure.index)
        ) {
            throw new Error('Invalid batch error index.');
        }
        seen.add(failure.index);
        errors.push({
            index: indices[failure.index]!,
            error: new FirebaseEdgeError({
                code:
                    operation === 'import'
                        ? 'auth/admin-invalid-user-import'
                        : 'auth/admin-delete-user-failed',
                message: failure.message || `Failed to ${operation} user.`
            })
        });
    }
    errors.sort((a, b) => a.index - b.index);
    return {
        successCount: indices.length - failures.length,
        failureCount: errors.length,
        errors
    };
}
