import { FirebaseEdgeError } from '../auth/errors.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';
let logger: ((message: string) => void) | null = null;
export function setLogFunction(
    logFunction: ((message: string) => void) | null
): void {
    if (logFunction !== null && typeof logFunction !== 'function')
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Expected a logger function or null.'
        });
    logger = logFunction;
}
/** @internal Diagnostics must never alter request outcomes. */
export function logFirestore(message: string): void {
    try {
        logger?.(message);
    } catch {
        /* Ignore diagnostic callback failures. */
    }
}
export enum GrpcStatus {
    OK = 0,
    CANCELLED = 1,
    UNKNOWN = 2,
    INVALID_ARGUMENT = 3,
    DEADLINE_EXCEEDED = 4,
    NOT_FOUND = 5,
    ALREADY_EXISTS = 6,
    PERMISSION_DENIED = 7,
    RESOURCE_EXHAUSTED = 8,
    FAILED_PRECONDITION = 9,
    ABORTED = 10,
    OUT_OF_RANGE = 11,
    UNIMPLEMENTED = 12,
    INTERNAL = 13,
    UNAVAILABLE = 14,
    DATA_LOSS = 15,
    UNAUTHENTICATED = 16
}
