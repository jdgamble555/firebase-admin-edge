import { FirebaseEdgeError, ensureError } from '../auth/errors.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';
import type { Firestore } from './firestore.js';

export interface SnapshotListenOptions {
    /** Delay after each completed poll, in milliseconds. Defaults to 5000. */
    pollIntervalMs?: number;
}
export type SnapshotCallback<T> = (snapshot: T) => void;
export type SnapshotErrorCallback = (error: Error) => void;

/** @internal Shared non-overlapping polling lifecycle for document and query listeners. */
export function listenByPolling<T>(
    firestore: Firestore,
    read: () => Promise<T>,
    update: (current: T, previous: T | undefined) => T | undefined,
    first: SnapshotListenOptions | SnapshotCallback<T>,
    second?: SnapshotCallback<T> | SnapshotErrorCallback,
    third?: SnapshotListenOptions | SnapshotErrorCallback
): () => void {
    const options = typeof first === 'function' ? (third ?? {}) : first;
    const next = typeof first === 'function' ? first : second;
    const error = typeof first === 'function' ? second : third;
    if (
        !options ||
        typeof options !== 'object' ||
        Array.isArray(options) ||
        typeof next !== 'function' ||
        (error !== undefined && typeof error !== 'function')
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Invalid snapshot listener arguments.'
        });
    const interval = (options as SnapshotListenOptions).pollIntervalMs ?? 5000;
    if (!Number.isInteger(interval) || interval <= 0 || interval > 2147483647)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'pollIntervalMs must be a positive 32-bit integer.'
        });
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let previous: T | undefined;
    let unregister: (() => void) | undefined;
    const stop = () => {
        if (stopped) return;
        stopped = true;
        clearTimeout(timer);
        unregister?.();
    };
    const poll = async () => {
        if (stopped) return;
        try {
            const current = await read();
            if (stopped) return;
            const changed = update(current, previous);
            previous = current;
            if (changed !== undefined) (next as SnapshotCallback<T>)(changed);
        } catch (cause) {
            if (stopped) return;
            stop();
            try {
                if (error) (error as SnapshotErrorCallback)(ensureError(cause));
                else
                    console.error('Firestore polling listener stopped:', cause);
            } catch (callbackError) {
                console.error(
                    'Firestore polling error callback failed:',
                    callbackError
                );
            }
            return;
        }
        if (stopped) return;
        timer = setTimeout(() => {
            void poll();
        }, interval);
    };
    unregister = firestore._registerSnapshotListener(stop);
    void Promise.resolve().then(poll);
    return stop;
}
