import { FirebaseEdgeError, ensureError } from '../auth/errors.js';

export type RemoteConfigResult<T> =
    | { error: null; data: T }
    | { error: FirebaseEdgeError; data: null };

/** @internal */
export function remoteConfigError(cause: unknown): FirebaseEdgeError {
    if (cause instanceof FirebaseEdgeError) {
        return cause;
    }
    const error = ensureError(cause);

    return new FirebaseEdgeError(
        {
            code:
                cause instanceof SyntaxError
                    ? 'remote-config/invalid-argument'
                    : 'remote-config/unknown-error',
            message: error.message
        },
        { cause: error }
    );
}

/** @internal */
export function invalidRemoteConfig(message: string): never {
    throw new FirebaseEdgeError({
        code: 'remote-config/invalid-argument',
        message
    });
}

/** @internal */
export function isRemoteConfigObject<T>(
    value: T
): value is T & Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
