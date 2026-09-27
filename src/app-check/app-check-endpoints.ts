import { createRemoteJWKSet, customFetch } from 'jose';
import { restFetch } from '../rest-fetch.js';
import { FirebaseEdgeError } from '../auth/errors.js';

/** @internal A reusable resolver with bounded caching and key rotation. */
export function createAppCheckKeyResolver(fetch: typeof globalThis.fetch) {
    return createRemoteJWKSet(
        new URL('https://firebaseappcheck.googleapis.com/v1/jwks'),
        {
            [customFetch]: fetch
        }
    );
}

/** @internal Authenticated App Check operations. */
export async function appCheckRequest(
    projectId: string,
    accessToken: string,
    operation:
        | {
              appId: string;
              customToken: string;
              limitedUse?: boolean;
              jti?: string;
          }
        | { token: string },
    fetch: typeof globalThis.fetch
) {
    const project = encodeURIComponent(projectId);
    const exchange = 'appId' in operation;
    const path = exchange
        ? `v1/projects/${project}/apps/${encodeURIComponent(operation.appId)}:exchangeCustomToken`
        : `v1beta/projects/${project}:verifyAppCheckToken`;
    const { error, data } = await restFetch<
        { token?: string; ttl?: string; alreadyConsumed?: boolean },
        { error?: { status?: string; message?: string } } | string
    >(`https://firebaseappcheck.googleapis.com/${path}`, {
        method: 'POST',
        bearerToken: accessToken,
        body: exchange
            ? {
                  customToken: operation.customToken,
                  ...(operation.limitedUse !== undefined && {
                      limitedUse: operation.limitedUse
                  }),
                  ...(operation.jti !== undefined && { jti: operation.jti })
              }
            : { app_check_token: operation.token },
        global: { fetch }
    });
    if (error !== null) {
        const status =
            typeof error === 'object' ? error?.error?.status : undefined;
        const codes: Record<string, string> = {
            INVALID_ARGUMENT: 'invalid-argument',
            PERMISSION_DENIED: 'permission-denied',
            UNAUTHENTICATED: 'unauthenticated',
            NOT_FOUND: 'not-found',
            RESOURCE_EXHAUSTED: 'resource-exhausted'
        };
        throw new FirebaseEdgeError({
            code: `app-check/${codes[status ?? ''] ?? 'unknown-error'}`,
            message:
                typeof error === 'string'
                    ? error
                    : (error?.error?.message ?? 'App Check request failed.')
        });
    }
    if (!data || typeof data !== 'object') {
        throw new FirebaseEdgeError({
            code: 'app-check/internal-error',
            message: 'Invalid App Check response.'
        });
    }
    return data;
}

/** @internal Convert the exchange response's protobuf duration. */
export function parseAppCheckToken(data: { token?: string; ttl?: string }) {
    if (
        typeof data.token !== 'string' ||
        !data.token ||
        typeof data.ttl !== 'string' ||
        !/^\d+(?:\.\d{1,9})?s$/.test(data.ttl)
    ) {
        throw new FirebaseEdgeError({
            code: 'app-check/internal-error',
            message: 'Invalid App Check token response.'
        });
    }
    const ttlMillis = Math.floor(Number(data.ttl.slice(0, -1)) * 1000);
    if (!Number.isSafeInteger(ttlMillis) || ttlMillis <= 0) {
        throw new FirebaseEdgeError({
            code: 'app-check/internal-error',
            message: 'Invalid App Check token lifetime.'
        });
    }
    return { token: data.token, ttlMillis };
}
