import { FirebaseEdgeError } from '../auth/errors.js';

export interface StorageRetryOptions {
    /** Additional attempts for safe operations. Defaults to 2. */
    maxRetries?: number;
    initialDelayMs?: number;
    maxDelayMs?: number;
}

/** @internal Apply bounded exponential backoff only to replayable Storage requests. */
export function createStorageRetryFetch(
    fetch: typeof globalThis.fetch,
    options: StorageRetryOptions = {}
): typeof globalThis.fetch {
    if (!options || typeof options !== 'object' || Array.isArray(options)) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Retry options must be an object.'
        });
    }
    const { maxRetries = 2, initialDelayMs = 100, maxDelayMs = 2000 } = options;
    if (
        !Number.isInteger(maxRetries) ||
        maxRetries < 0 ||
        maxRetries > 10 ||
        !Number.isFinite(initialDelayMs) ||
        initialDelayMs < 0 ||
        !Number.isFinite(maxDelayMs) ||
        maxDelayMs < initialDelayMs ||
        maxDelayMs > 60000
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Invalid retry count or delay bounds.'
        });
    }
    return async (input, init) => {
        // Request objects and streams can be consumed; only retry explicit reusable bodies.
        if (typeof input !== 'string' && !(input instanceof URL)) {
            return fetch(input, init);
        }
        const url = new URL(input);
        const method = init?.method?.toUpperCase() ?? 'GET';
        const headers = new Headers(init?.headers);
        const reusable = !(init?.body instanceof ReadableStream);
        const sessionProbe =
            url.searchParams.has('upload_id') &&
            method === 'PUT' &&
            /^bytes \*\/(?:\*|\d+)$/.test(headers.get('Content-Range') ?? '') &&
            (init?.body === '' || init?.body === undefined);
        // New object generations can reset metageneration, so POST requires a generation guard.
        const generationGuard = url.searchParams.has('ifGenerationMatch');
        const metadataGuard = url.searchParams.has('ifMetagenerationMatch');
        const guarded =
            generationGuard ||
            (metadataGuard &&
                (method === 'PATCH' ||
                    (method === 'DELETE' && !url.pathname.includes('/o/'))));
        const safe =
            url.origin === 'https://storage.googleapis.com' &&
            reusable &&
            (method === 'GET' ||
                method === 'HEAD' ||
                sessionProbe ||
                (guarded &&
                    !url.searchParams.has('upload_id') &&
                    ['POST', 'PATCH', 'DELETE'].includes(method) &&
                    url.searchParams.get('uploadType') !== 'resumable'));
        for (let attempt = 0; ; attempt++) {
            init?.signal?.throwIfAborted();
            let response: Response | undefined;
            try {
                response = await fetch(input, init);
                if (
                    !safe ||
                    attempt >= maxRetries ||
                    ![408, 429, 500, 502, 503, 504].includes(response.status)
                ) {
                    return response;
                }
            } catch (cause) {
                if (
                    !safe ||
                    attempt >= maxRetries ||
                    init?.signal?.aborted ||
                    !(cause instanceof TypeError)
                ) {
                    throw cause;
                }
            }
            const retryAfter = response?.headers.get('Retry-After');
            const retryMs =
                retryAfter === null || retryAfter === undefined
                    ? 0
                    : /^\d+(?:\.\d+)?$/.test(retryAfter)
                      ? Number(retryAfter) * 1000
                      : Math.max(0, Date.parse(retryAfter) - Date.now());
            // Do not retry earlier than the server requests, or wait beyond the configured bound.
            if (response && Number.isFinite(retryMs) && retryMs > maxDelayMs) {
                return response;
            }
            await response?.body?.cancel();
            const delay = Math.min(
                maxDelayMs,
                Math.max(
                    Number.isFinite(retryMs) ? retryMs : 0,
                    initialDelayMs * 2 ** attempt * (0.5 + Math.random() * 0.5)
                )
            );
            await waitForRetry(delay, init?.signal);
        }
    };
}

/** @internal Backoff must stop promptly when the request is aborted. */
function waitForRetry(
    delay: number,
    signal?: AbortSignal | null
): Promise<void> {
    signal?.throwIfAborted();
    return new Promise((resolve, reject) => {
        const abort = () => {
            clearTimeout(timer);
            signal?.removeEventListener('abort', abort);
            reject(signal?.reason);
        };
        const timer = setTimeout(() => {
            signal?.removeEventListener('abort', abort);
            resolve();
        }, delay);
        signal?.addEventListener('abort', abort, { once: true });
    });
}
