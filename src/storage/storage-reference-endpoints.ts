import { FirebaseEdgeError } from '../auth/errors.js';
import {
    storageFetch,
    readStorageObject,
    validateStorageOperation
} from './storage-endpoints.js';

/** @internal Explicit IAM signing reuses the configured OAuth identity and transport. */
export async function storageSignBlob(
    email: string,
    token: string,
    value: string,
    endpoint: string,
    fetch: typeof globalThis.fetch
): Promise<ArrayBuffer> {
    const base = new URL(endpoint);
    if (
        base.protocol !== 'https:' ||
        !(
            base.hostname === 'iamcredentials.googleapis.com' ||
            base.hostname.endsWith('-iamcredentials.googleapis.com')
        ) ||
        base.username ||
        base.password ||
        base.search ||
        base.hash ||
        !/^\/v1\/projects\/[^/]+\/serviceAccounts\/$/.test(base.pathname)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'signingEndpoint must be a Google IAM Credentials service-accounts HTTPS endpoint.'
        });
    }
    const bytes = new TextEncoder().encode(value);
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    const response = await storageFetch(
        `${base.href}${encodeURIComponent(email)}:signBlob`,
        {
            method: 'POST',
            redirect: 'manual',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ payload: btoa(binary) })
        },
        fetch
    );
    const data = await readStorageObject(response);
    if (typeof data.signedBlob !== 'string' || !data.signedBlob) {
        throw new FirebaseEdgeError({
            code: 'storage/internal-error',
            message: 'IAM signing returned no signature.'
        });
    }
    const signature = Uint8Array.from(atob(data.signedBlob), (character) =>
        character.charCodeAt(0)
    );
    return signature.buffer;
}

export interface StorageRequestOptions {
    method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';
    uri?: string;
    qs?: Record<string, string | number | boolean | undefined>;
    json?: unknown;
    headers?: Record<string, string>;
}
export type StorageResource =
    | { kind: 'bucket' }
    | { kind: 'file'; name: string }
    | { kind: 'channel'; id: string };

export type StorageReferenceAction =
    | {
          kind: 'makePrivate';
          strict?: boolean;
          preconditions?: Record<string, string>;
          metadata?: Record<string, unknown>;
      }
    | {
          kind: 'restoreBucket';
          generation: string;
          projection?: 'full' | 'noAcl';
      }
    | {
          kind: 'atomicMove';
          destination: string;
          preconditions?: Record<string, string>;
      }
    | {
          kind: 'watch';
          id: string;
          config: {
              address: string;
              type?: 'web_hook';
              token?: string;
              expiration?: string;
          };
      }
    | { kind: 'stopChannel'; id: string; resourceId: string };

/** @internal Translate named reference operations into REST requests. */
export function storageReferenceActionOptions(
    action: StorageReferenceAction
): StorageRequestOptions {
    if (action.kind === 'makePrivate') {
        return {
            method: 'PATCH',
            qs: {
                ...action.preconditions,
                predefinedAcl: action.strict ? 'private' : 'projectPrivate'
            },
            json: { ...action.metadata, acl: null }
        };
    }
    if (action.kind === 'restoreBucket') {
        if (
            !/^\d+$/.test(action.generation) ||
            (action.projection !== undefined &&
                !['full', 'noAcl'].includes(action.projection))
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Bucket restoration requires a generation.'
            });
        }
        return {
            method: 'POST',
            uri: '/restore',
            qs: {
                generation: action.generation,
                ...(action.projection !== undefined && {
                    projection: action.projection
                })
            }
        };
    }
    if (action.kind === 'atomicMove') {
        validateStorageOperation('validation', {
            kind: 'metadata',
            name: action.destination
        });
        return {
            method: 'POST',
            uri: `/moveTo/o/${encodeURIComponent(action.destination)}`,
            qs: action.preconditions
        };
    }
    if (action.kind === 'watch') {
        if (
            !action.id?.trim() ||
            !action.config?.address?.startsWith('https://')
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Channels require an ID and HTTPS webhook address.'
            });
        }
        return {
            method: 'POST',
            uri: '/o/watch',
            json: {
                ...action.config,
                id: action.id,
                type: action.config.type ?? 'web_hook'
            }
        };
    }
    if (!action.id?.trim() || !action.resourceId?.trim()) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Channel ID and resource ID are required.'
        });
    }
    return {
        method: 'POST',
        uri: '/stop',
        json: { id: action.id, resourceId: action.resourceId }
    };
}

/** @internal Construct the CSEK headers used for reads, writes and key rotation. */
export async function storageEncryptionHeaders(
    key: string | Uint8Array<ArrayBuffer>
): Promise<Record<string, string>> {
    let bytes: Uint8Array<ArrayBuffer>;
    try {
        bytes =
            typeof key === 'string'
                ? Uint8Array.from(atob(key), (character) =>
                      character.charCodeAt(0)
                  )
                : key;
    } catch {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Customer encryption keys must be valid base64 or bytes.'
        });
    }
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Customer encryption keys must contain 32 bytes.'
        });
    }
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return {
        'x-goog-encryption-algorithm': 'AES256',
        'x-goog-encryption-key': btoa(String.fromCharCode(...bytes)),
        'x-goog-encryption-key-sha256': btoa(
            String.fromCharCode(...new Uint8Array(digest))
        )
    };
}

/** @internal Keep the Admin request escape hatch scoped to authenticated Storage resources. */
export async function storageReferenceRequest(
    bucket: string | undefined,
    token: string,
    resource: StorageResource,
    options: StorageRequestOptions,
    fetch: typeof globalThis.fetch
): Promise<Record<string, unknown>> {
    validateStorageOperation(
        bucket,
        resource.kind === 'file'
            ? { kind: 'metadata', name: resource.name }
            : { kind: 'list', options: {} }
    );
    const { method = 'GET', uri = '', qs = {}, json, headers = {} } = options;
    if (
        !['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].includes(method) ||
        (uri &&
            (!uri.startsWith('/') ||
                uri.startsWith('//') ||
                /[?#\\]/.test(uri) ||
                uri.split('/').some((part) => /^(\.|%2e){1,2}$/i.test(part))))
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'Requests must use a supported method and a relative resource path.'
        });
    }
    const path =
        resource.kind === 'channel'
            ? '/channels'
            : `/b/${encodeURIComponent(bucket!)}` +
              (resource.kind === 'file'
                  ? `/o/${encodeURIComponent(resource.name)}`
                  : '');
    const url = new URL(
        `https://storage.googleapis.com/storage/v1${path}${uri}`
    );
    for (const [key, value] of Object.entries(qs)) {
        if (value !== undefined) {
            url.searchParams.set(key, String(value));
        }
    }
    const requestHeaders = new Headers(headers);
    requestHeaders.set('Authorization', `Bearer ${token}`);
    if (json !== undefined) {
        requestHeaders.set('Content-Type', 'application/json');
    }
    const response = await storageFetch(
        url.toString(),
        {
            method,
            headers: requestHeaders,
            ...(json !== undefined && { body: JSON.stringify(json) })
        },
        fetch,
        [],
        resource.kind === 'bucket' ? 'bucket-not-found' : 'object-not-found'
    );
    if (response.status === 204 || method === 'HEAD') {
        await response.body?.cancel();
        return {};
    }
    const text = await response.text();
    if (!text) {
        return {};
    }
    const value: unknown = JSON.parse(text);
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new FirebaseEdgeError({
            code: 'storage/internal-error',
            message: 'Expected a Storage resource response.'
        });
    }
    return value as Record<string, unknown>;
}

/** @internal Firebase token download URLs use the Firebase endpoint, not signed GCS URLs. */
export async function storageDownloadURL(
    bucket: string | undefined,
    name: string,
    token: string,
    fetch: typeof globalThis.fetch
): Promise<string> {
    validateStorageOperation(bucket, { kind: 'metadata', name });
    const url = new URL(
        `https://firebasestorage.googleapis.com/v0/b/${encodeURIComponent(bucket!)}/o/${encodeURIComponent(name)}`
    );
    const response = await storageFetch(
        url.toString(),
        { headers: { Authorization: `Bearer ${token}` } },
        fetch
    );
    const data = await readStorageObject(response);
    if (
        typeof data.downloadTokens !== 'string' ||
        !data.downloadTokens.split(',')[0]?.trim()
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/no-download-token',
            message: 'No Firebase download token is available for this object.'
        });
    }
    url.searchParams.set('alt', 'media');
    url.searchParams.set('token', data.downloadTokens.split(',')[0]!.trim());
    return url.toString();
}

/** @internal Requester-pays billing and encryption stay in the transport layer. */
export function storageScopedFetch(
    fetch: typeof globalThis.fetch,
    scope: {
        userProject?: string;
        encryptionKey?: string | Uint8Array<ArrayBuffer>;
        kmsKeyName?: string;
        timeout?: number;
    }
): typeof globalThis.fetch {
    return async (input, init) => {
        if (
            scope.timeout !== undefined &&
            (!Number.isSafeInteger(scope.timeout) || scope.timeout <= 0)
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'timeout must be a positive number of milliseconds.'
            });
        }
        if (scope.timeout !== undefined) {
            const deadline = AbortSignal.timeout(scope.timeout);
            init = {
                ...init,
                signal: init?.signal
                    ? AbortSignal.any([init.signal, deadline])
                    : deadline
            };
        }
        if (typeof input !== 'string' && !(input instanceof URL)) {
            return fetch(input, init);
        }
        const url = new URL(input);
        if (url.origin !== 'https://storage.googleapis.com') {
            return fetch(input, init);
        }
        if (scope.userProject && !url.searchParams.has('userProject')) {
            url.searchParams.set('userProject', scope.userProject);
        }
        if (
            scope.kmsKeyName &&
            url.pathname.startsWith('/upload/') &&
            !url.searchParams.has('kmsKeyName')
        ) {
            url.searchParams.set('kmsKeyName', scope.kmsKeyName);
        }
        const headers = new Headers(init?.headers);
        if (scope.encryptionKey !== undefined) {
            const encryption = await storageEncryptionHeaders(
                scope.encryptionKey
            );
            const prefixes = url.pathname.includes('/rewriteTo/')
                ? ['x-goog-encryption-', 'x-goog-copy-source-encryption-']
                : ['x-goog-encryption-'];
            for (const prefix of prefixes) {
                if (!headers.has(`${prefix}key`)) {
                    headers.set(`${prefix}algorithm`, 'AES256');
                    headers.set(
                        `${prefix}key`,
                        encryption['x-goog-encryption-key']!
                    );
                    headers.set(
                        `${prefix}key-sha256`,
                        encryption['x-goog-encryption-key-sha256']!
                    );
                }
            }
        }
        return fetch(url.toString(), { ...init, headers });
    };
}

/** @internal Probe anonymous access without sending service-account credentials. */
export async function storageIsPublic(
    bucket: string | undefined,
    name: string,
    fetch: typeof globalThis.fetch
): Promise<boolean> {
    validateStorageOperation(bucket, { kind: 'metadata', name });
    const url = `https://storage.googleapis.com/${encodeURIComponent(bucket!)}/${encodeURIComponent(name)}`;
    const response = await storageFetch(
        url,
        { method: 'HEAD', redirect: 'manual' },
        fetch,
        [403]
    );
    await response.body?.cancel();
    return response.status !== 403;
}
