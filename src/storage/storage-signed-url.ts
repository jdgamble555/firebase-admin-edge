import { importPKCS8 } from 'jose';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
import type { StorageSignedUrlOptions } from './storage-types.js';
import { validateStorageOperation } from './storage-endpoints.js';

/** @internal Construct and sign a V4 XML API request using Web Crypto. */
export async function signStorageUrl(
    account: ServiceAccount,
    bucket: string | undefined,
    name: string,
    options: StorageSignedUrlOptions
): Promise<string> {
    validateStorageOperation(bucket, { kind: 'metadata', name });
    if (
        !options ||
        typeof options !== 'object' ||
        Array.isArray(options) ||
        !['read', 'write'].includes(options.action)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Signed URL action must be read or write.'
        });
    }
    const { action, expiresInSeconds = 900, contentType } = options;
    if (
        !Number.isInteger(expiresInSeconds) ||
        expiresInSeconds < 1 ||
        expiresInSeconds > 604800
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'Signed URL lifetime must be an integer between 1 and 604800 seconds.'
        });
    }
    if (
        contentType !== undefined &&
        (action !== 'write' ||
            typeof contentType !== 'string' ||
            !contentType.trim() ||
            /[\r\n]/.test(contentType))
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'contentType requires a write URL and a nonempty HTTP header value.'
        });
    }
    if (
        name.split('/').some((segment) => segment === '.' || segment === '..')
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Signed URL object names cannot contain dot path segments.'
        });
    }
    if (!account?.client_email?.trim() || !account?.private_key?.trim()) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'A service account email and private key are required for URL signing.'
        });
    }

    const timestamp = new Date()
        .toISOString()
        .replace(/[-:]/g, '')
        .replace(/\.\d{3}Z$/, 'Z');
    const scope = `${timestamp.slice(0, 8)}/auto/storage/goog4_request`;
    const signedHeaders =
        contentType === undefined ? 'host' : 'content-type;host';
    const canonicalHeaders =
        (contentType === undefined
            ? ''
            : `content-type:${contentType.trim().replace(/\s+/g, ' ')}\n`) +
        'host:storage.googleapis.com\n';
    const path = `/${encodeStorageComponent(bucket)}/${name.split('/').map(encodeStorageComponent).join('/')}`;
    const query = Object.entries({
        'X-Goog-Algorithm': 'GOOG4-RSA-SHA256',
        'X-Goog-Credential': `${account.client_email}/${scope}`,
        'X-Goog-Date': timestamp,
        'X-Goog-Expires': String(expiresInSeconds),
        'X-Goog-SignedHeaders': signedHeaders
    })
        .map(
            ([key, value]) =>
                `${encodeStorageComponent(key)}=${encodeStorageComponent(value)}`
        )
        .sort()
        .join('&');
    const canonicalRequest = [
        action === 'read' ? 'GET' : 'PUT',
        path,
        query,
        canonicalHeaders,
        signedHeaders,
        'UNSIGNED-PAYLOAD'
    ].join('\n');
    const encoder = new TextEncoder();
    const digest = await crypto.subtle.digest(
        'SHA-256',
        encoder.encode(canonicalRequest)
    );
    const stringToSign = [
        'GOOG4-RSA-SHA256',
        timestamp,
        scope,
        storageHex(digest)
    ].join('\n');
    const key = await importPKCS8(
        account.private_key.replace(/\\n/g, '\n'),
        'RS256'
    );
    const signature = await crypto.subtle.sign(
        'RSASSA-PKCS1-v1_5',
        key,
        encoder.encode(stringToSign)
    );
    return `https://storage.googleapis.com${path}?${query}&X-Goog-Signature=${storageHex(signature)}`;
}

/** @internal RFC 3986 encoding, including characters left unescaped by encodeURIComponent. */
export function encodeStorageComponent(value: string) {
    return encodeURIComponent(value).replace(
        /[!'()*]/g,
        (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`
    );
}

/** @internal V4 uses lowercase hexadecimal for hashes and signatures. */
export function storageHex(bytes: ArrayBuffer) {
    return Array.from(new Uint8Array(bytes), (byte) =>
        byte.toString(16).padStart(2, '0')
    ).join('');
}
