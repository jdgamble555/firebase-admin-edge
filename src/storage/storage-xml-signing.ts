import { importPKCS8 } from 'jose';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
import type { StorageUploadData } from './storage-types.js';
import { storageUploadBlob } from './storage-checksum.js';
import { encodeStorageComponent, storageHex } from './storage-signed-url.js';
import { validateStorageOperation } from './storage-endpoints.js';

export interface StorageXmlRequestOptions {
    method: 'GET' | 'HEAD' | 'PUT' | 'POST' | 'DELETE';
    /** Omit for bucket-level operations. */
    name?: string;
    headers?: Record<string, string>;
    query?: Record<string, string>;
    body?: StorageUploadData;
    date?: Date;
}

/** Sign an XML API request with RSA service-account or HMAC credentials, without sending it. */
export async function signStorageXmlRequest(
    credentials:
        | Pick<ServiceAccount, 'client_email' | 'private_key'>
        | { accessId: string; secret: string },
    bucket: string | undefined,
    options: StorageXmlRequestOptions
): Promise<Request> {
    validateStorageOperation(bucket, { kind: 'list', options: {} });
    if (
        !options ||
        !['GET', 'HEAD', 'PUT', 'POST', 'DELETE'].includes(options.method)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Provide a supported XML request method.'
        });
    }
    if (options.name !== undefined) {
        validateStorageOperation(bucket, {
            kind: 'metadata',
            name: options.name
        });
        if (
            options.name
                .split('/')
                .some((part) => part === '.' || part === '..')
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Signed paths cannot contain dot segments.'
            });
        }
    }
    if (
        options.body !== undefined &&
        ['GET', 'HEAD'].includes(options.method)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'GET and HEAD requests cannot contain a body.'
        });
    }
    const hmac = credentials && 'accessId' in credentials;
    const identity = hmac ? credentials.accessId : credentials?.client_email;
    const secret = hmac ? credentials.secret : credentials?.private_key;
    if (
        typeof identity !== 'string' ||
        !identity.trim() ||
        /[\r\n/,]/.test(identity) ||
        typeof secret !== 'string' ||
        !secret.trim()
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Valid signing credentials are required.'
        });
    }
    const date = options.date ?? new Date();
    if (!(date instanceof Date) || !Number.isFinite(date.getTime())) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Invalid signing date.'
        });
    }
    const headers = new Headers(options.headers);
    for (const reserved of [
        'authorization',
        'host',
        'x-goog-date',
        'x-goog-content-sha256',
        'content-length'
    ]) {
        if (headers.has(reserved)) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: `${reserved} is managed by the signer.`
            });
        }
    }
    const encoder = new TextEncoder();
    const body =
        options.body === undefined
            ? undefined
            : storageUploadBlob(options.body);
    const bytes = body ? await body.arrayBuffer() : new ArrayBuffer(0);
    const hash = await crypto.subtle.digest('SHA-256', bytes);
    const payloadHash =
        headers.get('x-goog-resumable') === 'start'
            ? 'UNSIGNED-PAYLOAD'
            : storageHex(hash);
    const timestamp = date
        .toISOString()
        .replace(/[-:]/g, '')
        .replace(/\.\d{3}Z$/, 'Z');
    const scope = `${timestamp.slice(0, 8)}/auto/storage/goog4_request`;
    const algorithm = hmac ? 'GOOG4-HMAC-SHA256' : 'GOOG4-RSA-SHA256';
    headers.set('x-goog-date', timestamp);
    headers.set('x-goog-content-sha256', payloadHash);
    if (body && !headers.has('content-type')) {
        headers.set('content-type', body.type || 'application/octet-stream');
    }
    const canonicalHeaders = new Headers(headers);
    canonicalHeaders.set('host', 'storage.googleapis.com');
    const entries = Array.from(canonicalHeaders.entries()).sort(([a], [b]) =>
        a < b ? -1 : a > b ? 1 : 0
    );
    const signedHeaders = entries.map(([name]) => name).join(';');
    const canonical = entries
        .map(
            ([name, value]) => `${name}:${value.trim().replace(/\s+/g, ' ')}\n`
        )
        .join('');
    const query = Object.entries(options.query ?? {})
        .map(([key, value]) => {
            if (typeof value !== 'string' || /^(x-goog-|x-amz-)/i.test(key)) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'Invalid or reserved XML query parameter.'
                });
            }
            return `${encodeStorageComponent(key)}=${encodeStorageComponent(value)}`;
        })
        .sort()
        .join('&');
    const path = `/${encodeStorageComponent(bucket!)}${options.name === undefined ? '' : `/${options.name.split('/').map(encodeStorageComponent).join('/')}`}`;
    const canonicalRequest = [
        options.method,
        path,
        query,
        canonical,
        signedHeaders,
        payloadHash
    ].join('\n');
    const digest = await crypto.subtle.digest(
        'SHA-256',
        encoder.encode(canonicalRequest)
    );
    const stringToSign = [algorithm, timestamp, scope, storageHex(digest)].join(
        '\n'
    );
    let signature: ArrayBuffer;
    if (hmac) {
        let signingKey: ArrayBuffer = encoder.encode(`GOOG4${secret}`).buffer;
        for (const value of [
            timestamp.slice(0, 8),
            'auto',
            'storage',
            'goog4_request',
            stringToSign
        ]) {
            const key = await crypto.subtle.importKey(
                'raw',
                signingKey,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            signingKey = await crypto.subtle.sign(
                'HMAC',
                key,
                encoder.encode(value)
            );
        }
        signature = signingKey;
    } else {
        const key = await importPKCS8(secret.replace(/\\n/g, '\n'), 'RS256');
        signature = await crypto.subtle.sign(
            'RSASSA-PKCS1-v1_5',
            key,
            encoder.encode(stringToSign)
        );
    }
    headers.set(
        'Authorization',
        `${algorithm} Credential=${identity}/${scope}, SignedHeaders=${signedHeaders}, Signature=${storageHex(signature)}`
    );
    return new Request(
        `https://storage.googleapis.com${path}${query ? `?${query}` : ''}`,
        { method: options.method, headers, body, redirect: 'manual' }
    );
}
