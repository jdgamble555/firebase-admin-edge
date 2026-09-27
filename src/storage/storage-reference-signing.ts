import { importPKCS8 } from 'jose';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
import type { GetSignedUrlOptions } from './storage-reference-types.js';
import { encodeStorageComponent, storageHex } from './storage-signed-url.js';
import { validateStorageOperation } from './storage-endpoints.js';
export type StorageRemoteSigner = (
    value: string,
    endpoint: string
) => Promise<ArrayBuffer>;

/** @internal Centralize web-native service-account signing for Admin URLs and POST policies. */
async function signReferenceValue(
    account: ServiceAccount,
    value: string,
    endpoint?: string,
    remote?: StorageRemoteSigner
): Promise<ArrayBuffer> {
    if (endpoint !== undefined) {
        if (!remote) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'A remote signing transport is required.'
            });
        }
        return remote(value, endpoint);
    }
    if (!account.client_email?.trim() || !account.private_key?.trim()) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Service account signing credentials are required.'
        });
    }
    const key = await importPKCS8(
        account.private_key.replace(/\\n/g, '\n'),
        'RS256'
    );
    return crypto.subtle.sign(
        'RSASSA-PKCS1-v1_5',
        key,
        new TextEncoder().encode(value)
    );
}

/** @internal URL expiration in Admin is absolute, rather than a relative duration. */
function referenceExpiration(expires: string | number | Date): number {
    const value = new Date(expires).getTime();
    if (!Number.isFinite(value) || value <= Date.now()) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Expiration must be a valid future date.'
        });
    }
    return Math.floor(value / 1000);
}

/** @internal Support Admin V2/V4 signed URL options over the same web signing primitives. */
export async function signStorageReferenceUrl(
    account: ServiceAccount,
    bucket: string | undefined,
    name: string | undefined,
    options: GetSignedUrlOptions,
    remote?: StorageRemoteSigner
): Promise<string> {
    validateStorageOperation(
        bucket,
        name === undefined
            ? { kind: 'list', options: {} }
            : { kind: 'metadata', name }
    );
    if (
        !options ||
        !['read', 'write', 'delete', 'resumable', 'list'].includes(
            options.action
        ) ||
        (options.action === 'list' && name !== undefined) ||
        !['v2', 'v4'].includes(options.version ?? 'v2') ||
        name?.split('/').some((part) => part === '.' || part === '..')
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Invalid signed URL options or path.'
        });
    }
    const expires = referenceExpiration(options.expires);
    const method = {
        read: 'GET',
        list: 'GET',
        write: 'PUT',
        delete: 'DELETE',
        resumable: 'POST'
    }[options.action];
    const host = new URL(
        options.cname ??
            options.host ??
            (options.virtualHostedStyle
                ? `https://${bucket}.storage.googleapis.com`
                : 'https://storage.googleapis.com')
    );
    if (
        host.protocol !== 'https:' ||
        host.username ||
        host.password ||
        host.search ||
        host.hash ||
        host.pathname !== '/'
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'A signing hostname must be an HTTPS origin.'
        });
    }
    const objectPath = name?.split('/').map(encodeStorageComponent).join('/');
    const resource = `/${encodeStorageComponent(bucket!)}${objectPath === undefined ? '' : `/${objectPath}`}`;
    const path =
        options.cname || options.virtualHostedStyle
            ? `/${objectPath ?? ''}`
            : resource;
    const headers = new Headers();
    for (const [key, value] of Object.entries(options.extensionHeaders ?? {})) {
        if (value !== undefined) {
            headers.set(
                key,
                Array.isArray(value) ? value.join(',') : String(value)
            );
        }
    }
    if (options.action === 'resumable') {
        headers.set('x-goog-resumable', 'start');
    }
    const query: Record<string, string> = Object.fromEntries(
        Object.entries(options.queryParams ?? {}).map(([key, value]) => [
            key,
            String(value)
        ])
    );
    if (options.responseType) {
        query['response-content-type'] = options.responseType;
    }
    if (options.responseDisposition) {
        query['response-content-disposition'] = options.responseDisposition;
    }
    if (options.promptSaveAs) {
        query['response-content-disposition'] =
            `attachment; filename="${options.promptSaveAs.replace(/["\r\n]/g, '')}"`;
    }
    if (
        Object.keys(query).some((key) =>
            /^(x-goog-|googleaccessid$|signature$|expires$)/i.test(key)
        )
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'Authentication query parameters are managed by the signer.'
        });
    }
    if ((options.version ?? 'v2') === 'v2') {
        const canonicalHeaders = Array.from(headers)
            .sort(([a], [b]) => (a < b ? -1 : 1))
            .map(
                ([key, value]) =>
                    `${key}:${value.trim().replace(/\s+/g, ' ')}\n`
            )
            .join('');
        const signature = await signReferenceValue(
            account,
            [
                method,
                options.contentMd5 ?? '',
                options.contentType ?? '',
                String(expires),
                canonicalHeaders + resource
            ].join('\n'),
            options.signingEndpoint,
            remote
        );
        Object.assign(query, {
            GoogleAccessId: account.client_email,
            Expires: String(expires),
            Signature: btoa(String.fromCharCode(...new Uint8Array(signature)))
        });
    } else {
        const accessible = Math.floor(
            new Date(options.accessibleAt ?? Date.now()).getTime() / 1000
        );
        const duration = expires - accessible;
        if (!Number.isFinite(accessible) || duration < 1 || duration > 604800) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'V4 URLs require a lifetime of 1 to 604800 seconds.'
            });
        }
        const timestamp = new Date(accessible * 1000)
            .toISOString()
            .replace(/[-:]/g, '')
            .replace(/\.\d{3}Z$/, 'Z');
        const scope = `${timestamp.slice(0, 8)}/auto/storage/goog4_request`;
        headers.set('host', host.host);
        if (options.contentType) {
            headers.set('content-type', options.contentType);
        }
        if (options.contentMd5) {
            headers.set('content-md5', options.contentMd5);
        }
        const entries = Array.from(headers).sort(([a], [b]) =>
            a < b ? -1 : 1
        );
        const signedHeaders = entries.map(([key]) => key).join(';');
        const canonicalHeaders = entries
            .map(
                ([key, value]) =>
                    `${key}:${value.trim().replace(/\s+/g, ' ')}\n`
            )
            .join('');
        Object.assign(query, {
            'X-Goog-Algorithm': 'GOOG4-RSA-SHA256',
            'X-Goog-Credential': `${account.client_email}/${scope}`,
            'X-Goog-Date': timestamp,
            'X-Goog-Expires': String(duration),
            'X-Goog-SignedHeaders': signedHeaders
        });
        const canonicalQuery = Object.entries(query)
            .map(
                ([key, value]) =>
                    `${encodeStorageComponent(key)}=${encodeStorageComponent(value)}`
            )
            .sort()
            .join('&');
        const canonicalRequest = [
            method,
            path,
            canonicalQuery,
            canonicalHeaders,
            signedHeaders,
            headers.get('x-goog-content-sha256') ?? 'UNSIGNED-PAYLOAD'
        ].join('\n');
        const digest = await crypto.subtle.digest(
            'SHA-256',
            new TextEncoder().encode(canonicalRequest)
        );
        const signature = await signReferenceValue(
            account,
            ['GOOG4-RSA-SHA256', timestamp, scope, storageHex(digest)].join(
                '\n'
            ),
            options.signingEndpoint,
            remote
        );
        query['X-Goog-Signature'] = storageHex(signature);
    }
    const encodedQuery = Object.entries(query)
        .map(
            ([key, value]) =>
                `${encodeStorageComponent(key)}=${encodeStorageComponent(value)}`
        )
        .sort()
        .join('&');
    return `${host.origin}${path}?${encodedQuery}`;
}

export interface SignedPostPolicyOptions {
    signingEndpoint?: string;
    expires: string | number | Date;
    conditions?: Array<
        Record<string, string> | [string, ...Array<string | number>]
    >;
    fields?: Record<string, string>;
    virtualHostedStyle?: boolean;
    bucketBoundHostname?: string;
    equals?: string[] | string[][];
    startsWith?: string[] | string[][];
    acl?: string;
    successRedirect?: string;
    successStatus?: string;
    contentLengthRange?: { min?: number; max?: number };
}

/** @internal Form-upload policies are signed locally and do not send network requests. */
export async function signStoragePostPolicy(
    account: ServiceAccount,
    bucket: string | undefined,
    name: string,
    version: 'v2' | 'v4',
    options: SignedPostPolicyOptions,
    remote?: StorageRemoteSigner
) {
    validateStorageOperation(bucket, { kind: 'metadata', name });
    const expires = referenceExpiration(options.expires);
    const fields: Record<string, string> = { ...options.fields, key: name };
    const conditions: unknown[] = [
        ...(options.conditions ?? []),
        { bucket },
        name.includes('${filename}')
            ? ['starts-with', '$key', name.split('${filename}')[0]!]
            : { key: name }
    ];
    if (options.acl) {
        fields.acl = options.acl;
    }
    if (options.successRedirect) {
        fields.success_action_redirect = options.successRedirect;
    }
    if (options.successStatus) {
        fields.success_action_status = options.successStatus;
    }
    for (const [operator, entries] of [
        ['eq', options.equals],
        ['starts-with', options.startsWith]
    ] as const) {
        if (!entries?.length) {
            continue;
        }
        const pairs = (
            typeof entries[0] === 'string' ? [entries] : entries
        ) as string[][];
        for (const pair of pairs) {
            if (
                pair.length !== 2 ||
                !pair.every((value) => typeof value === 'string')
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: 'Policy comparisons require field/value pairs.'
                });
            }
            conditions.push([operator, ...pair]);
        }
    }
    if (options.contentLengthRange) {
        const { min = 0, max } = options.contentLengthRange;
        if (
            !Number.isSafeInteger(min) ||
            !Number.isSafeInteger(max) ||
            min < 0 ||
            max! < min
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Invalid form upload length range.'
            });
        }
        conditions.push(['content-length-range', min, max]);
    }
    if (version === 'v4') {
        if (expires - Math.floor(Date.now() / 1000) > 604800) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'V4 policy expiration cannot exceed seven days.'
            });
        }
        const timestamp = new Date()
            .toISOString()
            .replace(/[-:]/g, '')
            .replace(/\.\d{3}Z$/, 'Z');
        fields['x-goog-algorithm'] = 'GOOG4-RSA-SHA256';
        fields['x-goog-credential'] =
            `${account.client_email}/${timestamp.slice(0, 8)}/auto/storage/goog4_request`;
        fields['x-goog-date'] = timestamp;
    }
    for (const [key, value] of Object.entries(fields)) {
        if (key !== 'key') {
            conditions.push({ [key]: value });
        }
    }
    const string = JSON.stringify({
        expiration: new Date(expires * 1000).toISOString(),
        conditions
    });
    const base64 = btoa(
        String.fromCharCode(...new TextEncoder().encode(string))
    );
    const signature = await signReferenceValue(
        account,
        base64,
        options.signingEndpoint,
        remote
    );
    if (version === 'v2') {
        return {
            string,
            base64,
            signature: btoa(String.fromCharCode(...new Uint8Array(signature)))
        };
    }
    const origin = options.bucketBoundHostname
        ? new URL(options.bucketBoundHostname)
        : new URL(
              options.virtualHostedStyle
                  ? `https://${bucket}.storage.googleapis.com`
                  : 'https://storage.googleapis.com'
          );
    if (origin.protocol !== 'https:' || origin.username || origin.password) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Form upload host must use HTTPS.'
        });
    }
    return {
        url: `${origin.origin}/${options.bucketBoundHostname || options.virtualHostedStyle ? '' : encodeStorageComponent(bucket!)}`,
        fields: {
            ...fields,
            policy: base64,
            'x-goog-signature': storageHex(signature)
        }
    };
}
