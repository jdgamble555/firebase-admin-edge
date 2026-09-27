import { beforeAll, afterEach, beforeEach, expect, it, vi } from 'vitest';
import { generateKeyPair, exportPKCS8, exportSPKI } from 'jose';
import { createHash, verify } from 'node:crypto';
import {
    signStorageReferenceUrl,
    signStoragePostPolicy
} from './storage-reference-signing.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
import type { GetSignedUrlOptions } from './storage-reference-types.js';

let account: ServiceAccount;
let publicKey: string;

it.each(['v2', 'v4'] as const)(
    'signs bucket list URLs using %s and rejects list actions on files',
    async (version) => {
        const options = {
            action: 'list' as const,
            version,
            expires: Date.now() + 60000,
            queryParams: { prefix: 'photos/' }
        };
        const signed = await signStorageReferenceUrl(
            account,
            'bucket',
            undefined,
            options
        );
        expect(new URL(signed).pathname).toBe('/bucket');
        expect(new URL(signed).searchParams.get('prefix')).toBe('photos/');
        await expect(
            signStorageReferenceUrl(account, 'bucket', 'file', options)
        ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    }
);
beforeAll(async () => {
    const keys = await generateKeyPair('RS256', { extractable: true });
    const privateKey = await exportPKCS8(keys.privateKey);
    publicKey = await exportSPKI(keys.publicKey);
    account = {
        client_email: 'service@example.com',
        private_key: privateKey
    } as ServiceAccount;
});
beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-09-27T12:00:00Z'));
});
afterEach(() => vi.useRealTimers());

it('supports remote signing, scalar query/header values and filename form placeholders', async () => {
    const remote = vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3]).buffer);
    const endpoint =
        'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/';
    const signed = await signStorageReferenceUrl(
        account,
        'bucket',
        'file',
        {
            action: 'read',
            version: 'v4',
            expires: Date.now() + 60000,
            host: 'https://storage.example.com',
            extensionHeaders: {
                'x-goog-meta-tags': ['a', 'b'],
                'x-goog-meta-count': 2
            },
            queryParams: { generation: 12 },
            signingEndpoint: endpoint
        },
        remote
    );
    expect(new URL(signed).origin).toBe('https://storage.example.com');
    expect(new URL(signed).searchParams.get('generation')).toBe('12');
    expect(new URL(signed).searchParams.get('X-Goog-Signature')).toBe('010203');
    expect(remote).toHaveBeenCalledWith(expect.any(String), endpoint);
    const policy = await signStoragePostPolicy(
        account,
        'bucket',
        'uploads/${filename}',
        'v4',
        { expires: Date.now() + 60000, signingEndpoint: endpoint },
        remote
    );
    const decoded = JSON.parse(atob(policy.fields!.policy));
    expect(decoded.conditions).toContainEqual([
        'starts-with',
        '$key',
        'uploads/'
    ]);
    await expect(
        signStorageReferenceUrl(account, 'bucket', 'file', {
            action: 'read',
            expires: Date.now() + 60000,
            signingEndpoint: endpoint
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
});

it.each(['read', 'write', 'delete', 'resumable'] as const)(
    'produces independently verifiable V2 signatures for %s',
    async (action) => {
        const signed = await signStorageReferenceUrl(
            account,
            'bucket',
            'dir/a b',
            { action, expires: Date.now() + 60000, contentType: 'text/plain' }
        );
        const url = new URL(signed);
        const message = [
            { read: 'GET', write: 'PUT', delete: 'DELETE', resumable: 'POST' }[
                action
            ],
            '',
            'text/plain',
            url.searchParams.get('Expires'),
            (action === 'resumable' ? 'x-goog-resumable:start\n' : '') +
                '/bucket/dir/a%20b'
        ].join('\n');
        expect(
            verify(
                'RSA-SHA256',
                Buffer.from(message),
                publicKey,
                Buffer.from(url.searchParams.get('Signature')!, 'base64')
            )
        ).toBe(true);
        expect(url.searchParams.get('GoogleAccessId')).toBe(
            account.client_email
        );
    }
);
it('signs V4 query parameters and canonical headers including custom hosts', async () => {
    const signed = await signStorageReferenceUrl(account, 'bucket', 'a b', {
        action: 'read',
        version: 'v4',
        expires: Date.now() + 60000,
        virtualHostedStyle: true,
        extensionHeaders: { 'x-goog-meta-test': ' value ' },
        queryParams: { generation: '42' },
        responseType: 'text/plain',
        promptSaveAs: 'name.txt'
    });
    const url = new URL(signed);
    const signature = url.searchParams.get('X-Goog-Signature')!;
    const canonicalQuery = signed
        .split('?')[1]!
        .split('&')
        .filter((part) => !part.startsWith('X-Goog-Signature='))
        .join('&');
    const request = [
        'GET',
        '/a%20b',
        canonicalQuery,
        'host:bucket.storage.googleapis.com\nx-goog-meta-test:value\n',
        'host;x-goog-meta-test',
        'UNSIGNED-PAYLOAD'
    ].join('\n');
    const hash = createHash('sha256').update(request).digest('hex');
    const message = `GOOG4-RSA-SHA256\n20260927T120000Z\n20260927/auto/storage/goog4_request\n${hash}`;
    expect(
        verify(
            'RSA-SHA256',
            Buffer.from(message),
            publicKey,
            Buffer.from(signature, 'hex')
        )
    ).toBe(true);
    expect(url.searchParams.get('generation')).toBe('42');
    expect(url.searchParams.get('response-content-disposition')).toBe(
        'attachment; filename="name.txt"'
    );
});
it('supports bucket signatures and HTTPS custom origins', async () => {
    const signed = await signStorageReferenceUrl(account, 'bucket', undefined, {
        action: 'read',
        expires: Date.now() + 60000,
        cname: 'https://cdn.example.com'
    });
    expect(new URL(signed).pathname).toBe('/');
});
it.each([
    { expires: 'invalid' },
    { expires: 1 },
    { action: 'bad' },
    { version: 'bad' },
    { version: 'v4', expires: 9999999999999 },
    { cname: 'http://example.com' },
    { cname: 'https://example.com/path' },
    { queryParams: { 'X-Goog-Signature': 'bad' } }
])('rejects invalid signing options %j', async (invalid) => {
    const options = {
        action: 'read',
        expires: Date.now() + 60000,
        ...invalid
    } as GetSignedUrlOptions;
    await expect(
        signStorageReferenceUrl(account, 'bucket', 'file', options)
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
});
it('rejects missing credentials and dot segments', async () => {
    await expect(
        signStorageReferenceUrl({} as ServiceAccount, 'bucket', 'file', {
            action: 'read',
            expires: Date.now() + 60000
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    await expect(
        signStorageReferenceUrl(account, 'bucket', 'dir/../file', {
            action: 'read',
            expires: Date.now() + 60000
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
});
it.each(['v2', 'v4'] as const)(
    'creates a verifiable %s form policy with constraints',
    async (version) => {
        const data = await signStoragePostPolicy(
            account,
            'bucket',
            'file',
            version,
            {
                expires: Date.now() + 60000,
                fields: { 'Content-Type': 'text/plain' },
                contentLengthRange: { min: 1, max: 1024 },
                startsWith: ['$key', 'file'],
                equals: [['$success_action_status', '201']],
                successStatus: '201'
            }
        );
        const base64 = data.base64 ?? data.fields!.policy;
        const signature = data.signature ?? data.fields!['x-goog-signature'];
        const policy = JSON.parse(Buffer.from(base64, 'base64').toString());
        expect(policy.conditions).toContainEqual([
            'content-length-range',
            1,
            1024
        ]);
        expect(policy.conditions).toContainEqual({ bucket: 'bucket' });
        expect(policy.conditions).toContainEqual({ key: 'file' });
        expect(policy.conditions).toContainEqual([
            'starts-with',
            '$key',
            'file'
        ]);
        expect(
            verify(
                'RSA-SHA256',
                Buffer.from(base64),
                publicKey,
                Buffer.from(signature, version === 'v2' ? 'base64' : 'hex')
            )
        ).toBe(true);
    }
);
it('rejects invalid form constraints and expiration', async () => {
    await expect(
        signStoragePostPolicy(account, 'bucket', 'file', 'v4', {
            expires: Date.now() + 60000,
            contentLengthRange: { min: 10, max: 1 }
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    await expect(
        signStoragePostPolicy(account, 'bucket', 'file', 'v2', {
            expires: Date.now() + 60000,
            equals: ['one']
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    await expect(
        signStoragePostPolicy(account, 'bucket', 'file', 'v4', {
            expires: Date.now() + 604801000
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
});
