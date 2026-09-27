import { afterEach, beforeAll, beforeEach, expect, it, vi } from 'vitest';
import { generateKeyPair, exportPKCS8, exportSPKI } from 'jose';
import { createHash, verify } from 'node:crypto';
import { signStorageUrl } from './storage-signed-url.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
import type { StorageSignedUrlOptions } from './storage-types.js';

let account: ServiceAccount;
let publicKey: string;
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
    vi.setSystemTime(new Date('2026-09-27T12:34:56.789Z'));
});
afterEach(() => vi.useRealTimers());

it.each(['read', 'write'] as const)(
    'creates a verifiable V4 %s signature with encoded paths and headers',
    async (action) => {
        const contentType =
            action === 'write' ? 'text/plain; charset=utf-8' : undefined;
        const signed = await signStorageUrl(
            account,
            'my-bucket',
            "folder/a !'()*?#%é.txt",
            { action, expiresInSeconds: 60, contentType }
        );
        const url = new URL(signed);
        const path = '/my-bucket/folder/a%20%21%27%28%29%2A%3F%23%25%C3%A9.txt';
        expect(url.origin).toBe('https://storage.googleapis.com');
        expect(url.pathname).toBe(path);
        expect(url.hash).toBe('');
        const headers = action === 'read' ? 'host' : 'content-type;host';
        const query =
            'X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=service%40example.com%2F20260927%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20260927T123456Z&X-Goog-Expires=60&X-Goog-SignedHeaders=' +
            (action === 'read' ? 'host' : 'content-type%3Bhost');
        expect(signed.split('?')[1]!.split('&X-Goog-Signature=')[0]).toBe(
            query
        );
        const canonicalRequest = [
            action === 'read' ? 'GET' : 'PUT',
            path,
            query,
            (contentType ? `content-type:${contentType}\n` : '') +
                'host:storage.googleapis.com\n',
            headers,
            'UNSIGNED-PAYLOAD'
        ].join('\n');
        const hash = createHash('sha256')
            .update(canonicalRequest)
            .digest('hex');
        const message = `GOOG4-RSA-SHA256\n20260927T123456Z\n20260927/auto/storage/goog4_request\n${hash}`;
        const signature = url.searchParams.get('X-Goog-Signature')!;
        expect(signature).toMatch(/^[a-f0-9]{512}$/);
        expect(
            verify(
                'RSA-SHA256',
                Buffer.from(message),
                publicKey,
                Buffer.from(signature, 'hex')
            )
        ).toBe(true);
        expect(
            verify(
                'RSA-SHA256',
                Buffer.from(message + 'tampered'),
                publicKey,
                Buffer.from(signature, 'hex')
            )
        ).toBe(false);
    }
);

it.each([undefined, 1, 604800])(
    'supports default and boundary expiration %s',
    async (expiresInSeconds) => {
        const signed = await signStorageUrl(account, 'bucket', 'file', {
            action: 'read',
            expiresInSeconds
        });
        expect(new URL(signed).searchParams.get('X-Goog-Expires')).toBe(
            String(expiresInSeconds ?? 900)
        );
    }
);

it('accepts escaped private keys and keeps literal percent sequences and repeated slashes', async () => {
    const signed = await signStorageUrl(
        { ...account, private_key: account.private_key.replace(/\n/g, '\\n') },
        'bucket',
        'folder//%2E%2E/file',
        { action: 'read' }
    );
    expect(new URL(signed).pathname).toBe('/bucket/folder//%252E%252E/file');
});

it.each([
    null,
    [],
    {},
    { action: 'delete' },
    { action: 'read', expiresInSeconds: 0 },
    { action: 'read', expiresInSeconds: 604801 },
    { action: 'read', expiresInSeconds: 1.5 },
    { action: 'read', expiresInSeconds: NaN },
    { action: 'read', expiresInSeconds: Infinity },
    { action: 'read', expiresInSeconds: '60' },
    { action: 'read', contentType: 'text/plain' },
    { action: 'write', contentType: '' },
    { action: 'write', contentType: 'a\nb' },
    { action: 'write', contentType: 1 }
])('rejects invalid signing options %#', async (options) => {
    await expect(
        signStorageUrl(
            account,
            'bucket',
            'file',
            options as StorageSignedUrlOptions
        )
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
});

it.each(['', 'a/../b', './a', 'a/.', 'a\nb'])(
    'rejects unsafe object names (%s)',
    async (name) => {
        await expect(
            signStorageUrl(account, 'bucket', name, { action: 'read' })
        ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    }
);

it('requires a bucket and signing credentials', async () => {
    await expect(
        signStorageUrl(account, undefined, 'file', { action: 'read' })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    await expect(
        signStorageUrl({} as ServiceAccount, 'bucket', 'file', {
            action: 'read'
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    await expect(
        signStorageUrl(
            { ...account, private_key: 'bad key' },
            'bucket',
            'file',
            { action: 'read' }
        )
    ).rejects.toThrow();
});
