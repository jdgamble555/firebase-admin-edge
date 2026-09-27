import { beforeAll, expect, it } from 'vitest';
import { generateKeyPair, exportPKCS8, exportSPKI } from 'jose';
import { createHash, createHmac, verify } from 'node:crypto';
import { signStorageXmlRequest } from './storage-xml-signing.js';

let credentials: { client_email: string; private_key: string };
let publicKey: string;
const date = new Date('2026-09-27T12:34:56Z');
beforeAll(async () => {
    const pair = await generateKeyPair('RS256', { extractable: true });
    const privateKey = await exportPKCS8(pair.privateKey);
    publicKey = await exportSPKI(pair.publicKey);
    credentials = {
        client_email: 'service@example.com',
        private_key: privateKey
    };
});
it.each(['rsa', 'hmac'])(
    'creates independently verifiable %s Authorization signatures',
    async (kind) => {
        const identity =
            kind === 'rsa'
                ? credentials
                : { accessId: 'test-key', secret: 'test-secret' };
        const request = await signStorageXmlRequest(identity, 'bucket', {
            method: 'PUT',
            name: 'folder/a !é.txt',
            body: 'abc',
            query: { generation: '7', 'a b': 'c d' },
            headers: { 'Content-Type': 'text/plain' },
            date
        });
        expect(request.url).toBe(
            'https://storage.googleapis.com/bucket/folder/a%20%21%C3%A9.txt?a%20b=c%20d&generation=7'
        );
        expect(request.redirect).toBe('manual');
        const payload = await request.text();
        expect(payload).toBe('abc');
        const hash = createHash('sha256').update('abc').digest('hex');
        expect(request.headers.get('x-goog-content-sha256')).toBe(hash);
        const signedHeaders =
            'content-type;host;x-goog-content-sha256;x-goog-date';
        const canonical = [
            'PUT',
            '/bucket/folder/a%20%21%C3%A9.txt',
            'a%20b=c%20d&generation=7',
            `content-type:text/plain\nhost:storage.googleapis.com\nx-goog-content-sha256:${hash}\nx-goog-date:20260927T123456Z\n`,
            signedHeaders,
            hash
        ].join('\n');
        const algorithm =
            kind === 'rsa' ? 'GOOG4-RSA-SHA256' : 'GOOG4-HMAC-SHA256';
        const scope = '20260927/auto/storage/goog4_request';
        const stringToSign = [
            algorithm,
            '20260927T123456Z',
            scope,
            createHash('sha256').update(canonical).digest('hex')
        ].join('\n');
        const authorization = request.headers.get('authorization')!;
        const signature = authorization.split('Signature=')[1]!;
        expect(authorization).toContain(`SignedHeaders=${signedHeaders}`);
        if (kind === 'rsa') {
            expect(
                verify(
                    'RSA-SHA256',
                    Buffer.from(stringToSign),
                    publicKey,
                    Buffer.from(signature, 'hex')
                )
            ).toBe(true);
            return;
        }
        let key: Buffer<ArrayBufferLike> = Buffer.from('GOOG4test-secret');
        for (const value of [
            '20260927',
            'auto',
            'storage',
            'goog4_request',
            stringToSign
        ]) {
            key = createHmac('sha256', key).update(value).digest();
        }
        expect(signature).toBe(key.toString('hex'));
    }
);
it('supports bucket-level reads and resumable initiation', async () => {
    const request = await signStorageXmlRequest(credentials, 'bucket', {
        method: 'GET',
        date
    });
    expect(new URL(request.url).pathname).toBe('/bucket');
    const resumable = await signStorageXmlRequest(credentials, 'bucket', {
        method: 'POST',
        name: 'file',
        headers: { 'x-goog-resumable': 'start' },
        date
    });
    expect(resumable.headers.get('x-goog-content-sha256')).toBe(
        'UNSIGNED-PAYLOAD'
    );
});
it.each([
    { method: 'PATCH' },
    { method: 'GET', body: 'abc' },
    { method: 'PUT', name: '../file' },
    { method: 'GET', date: new Date(NaN) },
    { method: 'GET', headers: { Host: 'evil.example' } },
    { method: 'GET', query: { 'X-Goog-Signature': 'bad' } }
])('rejects invalid XML signing options %j', async (options) => {
    await expect(
        signStorageXmlRequest(credentials, 'bucket', options as never)
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
});
it('rejects missing credentials and buckets', async () => {
    await expect(
        signStorageXmlRequest({ accessId: '', secret: '' }, 'bucket', {
            method: 'GET'
        })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    await expect(
        signStorageXmlRequest(credentials, undefined, { method: 'GET' })
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
});
