import { expect, it, vi } from 'vitest';
import {
    storageReferenceActionOptions,
    storageReferenceRequest,
    storageDownloadURL,
    storageEncryptionHeaders,
    storageScopedFetch,
    storageIsPublic,
    storageSignBlob
} from './storage-reference-endpoints.js';

it('forwards bucket restore projections and rejects invalid ones', () => {
    expect(
        storageReferenceActionOptions({
            kind: 'restoreBucket',
            generation: '12',
            projection: 'full'
        })
    ).toEqual({
        method: 'POST',
        uri: '/restore',
        qs: { generation: '12', projection: 'full' }
    });
    expect(() =>
        storageReferenceActionOptions({
            kind: 'restoreBucket',
            generation: '12',
            projection: 'bad' as never
        })
    ).toThrow();
});

it('uses authenticated IAM signBlob only at trusted service-account endpoints', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValue(Response.json({ signedBlob: 'AQID' }));
    const endpoint =
        'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/';
    const signature = await storageSignBlob(
        'service@example.com',
        'token',
        'abc',
        endpoint,
        fetch
    );
    expect(new Uint8Array(signature)).toEqual(new Uint8Array([1, 2, 3]));
    expect(fetch).toHaveBeenCalledWith(
        `${endpoint}service%40example.com:signBlob`,
        expect.objectContaining({
            method: 'POST',
            redirect: 'manual',
            body: '{"payload":"YWJj"}',
            headers: {
                Authorization: 'Bearer token',
                'Content-Type': 'application/json'
            }
        })
    );
    fetch.mockClear();
    await expect(
        storageSignBlob(
            'service@example.com',
            'token',
            'abc',
            'https://evil.example/v1/projects/-/serviceAccounts/',
            fetch
        )
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    expect(fetch).not.toHaveBeenCalled();
    fetch.mockResolvedValue(Response.json({}));
    await expect(
        storageSignBlob('service@example.com', 'token', 'abc', endpoint, fetch)
    ).rejects.toMatchObject({ code: 'storage/internal-error' });
});

it('keeps explicit billing overrides and applies fetch deadlines without changing the base transport', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response());
    const scoped = storageScopedFetch(fetch, {
        userProject: 'default',
        timeout: 1000
    });
    await scoped(
        'https://storage.googleapis.com/storage/v1/b/bucket?userProject=override'
    );
    expect(
        new URL(fetch.mock.calls[0]?.[0]).searchParams.get('userProject')
    ).toBe('override');
    expect(fetch.mock.calls[0]?.[1].signal).toBeInstanceOf(AbortSignal);
    const invalid = storageScopedFetch(fetch, { timeout: -1 });
    await expect(
        invalid('https://storage.googleapis.com/storage/v1/b/bucket')
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
});

it('scopes requests, replaces authorization case-insensitively and parses responses', async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json({ name: 'a/b' }));
    const data = await storageReferenceRequest(
        'bucket',
        'token',
        { kind: 'file', name: 'a/b' },
        {
            method: 'PATCH',
            qs: { generation: '12', ignored: undefined },
            json: { contentType: 'text/plain' },
            headers: { authorization: 'wrong' }
        },
        fetch
    );
    expect(data).toEqual({ name: 'a/b' });
    const [input, init] = fetch.mock.calls[0]!;
    const url = new URL(input);
    expect(url.pathname).toBe('/storage/v1/b/bucket/o/a%2Fb');
    expect(url.search).toBe('?generation=12');
    expect(new Headers(init.headers).get('authorization')).toBe('Bearer token');
    expect(JSON.parse(init.body)).toEqual({ contentType: 'text/plain' });
});
it.each([
    'https://evil.example',
    '//evil.example',
    '/../b/other',
    '/%2e%2e/b/other',
    '/x?q=1',
    '/x#fragment'
])('rejects escaping URI %s before fetch', async (uri) => {
    const fetch = vi.fn();
    await expect(
        storageReferenceRequest(
            'bucket',
            'token',
            { kind: 'bucket' },
            { uri },
            fetch
        )
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    expect(fetch).not.toHaveBeenCalled();
});
it('handles empty responses, malformed JSON resources, and mapped HTTP errors', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(new Response(null, { status: 204 }))
        .mockResolvedValueOnce(Response.json([]))
        .mockResolvedValueOnce(
            Response.json({ error: { message: 'Denied' } }, { status: 403 })
        );
    await expect(
        storageReferenceRequest(
            'bucket',
            'token',
            { kind: 'bucket' },
            { method: 'DELETE' },
            fetch
        )
    ).resolves.toEqual({});
    await expect(
        storageReferenceRequest(
            'bucket',
            'token',
            { kind: 'bucket' },
            {},
            fetch
        )
    ).rejects.toMatchObject({ code: 'storage/internal-error' });
    await expect(
        storageReferenceRequest(
            'bucket',
            'token',
            { kind: 'bucket' },
            {},
            fetch
        )
    ).rejects.toMatchObject({ code: 'storage/permission-denied' });
});
it('constructs advanced operation routes and rejects missing identifiers', () => {
    expect(
        storageReferenceActionOptions({
            kind: 'atomicMove',
            destination: 'dir/new',
            preconditions: { ifGenerationMatch: '0' }
        })
    ).toMatchObject({ method: 'POST', uri: '/moveTo/o/dir%2Fnew' });
    expect(
        storageReferenceActionOptions({
            kind: 'restoreBucket',
            generation: '12'
        })
    ).toEqual({ method: 'POST', uri: '/restore', qs: { generation: '12' } });
    expect(
        storageReferenceActionOptions({ kind: 'makePrivate', strict: true })
    ).toMatchObject({
        method: 'PATCH',
        qs: { predefinedAcl: 'private' },
        json: { acl: null }
    });
    expect(
        storageReferenceActionOptions({ kind: 'makePrivate' })
    ).toMatchObject({ qs: { predefinedAcl: 'projectPrivate' } });
    expect(
        storageReferenceActionOptions({
            kind: 'watch',
            id: 'id',
            config: { address: 'https://example.com/hooks' }
        })
    ).toMatchObject({ uri: '/o/watch', json: { type: 'web_hook', id: 'id' } });
    expect(
        storageReferenceActionOptions({
            kind: 'stopChannel',
            id: 'id',
            resourceId: 'resource'
        })
    ).toMatchObject({
        uri: '/stop',
        json: { id: 'id', resourceId: 'resource' }
    });
    expect(() =>
        storageReferenceActionOptions({
            kind: 'restoreBucket',
            generation: '-1'
        })
    ).toThrow();
    expect(() =>
        storageReferenceActionOptions({
            kind: 'watch',
            id: '',
            config: { address: 'http://example.com' }
        })
    ).toThrow();
    expect(() =>
        storageReferenceActionOptions({
            kind: 'stopChannel',
            id: '',
            resourceId: ''
        })
    ).toThrow();
});
it('retrieves Firebase token URLs without creating tokens or exposing OAuth tokens', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(
            Response.json({ downloadTokens: 'first,second' })
        )
        .mockResolvedValueOnce(Response.json({}));
    const url = await storageDownloadURL(
        'bucket',
        'folder/a b',
        'oauth',
        fetch
    );
    expect(url).toBe(
        'https://firebasestorage.googleapis.com/v0/b/bucket/o/folder%2Fa%20b?alt=media&token=first'
    );
    await expect(
        storageDownloadURL('bucket', 'file', 'oauth', fetch)
    ).rejects.toMatchObject({ code: 'storage/no-download-token' });
    expect(fetch.mock.calls[0]?.[1].headers.Authorization).toBe('Bearer oauth');
});
it('builds SHA256 encryption headers and rejects invalid keys', async () => {
    const key = new Uint8Array(32);
    const headers = await storageEncryptionHeaders(key);
    expect(headers).toEqual({
        'x-goog-encryption-algorithm': 'AES256',
        'x-goog-encryption-key': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'x-goog-encryption-key-sha256':
            'Zmh6rfhivXdsj8GLjp+OIAiXFIVu4jOzkCpZHQ1fKSU='
    });
    await expect(
        storageEncryptionHeaders(headers['x-goog-encryption-key']!)
    ).resolves.toEqual(headers);
    await expect(storageEncryptionHeaders('!')).rejects.toMatchObject({
        code: 'storage/invalid-argument'
    });
    await expect(
        storageEncryptionHeaders(new Uint8Array(3))
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
});
it('scopes billing and encryption to Storage and preserves destination keys during rewrites', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response());
    const scoped = storageScopedFetch(fetch, {
        userProject: 'billing',
        encryptionKey: new Uint8Array(32),
        kmsKeyName: 'kms'
    });
    await scoped('https://storage.googleapis.com/upload/storage/v1/b/bucket/o');
    const [upload, init] = fetch.mock.calls[0]!;
    expect(new URL(upload).searchParams.get('userProject')).toBe('billing');
    expect(new URL(upload).searchParams.get('kmsKeyName')).toBe('kms');
    expect(new Headers(init.headers).get('x-goog-encryption-algorithm')).toBe(
        'AES256'
    );
    await scoped(
        'https://storage.googleapis.com/storage/v1/b/b/o/a/rewriteTo/b/b/o/b',
        { headers: { 'x-goog-encryption-key': 'destination' } }
    );
    const rewrite = new Headers(fetch.mock.calls[1]?.[1].headers);
    expect(rewrite.get('x-goog-encryption-key')).toBe('destination');
    expect(rewrite.get('x-goog-copy-source-encryption-key')).toBe(
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    );
    await scoped('https://oauth2.googleapis.com/token');
    expect(fetch.mock.calls[2]).toEqual([
        'https://oauth2.googleapis.com/token',
        undefined
    ]);
    const request = new Request('https://example.com');
    await scoped(request);
    expect(fetch.mock.calls[3]).toEqual([request, undefined]);
});
it('probes public access anonymously and preserves unexpected errors', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(new Response(null, { status: 200 }))
        .mockResolvedValueOnce(new Response(null, { status: 403 }))
        .mockResolvedValueOnce(new Response(null, { status: 404 }));
    await expect(storageIsPublic('bucket', 'name', fetch)).resolves.toBe(true);
    await expect(storageIsPublic('bucket', 'name', fetch)).resolves.toBe(false);
    await expect(
        storageIsPublic('bucket', 'name', fetch)
    ).rejects.toMatchObject({ code: 'storage/object-not-found' });
    expect(fetch.mock.calls[0]?.[1]).toEqual({
        method: 'HEAD',
        redirect: 'manual'
    });
});
