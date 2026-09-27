import { expect, it, vi } from 'vitest';
import {
    parseStorageMetadata,
    storageRequest,
    validateStorageOperation
} from './storage-endpoints.js';
import type { StorageOperation } from './storage-types.js';
import { StorageCrc32c } from './storage-checksum.js';

it('uses custom checksum generators in upload, download and stream transports', async () => {
    const generator = vi.fn(() => new StorageCrc32c());
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(
            Response.json({ ...metadata, crc32c: 'Nks/tw==' })
        )
        .mockResolvedValueOnce(
            new Response('abc', {
                headers: { 'x-goog-hash': 'crc32c=Nks/tw==' }
            })
        )
        .mockResolvedValueOnce(
            new Response('abc', {
                headers: { 'x-goog-hash': 'crc32c=Nks/tw==' }
            })
        );
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'upload',
            name: 'file',
            body: 'abc',
            options: { crc32c: 'auto', crc32cGenerator: generator }
        },
        fetch
    );
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'download',
            name: 'file',
            options: { verifyChecksum: true, crc32cGenerator: generator }
        },
        fetch
    );
    const response = await storageRequest(
        'bucket',
        'token',
        {
            kind: 'stream',
            name: 'file',
            options: { verifyChecksum: true, crc32cGenerator: generator }
        },
        fetch
    );
    await expect(response.text()).resolves.toBe('abc');
    expect(generator).toHaveBeenCalledTimes(3);
});

it('sends retention metadata, ACLs and restore projections with validation', async () => {
    const fetch = vi
        .fn()
        .mockImplementation(async () => Response.json(metadata));
    const update = {
        retention: {
            mode: 'Unlocked' as const,
            retainUntilTime: '2027-01-01T00:00:00Z'
        },
        acl: [{ entity: 'allUsers', role: 'READER' as const }]
    };
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'updateMetadata',
            name: 'file',
            metadata: update,
            options: { overrideUnlockedRetention: true }
        },
        fetch
    );
    expect(
        new URL(fetch.mock.calls[0]![0]).searchParams.get(
            'overrideUnlockedRetention'
        )
    ).toBe('true');
    expect(JSON.parse(fetch.mock.calls[0]![1].body)).toEqual(update);
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'restore',
            name: 'file',
            options: { generation: '12', projection: 'full' }
        },
        fetch
    );
    expect(
        new URL(fetch.mock.calls[1]![0]).searchParams.get('projection')
    ).toBe('full');
    for (const value of [
        { retention: { mode: 'wrong', retainUntilTime: '2027-01-01' } },
        { retention: { mode: 'Locked', retainUntilTime: 'bad' } },
        { acl: [{ entity: '', role: 'READER' }] }
    ]) {
        expect(() =>
            validateStorageOperation('bucket', {
                kind: 'updateMetadata',
                name: 'file',
                metadata: value,
                options: {}
            } as never)
        ).toThrow();
    }
    expect(() =>
        validateStorageOperation('bucket', {
            kind: 'restore',
            name: 'file',
            options: { generation: '12', projection: 'bad' }
        } as never)
    ).toThrow();
    expect(() =>
        validateStorageOperation('bucket', {
            kind: 'updateMetadata',
            name: 'file',
            metadata: { retention: null },
            options: { overrideUnlockedRetention: 'yes' }
        } as never)
    ).toThrow();
});

const metadata = {
    name: 'folder/a #?.bin',
    bucket: 'bucket',
    generation: '9007199254740993',
    size: '2'
};

it('uploads MD5 atomically and verifies its returned value', async () => {
    const md5Hash = 'kAFQmDzST7DWlj99KOF/cg==';
    const fetch = vi
        .fn()
        .mockResolvedValue(Response.json({ ...metadata, md5Hash }));
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'upload',
            name: 'file',
            body: 'abc',
            options: {
                md5Hash: 'auto',
                userProject: 'billing',
                predefinedAcl: 'private'
            }
        },
        fetch
    );
    const [url, init] = fetch.mock.calls[0]!;
    expect(new URL(url).searchParams.get('predefinedAcl')).toBe('private');
    expect(new URL(url).searchParams.get('userProject')).toBe('billing');
    const body = await init.body.text();
    expect(body).toContain(`"md5Hash":"${md5Hash}"`);
    expect(() =>
        validateStorageOperation('bucket', {
            kind: 'upload',
            name: 'file',
            body: 'abc',
            options: { md5Hash: 'bad' }
        })
    ).toThrow();
});

it('supports primitive metadata, listing projections, suffix ranges and resumable origins', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(Response.json(metadata))
        .mockResolvedValueOnce(Response.json({ items: [metadata] }))
        .mockResolvedValueOnce(new Response('bc', { status: 206 }))
        .mockResolvedValueOnce(
            new Response(null, { headers: { location: 'session' } })
        );
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'updateMetadata',
            name: 'file',
            metadata: { metadata: { count: 2, active: true, removed: null } },
            options: {}
        },
        fetch
    );
    expect(JSON.parse(fetch.mock.calls[0]?.[1].body)).toEqual({
        metadata: { count: '2', active: 'true', removed: null }
    });
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'list',
            options: {
                fields: 'items(contentType)',
                includeFoldersAsPrefixes: true,
                includeTrailingDelimiter: true,
                delimiter: '/',
                userProject: 'billing'
            }
        },
        fetch
    );
    const query = new URL(fetch.mock.calls[1]?.[0]).searchParams;
    expect(query.get('fields')).toContain('items(name,bucket,generation,size)');
    expect(query.get('includeFoldersAsPrefixes')).toBe('true');
    await storageRequest(
        'bucket',
        'token',
        { kind: 'download', name: 'file', options: { end: -2 } },
        fetch
    );
    expect(fetch.mock.calls[2]?.[1].headers.Range).toBe('bytes=-2');
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'resumable',
            name: 'file',
            options: {
                origin: 'https://example.com',
                md5Hash: 'kAFQmDzST7DWlj99KOF/cg=='
            }
        },
        fetch
    );
    expect(fetch.mock.calls[3]?.[1].headers.Origin).toBe('https://example.com');
    expect(JSON.parse(fetch.mock.calls[3]?.[1].body).md5Hash).toBe(
        'kAFQmDzST7DWlj99KOF/cg=='
    );
});

it('includes custom metadata in one multipart upload without requiring CRC32C', async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json(metadata));
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'upload',
            name: 'file',
            body: 'abc',
            options: { metadata: { metadata: { tag: 'value' } } }
        },
        fetch
    );
    const [url, init] = fetch.mock.calls[0]!;
    expect(new URL(url).searchParams.get('uploadType')).toBe('multipart');
    const body = await init.body.text();
    expect(body).toContain('"metadata":{"tag":"value"}');
    expect(body).not.toContain('"crc32c"');
    expect(() =>
        validateStorageOperation('bucket', {
            kind: 'upload',
            name: 'file',
            body: 'abc',
            options: { metadata: { generation: '1' } as never }
        })
    ).toThrow();
});

it('rewrites metadata and destination encryption atomically', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValue(Response.json({ done: true, resource: metadata }));
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'copy',
            name: 'source',
            destination: 'target',
            options: {
                metadata: { contentType: 'text/plain', temporaryHold: false },
                destinationKmsKeyName: 'kms/key',
                destinationEncryptionKey: new Uint8Array(32)
            }
        },
        fetch
    );
    const [url, init] = fetch.mock.calls[0]!;
    expect(new URL(url).searchParams.get('destinationKmsKeyName')).toBe(
        'kms/key'
    );
    expect(JSON.parse(init.body)).toEqual({
        contentType: 'text/plain',
        temporaryHold: false
    });
    expect(new Headers(init.headers).get('x-goog-encryption-algorithm')).toBe(
        'AES256'
    );
});

it('wraps streamed downloads with deferred checksum verification', async () => {
    const fetch = vi.fn().mockResolvedValue(
        new Response('123456789', {
            headers: { 'x-goog-hash': 'crc32c=4waSgw==' }
        })
    );
    const response = await storageRequest(
        'bucket',
        'token',
        { kind: 'stream', name: 'file', options: { verifyChecksum: true } },
        fetch
    );
    const text = await response.text();
    expect(text).toBe('123456789');
});

it('sends automatic CRC32C and reports UTF-8 upload bytes after completion', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValue(Response.json({ ...metadata, crc32c: '4waSgw==' }));
    const onProgress = vi.fn();
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'upload',
            name: 'file',
            body: '123456789',
            options: { crc32c: 'auto', onProgress }
        },
        fetch
    );
    const [url, init] = fetch.mock.calls[0]!;
    expect(new URL(url).searchParams.get('uploadType')).toBe('multipart');
    expect(init.headers['Content-Type']).toMatch(
        /^multipart\/related; boundary=storage-/
    );
    const body = await init.body.text();
    expect(body).toContain('"crc32c":"4waSgw=="');
    expect(body).toContain('\r\n\r\n123456789\r\n--storage-');
    expect(onProgress).toHaveBeenCalledWith({
        bytesTransferred: 9,
        totalBytes: 9,
        complete: true
    });
});

it('verifies buffered downloads against response CRC32C', async () => {
    const fetch = vi.fn().mockResolvedValue(
        new Response('123456789', {
            headers: { 'x-goog-hash': 'crc32c=4waSgw==' }
        })
    );
    const bytes = await storageRequest(
        'bucket',
        'token',
        { kind: 'download', name: 'file', options: { verifyChecksum: true } },
        fetch
    );
    expect(bytes).toEqual(new TextEncoder().encode('123456789'));
});

it('puts whole-object checksums into resumable upload metadata', async () => {
    const fetch = vi.fn().mockResolvedValue(
        new Response(null, {
            headers: {
                Location:
                    'https://storage.googleapis.com/upload/storage/v1/b/bucket/o?upload_id=abc'
            }
        })
    );
    await storageRequest(
        'bucket',
        'token',
        { kind: 'resumable', name: 'file', options: { crc32c: '4waSgw==' } },
        fetch
    );
    expect(JSON.parse(fetch.mock.calls[0]![1].body).crc32c).toBe('4waSgw==');
});

it.each([
    { kind: 'upload', name: 'file', body: 'a', options: { crc32c: 'bad' } },
    { kind: 'upload', name: 'file', body: 'a', options: { onProgress: true } },
    {
        kind: 'stream',
        name: 'file',
        options: { start: 0, verifyChecksum: true }
    },
    {
        kind: 'download',
        name: 'file',
        options: { start: 0, verifyChecksum: true }
    },
    { kind: 'download', name: 'file', options: { verifyChecksum: 'yes' } },
    { kind: 'resumable', name: 'file', options: { crc32c: 'auto' } }
])('rejects invalid checksum and progress options %j', (operation) => {
    expect(() =>
        validateStorageOperation('bucket', operation as StorageOperation)
    ).toThrow();
});

it('uploads raw bytes with encoded names, content type and create-only preconditions', async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json(metadata));
    const body = new Uint8Array([0, 255]);
    const data = await storageRequest(
        'bucket',
        'token',
        {
            kind: 'upload',
            name: metadata.name,
            body,
            options: { contentType: 'image/png', ifGenerationMatch: '0' }
        },
        fetch
    );
    const [url, init] = fetch.mock.calls[0]!;
    expect(new URL(url).pathname).toBe('/upload/storage/v1/b/bucket/o');
    expect(new URL(url).searchParams.get('name')).toBe(metadata.name);
    expect(new URL(url).searchParams.get('uploadType')).toBe('media');
    expect(new URL(url).searchParams.get('ifGenerationMatch')).toBe('0');
    expect(init).toEqual({
        method: 'POST',
        headers: { Authorization: 'Bearer token', 'Content-Type': 'image/png' },
        body
    });
    expect(data).toEqual(metadata);
});

it.each([
    ['', 'application/octet-stream'],
    [new ArrayBuffer(0), 'application/octet-stream'],
    [new Blob(['hello'], { type: 'text/plain' }), 'text/plain']
] as const)(
    'accepts empty and web-native uploads with default MIME types',
    async (body, contentType) => {
        const fetch = vi.fn().mockResolvedValue(Response.json(metadata));
        await storageRequest(
            'bucket',
            'token',
            { kind: 'upload', name: 'file', body, options: {} },
            fetch
        );
        expect(fetch.mock.calls[0]![1].headers['Content-Type']).toBe(
            contentType
        );
        expect(fetch.mock.calls[0]![1].body).toBe(body);
    }
);

it('downloads bytes without interpreting JSON content and safely encodes object names', async () => {
    const bytes = new Uint8Array([0, 255, 128]);
    const fetch = vi.fn().mockResolvedValue(
        new Response(bytes, {
            headers: { 'Content-Type': 'application/json' }
        })
    );
    const data = await storageRequest(
        'bucket',
        'token',
        { kind: 'download', name: metadata.name },
        fetch
    );
    expect(data).toEqual(bytes);
    expect(fetch.mock.calls[0]![0]).toBe(
        'https://storage.googleapis.com/storage/v1/b/bucket/o/folder%2Fa%20%23%3F.bin?alt=media'
    );
});

it('gets metadata and deletes with a generation condition and an empty response', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(Response.json(metadata))
        .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const info = await storageRequest(
        'bucket',
        'token',
        { kind: 'metadata', name: 'file' },
        fetch
    );
    const removed = await storageRequest(
        'bucket',
        'token',
        {
            kind: 'delete',
            name: 'file',
            options: { ifGenerationMatch: metadata.generation }
        },
        fetch
    );
    expect(info).toEqual(metadata);
    expect(removed).toBeUndefined();
    expect(fetch.mock.calls[0]![0]).toBe(
        'https://storage.googleapis.com/storage/v1/b/bucket/o/file'
    );
    expect(fetch.mock.calls[1]![1].method).toBe('DELETE');
    expect(
        new URL(fetch.mock.calls[1]![0]).searchParams.get('ifGenerationMatch')
    ).toBe(metadata.generation);
});

it('lists a single page and normalizes omitted arrays', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(
            Response.json({
                items: [metadata],
                prefixes: ['folder/'],
                nextPageToken: 'next'
            })
        )
        .mockResolvedValueOnce(Response.json({}));
    const data = await storageRequest(
        'bucket',
        'token',
        {
            kind: 'list',
            options: {
                prefix: 'a &/',
                delimiter: '/',
                maxResults: 5,
                pageToken: 'p+='
            }
        },
        fetch
    );
    expect(data).toEqual({
        files: [metadata],
        prefixes: ['folder/'],
        nextPageToken: 'next'
    });
    expect(
        Object.fromEntries(new URL(fetch.mock.calls[0]![0]).searchParams)
    ).toEqual({
        prefix: 'a &/',
        delimiter: '/',
        maxResults: '5',
        pageToken: 'p+='
    });
    const empty = await storageRequest(
        'bucket',
        'token',
        { kind: 'list', options: {} },
        fetch
    );
    expect(empty).toEqual({ files: [], prefixes: [] });
    expect(fetch).toHaveBeenCalledTimes(2);
});

it.each([
    [400, 'invalid-argument'],
    [401, 'unauthenticated'],
    [403, 'permission-denied'],
    [404, 'object-not-found'],
    [409, 'conflict'],
    [412, 'precondition-failed'],
    [429, 'quota-exceeded'],
    [503, 'unknown-error']
] as const)('maps HTTP %s failures', async (status, code) => {
    const fetch = vi
        .fn()
        .mockResolvedValue(
            Response.json({ error: { message: 'failed' } }, { status })
        );
    await expect(
        storageRequest(
            'bucket',
            'token',
            { kind: 'metadata', name: 'file' },
            fetch
        )
    ).rejects.toMatchObject({
        code: `storage/${code}`,
        message: 'failed',
        context: { status }
    });
});

it.each(['offline', '', 'null'])(
    'handles nonstandard error bodies (%s)',
    async (body) => {
        const fetch = vi
            .fn()
            .mockResolvedValue(new Response(body, { status: 500 }));
        await expect(
            storageRequest(
                'bucket',
                'token',
                { kind: 'metadata', name: 'file' },
                fetch
            )
        ).rejects.toMatchObject({
            code: 'storage/unknown-error',
            message: body || 'Storage request failed (500).'
        });
    }
);

it.each([
    null,
    [],
    { items: {} },
    { prefixes: [2] },
    { nextPageToken: 3 },
    { items: [{}] }
])('rejects malformed list responses', async (body) => {
    const fetch = vi.fn().mockResolvedValue(Response.json(body));
    await expect(
        storageRequest('bucket', 'token', { kind: 'list', options: {} }, fetch)
    ).rejects.toMatchObject({ code: 'storage/internal-error' });
});

it('parses metadata without truncating integer strings', () => {
    expect(parseStorageMetadata(metadata)).toBe(metadata);
    for (const invalid of [
        null,
        {},
        { ...metadata, size: 2 },
        { ...metadata, generation: 3 },
        { ...metadata, bucket: null },
        { ...metadata, name: null }
    ]) {
        expect(() => parseStorageMetadata(invalid)).toThrow(
            'Invalid Storage object metadata'
        );
    }
});

it.each([
    undefined,
    '',
    'gs://bucket',
    'bucket/path',
    'bucket?x',
    'bucket#x',
    ' bucket',
    '.',
    '..'
])('rejects invalid buckets (%s)', async (bucket) => {
    expect(() =>
        validateStorageOperation(bucket, { kind: 'list', options: {} })
    ).toThrow();
    const fetch = vi.fn();
    await expect(
        storageRequest(
            bucket as string,
            'token',
            { kind: 'list', options: {} },
            fetch
        )
    ).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
});

it.each([
    { kind: 'metadata', name: '' },
    { kind: 'metadata', name: '..' },
    { kind: 'metadata', name: 'a\nb' },
    { kind: 'metadata', name: null },
    { kind: 'upload', name: 'file', body: {}, options: {} },
    { kind: 'upload', name: 'file', body: '', options: { contentType: '' } },
    {
        kind: 'upload',
        name: 'file',
        body: '',
        options: { contentType: 'a\nb' }
    },
    { kind: 'delete', name: 'file', options: { ifGenerationMatch: -1 } },
    { kind: 'delete', name: 'file', options: { ifGenerationMatch: '-1' } },
    { kind: 'list', options: null },
    { kind: 'list', options: [] },
    { kind: 'list', options: { maxResults: 0 } },
    { kind: 'list', options: { maxResults: 1001 } },
    { kind: 'list', options: { maxResults: 1.5 } },
    { kind: 'list', options: { prefix: 1 } },
    { kind: 'list', options: { delimiter: false } },
    { kind: 'list', options: { pageToken: 1 } }
])('rejects invalid operation %#', (operation) => {
    expect(() =>
        validateStorageOperation('bucket', operation as StorageOperation)
    ).toThrow();
});

it('patches writable metadata with removals and generation preconditions', async () => {
    const patch = {
        contentType: 'image/png',
        cacheControl: 'public, max-age=3600',
        contentDisposition: null,
        contentEncoding: 'gzip',
        contentLanguage: 'en',
        metadata: { label: 'new', removed: null }
    };
    const fetch = vi
        .fn()
        .mockResolvedValue(Response.json({ ...metadata, ...patch }));
    const data = await storageRequest(
        'bucket',
        'token',
        {
            kind: 'updateMetadata',
            name: metadata.name,
            metadata: patch,
            options: { ifGenerationMatch: '5', ifMetagenerationMatch: '2' }
        },
        fetch
    );
    const [url, init] = fetch.mock.calls[0]!;
    expect(new URL(url).pathname).toBe(
        '/storage/v1/b/bucket/o/folder%2Fa%20%23%3F.bin'
    );
    expect(Object.fromEntries(new URL(url).searchParams)).toEqual({
        ifGenerationMatch: '5',
        ifMetagenerationMatch: '2'
    });
    expect(init).toEqual({
        method: 'PATCH',
        headers: {
            Authorization: 'Bearer token',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(patch)
    });
    expect(data).toEqual({ ...metadata, ...patch });
});

it('permits removing all custom metadata', async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json(metadata));
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'updateMetadata',
            name: 'file',
            metadata: { metadata: null },
            options: {}
        },
        fetch
    );
    expect(fetch.mock.calls[0]![1].body).toBe('{"metadata":null}');
});

it.each([
    {},
    null,
    [],
    { name: 'rename' },
    { cacheControl: 42 },
    { contentType: 'a\nb' },
    { metadata: [] },
    { metadata: 'bad' },
    { metadata: { label: {} } }
])('rejects invalid metadata update %# before fetch', async (patch) => {
    const fetch = vi.fn();
    await expect(
        storageRequest(
            'bucket',
            'token',
            {
                kind: 'updateMetadata',
                name: 'file',
                metadata: patch as never,
                options: {}
            },
            fetch
        )
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    expect(fetch).not.toHaveBeenCalled();
});

it.each([undefined, 'other'])(
    'copies to a destination bucket (%s) across rewrite pages',
    async (destinationBucket) => {
        const fetch = vi
            .fn()
            .mockResolvedValueOnce(
                Response.json({ done: false, rewriteToken: 'next+/' })
            )
            .mockResolvedValueOnce(
                Response.json({ done: true, resource: metadata })
            );
        const data = await storageRequest(
            'bucket',
            'token',
            {
                kind: 'copy',
                name: 'folder/source?#',
                destination: 'folder/copy?#',
                options: {
                    destinationBucket,
                    ifGenerationMatch: '0',
                    ifSourceGenerationMatch: '7'
                }
            },
            fetch
        );
        expect(data).toEqual(metadata);
        expect(fetch).toHaveBeenCalledTimes(2);
        for (const [url, init] of fetch.mock.calls) {
            expect(new URL(url).pathname).toBe(
                `/storage/v1/b/bucket/o/folder%2Fsource%3F%23/rewriteTo/b/${destinationBucket ?? 'bucket'}/o/folder%2Fcopy%3F%23`
            );
            expect(new URL(url).searchParams.get('ifGenerationMatch')).toBe(
                '0'
            );
            expect(
                new URL(url).searchParams.get('ifSourceGenerationMatch')
            ).toBe('7');
            expect(init).toEqual({
                method: 'POST',
                headers: { Authorization: 'Bearer token' }
            });
        }
        expect(
            new URL(fetch.mock.calls[0]![0]).searchParams.has('rewriteToken')
        ).toBe(false);
        expect(
            new URL(fetch.mock.calls[1]![0]).searchParams.get('rewriteToken')
        ).toBe('next+/');
    }
);

it('copies without preconditions and accepts the same name in another bucket', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValue(Response.json({ done: true, resource: metadata }));
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'copy',
            name: 'file',
            destination: 'file',
            options: { destinationBucket: 'other' }
        },
        fetch
    );
    expect(new URL(fetch.mock.calls[0]![0]).search).toBe('');
});

it.each([
    {},
    { done: false },
    { done: false, rewriteToken: '' },
    { done: true },
    { done: true, resource: {} },
    { done: 'true' },
    null
])('rejects malformed rewrite responses %#', async (body) => {
    const fetch = vi.fn().mockResolvedValue(Response.json(body));
    await expect(
        storageRequest(
            'bucket',
            'token',
            { kind: 'copy', name: 'file', destination: 'copy', options: {} },
            fetch
        )
    ).rejects.toMatchObject({ code: 'storage/internal-error' });
    expect(fetch).toHaveBeenCalledTimes(1);
});

it('stops rewrite continuation on an API failure', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(
            Response.json({ done: false, rewriteToken: 'next' })
        )
        .mockResolvedValueOnce(
            Response.json(
                { error: { message: 'source changed' } },
                { status: 412 }
            )
        );
    await expect(
        storageRequest(
            'bucket',
            'token',
            { kind: 'copy', name: 'file', destination: 'copy', options: {} },
            fetch
        )
    ).rejects.toMatchObject({ code: 'storage/precondition-failed' });
    expect(fetch).toHaveBeenCalledTimes(2);
});

it.each([
    { kind: 'copy', name: 'file', destination: 'file', options: {} },
    { kind: 'copy', name: 'file', destination: '', options: {} },
    {
        kind: 'copy',
        name: 'file',
        destination: 'copy',
        options: { destinationBucket: null }
    },
    {
        kind: 'copy',
        name: 'file',
        destination: 'copy',
        options: { destinationBucket: 'bad/bucket' }
    },
    {
        kind: 'copy',
        name: 'file',
        destination: 'copy',
        options: { ifSourceGenerationMatch: '-1' }
    },
    {
        kind: 'updateMetadata',
        name: 'file',
        metadata: { contentType: 'text/plain' },
        options: { ifMetagenerationMatch: 1 }
    }
])('validates copy targets and new preconditions %#', (operation) => {
    expect(() =>
        validateStorageOperation('bucket', operation as StorageOperation)
    ).toThrow();
});

it('returns a streaming response without consuming or buffering its body', async () => {
    const response = new Response(new Uint8Array([1, 2]), {
        status: 206,
        headers: {
            'Content-Range': 'bytes 2-3/10',
            'Content-Type': 'image/png'
        }
    });
    const fetch = vi.fn().mockResolvedValue(response);
    const data = await storageRequest(
        'bucket',
        'token',
        {
            kind: 'stream',
            name: 'file',
            options: {
                generation: '7',
                start: 2,
                end: 3,
                ifGenerationMatch: '7',
                ifGenerationNotMatch: '6',
                ifMetagenerationMatch: '2',
                ifMetagenerationNotMatch: '1'
            }
        },
        fetch
    );
    expect(data).toBe(response);
    expect(data.bodyUsed).toBe(false);
    expect(data.headers.get('Content-Range')).toBe('bytes 2-3/10');
    const [url, init] = fetch.mock.calls[0]!;
    expect(init.headers.Range).toBe('bytes=2-3');
    expect(Object.fromEntries(new URL(url).searchParams)).toEqual({
        alt: 'media',
        generation: '7',
        ifGenerationMatch: '7',
        ifGenerationNotMatch: '6',
        ifMetagenerationMatch: '2',
        ifMetagenerationNotMatch: '1'
    });
    await data.body?.cancel();
});

it.each([{ start: 2 }, { end: 3 }])(
    'supports open and implicit-start byte ranges',
    async (options) => {
        const fetch = vi
            .fn()
            .mockResolvedValue(new Response('ab', { status: 206 }));
        const bytes = await storageRequest(
            'bucket',
            'token',
            { kind: 'download', name: 'file', options },
            fetch
        );
        expect(bytes).toEqual(new TextEncoder().encode('ab'));
        expect(fetch.mock.calls[0]![1].headers.Range).toBe(
            options.start !== undefined ? 'bytes=2-' : 'bytes=0-3'
        );
    }
);

it('creates resumable sessions with content metadata and upload size', async () => {
    const location =
        'https://storage.googleapis.com/upload/storage/v1/b/bucket/o?upload_id=secret';
    const fetch = vi
        .fn()
        .mockResolvedValue(
            new Response(null, { headers: { Location: location } })
        );
    const session = await storageRequest(
        'bucket',
        'token',
        {
            kind: 'resumable',
            name: 'a/b',
            options: {
                size: 0,
                contentType: 'text/plain',
                metadata: { metadata: { label: 'test' } },
                ifGenerationMatch: '0'
            }
        },
        fetch
    );
    expect(session).toBe(location);
    const [url, init] = fetch.mock.calls[0]!;
    expect(new URL(url).pathname).toBe('/upload/storage/v1/b/bucket/o');
    expect(Object.fromEntries(new URL(url).searchParams)).toEqual({
        uploadType: 'resumable',
        name: 'a/b',
        ifGenerationMatch: '0'
    });
    expect(init).toMatchObject({
        method: 'POST',
        headers: {
            'X-Upload-Content-Type': 'text/plain',
            'X-Upload-Content-Length': '0'
        }
    });
    expect(JSON.parse(init.body)).toEqual({
        contentType: 'text/plain',
        metadata: { label: 'test' }
    });
});

it('supports empty resumable options and rejects a missing session location', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(null));
    await expect(
        storageRequest(
            'bucket',
            'token',
            { kind: 'resumable', name: 'file', options: {} },
            fetch
        )
    ).rejects.toMatchObject({ code: 'storage/internal-error' });
    expect(fetch.mock.calls[0]![1].body).toBe('{}');
});

it('lists object versions and soft-deleted objects on separate requests', async () => {
    const fetch = vi
        .fn()
        .mockImplementation(() => Promise.resolve(Response.json({})));
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'list',
            options: {
                versions: true,
                startOffset: 'a',
                endOffset: 'z',
                matchGlob: '**.txt'
            }
        },
        fetch
    );
    await storageRequest(
        'bucket',
        'token',
        { kind: 'list', options: { softDeleted: true } },
        fetch
    );
    expect(
        Object.fromEntries(new URL(fetch.mock.calls[0]![0]).searchParams)
    ).toEqual({
        versions: 'true',
        startOffset: 'a',
        endOffset: 'z',
        matchGlob: '**.txt'
    });
    expect(
        new URL(fetch.mock.calls[1]![0]).searchParams.get('softDeleted')
    ).toBe('true');
});

it('restores soft-deleted generations with destination preconditions', async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json(metadata));
    const data = await storageRequest(
        'bucket',
        'token',
        {
            kind: 'restore',
            name: 'a/b',
            options: {
                generation: '7',
                ifGenerationMatch: '0',
                restoreToken: 'restore+token',
                copySourceAcl: true
            }
        },
        fetch
    );
    expect(data).toEqual(metadata);
    const [url, init] = fetch.mock.calls[0]!;
    expect(new URL(url).pathname).toBe('/storage/v1/b/bucket/o/a%2Fb/restore');
    expect(Object.fromEntries(new URL(url).searchParams)).toEqual({
        generation: '7',
        ifGenerationMatch: '0',
        restoreToken: 'restore+token',
        copySourceAcl: 'true'
    });
    expect(init.method).toBe('POST');
});

it('composes generation-specific source objects without downloading content', async () => {
    const sources = [
        {
            name: 'a',
            generation: '7',
            objectPreconditions: { ifGenerationMatch: '7' }
        },
        { name: 'b' }
    ];
    const fetch = vi.fn().mockResolvedValue(Response.json(metadata));
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'compose',
            name: 'combined',
            sources,
            options: {
                ifGenerationMatch: '0',
                metadata: { contentType: 'text/plain' }
            }
        },
        fetch
    );
    const [url, init] = fetch.mock.calls[0]!;
    expect(new URL(url).pathname).toBe(
        '/storage/v1/b/bucket/o/combined/compose'
    );
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body)).toEqual({
        sourceObjects: sources,
        destination: { contentType: 'text/plain' }
    });
});

it('can copy an older generation over the same object name', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValue(Response.json({ done: true, resource: metadata }));
    await storageRequest(
        'bucket',
        'token',
        {
            kind: 'copy',
            name: 'file',
            destination: 'file',
            options: {
                sourceGeneration: '7',
                ifGenerationMatch: '8',
                ifSourceMetagenerationMatch: '1',
                ifGenerationNotMatch: '6',
                ifMetagenerationNotMatch: '3'
            }
        },
        fetch
    );
    expect(
        Object.fromEntries(new URL(fetch.mock.calls[0]![0]).searchParams)
    ).toEqual({
        sourceGeneration: '7',
        ifGenerationMatch: '8',
        ifSourceMetagenerationMatch: '1',
        ifGenerationNotMatch: '6',
        ifMetagenerationNotMatch: '3'
    });
});

it.each([
    { kind: 'download', name: 'file', options: { start: -1 } },
    { kind: 'stream', name: 'file', options: { start: 5, end: 4 } },
    { kind: 'stream', name: 'file', options: { end: 1.5 } },
    { kind: 'metadata', name: 'file', options: { generation: 'bad' } },
    { kind: 'list', options: { versions: true, softDeleted: true } },
    { kind: 'list', options: { versions: 'true' } },
    { kind: 'resumable', name: 'file', options: { size: -1 } },
    { kind: 'resumable', name: 'file', options: { contentType: 'a\nb' } },
    { kind: 'restore', name: 'file', options: {} },
    { kind: 'restore', name: 'file', options: undefined },
    { kind: 'compose', name: 'file', sources: [], options: {} },
    {
        kind: 'compose',
        name: 'file',
        sources: Array.from({ length: 33 }, () => ({ name: 'a' })),
        options: {}
    },
    { kind: 'compose', name: 'file', sources: [null], options: {} },
    { kind: 'compose', name: 'file', sources: [{ name: '' }], options: {} }
])('rejects invalid advanced object options %#', (operation) => {
    expect(() =>
        validateStorageOperation('bucket', operation as never)
    ).toThrow();
});
