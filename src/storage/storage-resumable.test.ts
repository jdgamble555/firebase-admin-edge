import { expect, it, vi } from 'vitest';
import { resumableRequest, validateSessionUri } from './storage-resumable.js';

const session =
    'https://storage.googleapis.com/upload/storage/v1/b/bucket/o?uploadType=resumable&upload_id=secret';
const metadata = { name: 'file', bucket: 'bucket', generation: '1', size: '3' };

it('can finalize already-acknowledged bytes with an empty final request', async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json(metadata));
    const result = await resumableRequest(
        session,
        { kind: 'chunk', body: '', options: { offset: 3, totalSize: 3 } },
        fetch
    );
    expect(result.complete).toBe(true);
    expect(fetch.mock.calls[0]![1].headers['Content-Range']).toBe('bytes */3');
});

it('reports persisted progress and sends whole-object CRC32C on the final chunk', async () => {
    const onProgress = vi.fn();
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(
            new Response(null, {
                status: 308,
                headers: { Range: 'bytes=0-262143' }
            })
        )
        .mockResolvedValueOnce(
            Response.json({ ...metadata, size: '262147', crc32c: 'AAAAAA==' })
        );
    await resumableRequest(
        session,
        {
            kind: 'chunk',
            body: new Uint8Array(262144),
            options: { offset: 0, totalSize: 262147, onProgress }
        },
        fetch
    );
    await resumableRequest(
        session,
        {
            kind: 'chunk',
            body: 'abc',
            options: {
                offset: 262144,
                totalSize: 262147,
                crc32c: 'AAAAAA==',
                onProgress
            }
        },
        fetch
    );
    expect(onProgress.mock.calls).toEqual([
        [{ bytesTransferred: 262144, totalBytes: 262147, complete: false }],
        [{ bytesTransferred: 262147, totalBytes: 262147, complete: true }]
    ]);
    expect(fetch.mock.calls[1]![1].headers['X-Goog-Hash']).toBe(
        'crc32c=AAAAAA=='
    );
});

it.each([{ crc32c: 'bad' }, { crc32c: 'AAAAAA==' }, { onProgress: 1 }])(
    'rejects invalid checksum/progress and checksums on non-final chunks',
    async (options) => {
        const fetch = vi.fn();
        await expect(
            resumableRequest(
                session,
                {
                    kind: 'chunk',
                    body: new Uint8Array(262144),
                    options: { offset: 0, ...options } as never
                },
                fetch
            )
        ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
        expect(fetch).not.toHaveBeenCalled();
    }
);

it('sends aligned chunks without OAuth and trusts persisted byte counts', async () => {
    const fetch = vi.fn().mockResolvedValue(
        new Response(null, {
            status: 308,
            headers: { Range: 'bytes=0-131071' }
        })
    );
    const progress = await resumableRequest(
        session,
        { kind: 'chunk', body: new Uint8Array(262144), options: { offset: 0 } },
        fetch
    );
    expect(progress).toEqual({ complete: false, nextOffset: 131072 });
    const [url, init] = fetch.mock.calls[0]!;
    expect(url).toBe(session);
    expect(init).toMatchObject({
        method: 'PUT',
        redirect: 'manual',
        headers: { 'Content-Range': 'bytes 0-262143/*' }
    });
    expect(init.headers.Authorization).toBeUndefined();
    expect(init.body.size).toBe(262144);
});

it.each([
    'abc',
    new Uint8Array([1, 2, 3]),
    new Blob(['abc']),
    new ArrayBuffer(3)
])('completes final chunks with web data types', async (body) => {
    const fetch = vi.fn().mockResolvedValue(Response.json(metadata));
    const progress = await resumableRequest(
        session,
        { kind: 'chunk', body, options: { offset: 262144, totalSize: 262147 } },
        fetch
    );
    expect(progress).toEqual({ complete: true, metadata });
    expect(fetch.mock.calls[0]![1].headers['Content-Range']).toBe(
        'bytes 262144-262146/262147'
    );
});

it('counts UTF-8 bytes and handles empty uploads', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(Response.json(metadata))
        .mockResolvedValueOnce(Response.json({ ...metadata, size: '0' }));
    await resumableRequest(
        session,
        { kind: 'chunk', body: 'é', options: { offset: 0, totalSize: 2 } },
        fetch
    );
    await resumableRequest(
        session,
        { kind: 'chunk', body: '', options: { offset: 0, totalSize: 0 } },
        fetch
    );
    expect(fetch.mock.calls[0]![1].headers['Content-Range']).toBe(
        'bytes 0-1/2'
    );
    expect(fetch.mock.calls[1]![1].headers['Content-Range']).toBe('bytes */0');
});

it('probes unknown, partially committed, and completed uploads', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(new Response(null, { status: 308 }))
        .mockResolvedValueOnce(
            new Response(null, {
                status: 308,
                headers: { Range: 'bytes=0-262143' }
            })
        )
        .mockResolvedValueOnce(Response.json(metadata));
    const empty = await resumableRequest(session, { kind: 'status' }, fetch);
    const partial = await resumableRequest(
        session,
        { kind: 'status', totalSize: 300000 },
        fetch
    );
    const complete = await resumableRequest(
        session,
        { kind: 'status', totalSize: 3 },
        fetch
    );
    expect(empty).toEqual({ complete: false, nextOffset: 0 });
    expect(partial).toEqual({ complete: false, nextOffset: 262144 });
    expect(complete).toEqual({ complete: true, metadata });
    expect(fetch.mock.calls[0]![1].headers['Content-Range']).toBe('bytes */*');
    expect(fetch.mock.calls[1]![1].headers['Content-Range']).toBe(
        'bytes */300000'
    );
});

it.each([499, 204])(
    'accepts successful cancellation status %s',
    async (status) => {
        const fetch = vi.fn().mockResolvedValue(new Response(null, { status }));
        const result = await resumableRequest(
            session,
            { kind: 'cancel' },
            fetch
        );
        expect(result).toBeUndefined();
        expect(fetch).toHaveBeenCalledWith(session, {
            method: 'DELETE',
            redirect: 'manual'
        });
    }
);

it.each([
    'https://evil.example/upload?upload_id=x',
    'http://storage.googleapis.com/upload/storage/v1/b/b/o?upload_id=x',
    'https://user@storage.googleapis.com/upload/storage/v1/b/b/o?upload_id=x',
    'https://storage.googleapis.com/storage/v1/b/b/o?upload_id=x',
    session + '#fragment',
    'bad',
    'https://storage.googleapis.com/upload/storage/v1/b/b/o'
])('rejects unsafe session URI %# without fetch', async (uri) => {
    const fetch = vi.fn();
    expect(() => validateSessionUri(uri)).toThrow();
    await expect(
        resumableRequest(uri, { kind: 'cancel' }, fetch)
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    expect(fetch).not.toHaveBeenCalled();
});

it.each([
    { kind: 'status', totalSize: -1 },
    { kind: 'status', totalSize: 1.5 },
    { kind: 'chunk', body: 'a', options: null },
    { kind: 'chunk', body: 'a', options: { offset: -1 } },
    { kind: 'chunk', body: {}, options: { offset: 0 } },
    { kind: 'chunk', body: 'a', options: { offset: 0 } },
    { kind: 'chunk', body: '', options: { offset: 0 } },
    { kind: 'chunk', body: 'abc', options: { offset: 0, totalSize: 2 } },
    { kind: 'chunk', body: 'a', options: { offset: Number.MAX_SAFE_INTEGER } }
])('rejects invalid chunk or status parameters %#', async (operation) => {
    const fetch = vi.fn();
    await expect(
        resumableRequest(session, operation as never, fetch)
    ).rejects.toMatchObject({ code: 'storage/invalid-argument' });
    expect(fetch).not.toHaveBeenCalled();
});

it.each(['bad', 'bytes=5-10', 'bytes=0-9007199254740992', 'bytes=0-999'])(
    'rejects invalid or impossible progress (%s)',
    async (range) => {
        const fetch = vi
            .fn()
            .mockResolvedValue(
                new Response(null, { status: 308, headers: { Range: range } })
            );
        await expect(
            resumableRequest(
                session,
                {
                    kind: 'chunk',
                    body: 'abc',
                    options: { offset: 0, totalSize: 3 }
                },
                fetch
            )
        ).rejects.toMatchObject({ code: 'storage/internal-error' });
    }
);

it('propagates transport errors and rejects malformed completion metadata', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(new Response('expired', { status: 404 }))
        .mockResolvedValueOnce(Response.json({}));
    await expect(
        resumableRequest(session, { kind: 'status' }, fetch)
    ).rejects.toMatchObject({ code: 'storage/object-not-found' });
    await expect(
        resumableRequest(session, { kind: 'status' }, fetch)
    ).rejects.toMatchObject({ code: 'storage/internal-error' });
});
