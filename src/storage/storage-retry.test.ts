import { afterEach, expect, it, vi } from 'vitest';
import { createStorageRetryFetch } from './storage-retry.js';

afterEach(() => vi.useRealTimers());
const url = 'https://storage.googleapis.com/storage/v1/b/bucket/o/file';
it.each([408, 429, 500, 502, 503, 504])(
    'retries transient status %i and cancels its response body',
    async (status) => {
        const cancel = vi.fn();
        const failed = new Response(new ReadableStream({ cancel }), { status });
        const fetch = vi
            .fn()
            .mockResolvedValueOnce(failed)
            .mockResolvedValue(new Response('ok'));
        const retry = createStorageRetryFetch(fetch, { initialDelayMs: 0 });
        const response = await retry(url);
        expect(response.status).toBe(200);
        expect(fetch).toHaveBeenCalledTimes(2);
        expect(cancel).toHaveBeenCalledOnce();
    }
);
it.each(['POST', 'PATCH', 'DELETE'])(
    'retries guarded %s writes',
    async (method) => {
        const fetch = vi
            .fn()
            .mockRejectedValueOnce(new TypeError('network'))
            .mockResolvedValue(new Response());
        const retry = createStorageRetryFetch(fetch, { initialDelayMs: 0 });
        await retry(`${url}?ifGenerationMatch=0`, { method, body: 'reusable' });
        expect(fetch).toHaveBeenCalledTimes(2);
    }
);
it.each([
    [url, { method: 'POST' }],
    [url, { method: 'PATCH' }],
    ['https://oauth2.googleapis.com/token', {}],
    [`${url}?ifGenerationMatch=0&uploadType=resumable`, { method: 'POST' }],
    [`${url}?upload_id=abc`, { method: 'PUT', body: 'chunk' }],
    [url, { method: 'POST', body: new ReadableStream() }],
    [new Request(url), undefined]
] as const)(
    'does not replay unsafe or consumable requests',
    async (input, init) => {
        const fetch = vi
            .fn()
            .mockResolvedValue(new Response(null, { status: 503 }));
        const retry = createStorageRetryFetch(fetch, { initialDelayMs: 0 });
        await retry(input, init);
        expect(fetch).toHaveBeenCalledOnce();
    }
);
it('retries empty resumable status probes', async () => {
    const fetch = vi
        .fn()
        .mockRejectedValueOnce(new TypeError('network'))
        .mockResolvedValue(new Response(null, { status: 308 }));
    const retry = createStorageRetryFetch(fetch, { initialDelayMs: 0 });
    const response = await retry(`${url}?upload_id=abc`, {
        method: 'PUT',
        body: '',
        headers: { 'Content-Range': 'bytes */*' }
    });
    expect(response.status).toBe(308);
    expect(fetch).toHaveBeenCalledTimes(2);
});
it('bounds retry counts and leaves ordinary errors alone', async () => {
    const fetch = vi
        .fn()
        .mockImplementation(async () => new Response(null, { status: 503 }));
    const retry = createStorageRetryFetch(fetch, {
        initialDelayMs: 0,
        maxRetries: 2
    });
    await retry(url);
    expect(fetch).toHaveBeenCalledTimes(3);
    fetch.mockReset().mockRejectedValue(new Error('bug'));
    await expect(retry(url)).rejects.toThrow('bug');
    expect(fetch).toHaveBeenCalledOnce();
});
it('honors Retry-After and aborts backoff promptly', async () => {
    vi.useFakeTimers();
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(
            new Response(null, { status: 429, headers: { 'Retry-After': '1' } })
        )
        .mockResolvedValue(new Response());
    const retry = createStorageRetryFetch(fetch);
    const request = retry(url);
    await vi.advanceTimersByTimeAsync(999);
    expect(fetch).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(1);
    await request;
    expect(fetch).toHaveBeenCalledTimes(2);
    fetch.mockReset().mockResolvedValue(new Response(null, { status: 503 }));
    const controller = new AbortController();
    const pending = retry(url, { signal: controller.signal });
    const rejected = expect(pending).rejects.toThrow('cancelled');
    await vi.advanceTimersByTimeAsync(0);
    controller.abort(new Error('cancelled'));
    await rejected;
    expect(fetch).toHaveBeenCalledOnce();
});
it('returns responses whose Retry-After exceeds the wait bound', async () => {
    const fetch = vi.fn().mockResolvedValue(
        new Response(null, {
            status: 429,
            headers: { 'Retry-After': '60' }
        })
    );
    const retry = createStorageRetryFetch(fetch);
    const response = await retry(url);
    expect(response.status).toBe(429);
    expect(fetch).toHaveBeenCalledOnce();
});

it.each(['POST', 'DELETE'])(
    'does not treat object metageneration as an identity guard for %s',
    async (method) => {
        const fetch = vi
            .fn()
            .mockResolvedValue(new Response(null, { status: 503 }));
        const retry = createStorageRetryFetch(fetch, { initialDelayMs: 0 });
        await retry(`${url}?ifMetagenerationMatch=1`, { method });
        expect(fetch).toHaveBeenCalledOnce();
    }
);

it('retries guarded metadata changes', async () => {
    const fetch = vi
        .fn()
        .mockRejectedValueOnce(new TypeError('network'))
        .mockResolvedValue(new Response());
    const retry = createStorageRetryFetch(fetch, { initialDelayMs: 0 });
    await retry(`${url}?ifMetagenerationMatch=1`, {
        method: 'PATCH',
        body: '{}'
    });
    expect(fetch).toHaveBeenCalledTimes(2);
});
it.each([
    { maxRetries: -1 },
    { maxRetries: 11 },
    { initialDelayMs: NaN },
    { maxDelayMs: 1 },
    null
])('rejects invalid retry options %j', (options) => {
    expect(() => createStorageRetryFetch(vi.fn(), options as never)).toThrow();
});
