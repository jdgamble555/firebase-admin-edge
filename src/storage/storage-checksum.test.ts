import { expect, it, vi } from 'vitest';
import {
    calculateStorageMd5,
    validateStorageMd5,
    calculateStorageCrc32c,
    storageUploadBlob,
    validateStorageCrc32c,
    verifyStorageDownload,
    verifyStorageUpload,
    verifyStorageStream,
    StorageCrc32c
} from './storage-checksum.js';
import { createStorageCrc32c } from './storage-checksum.js';

it('uses fresh custom validators for buffered and streamed checksums', async () => {
    const generator = vi.fn(() => new StorageCrc32c());
    await expect(calculateStorageCrc32c('abc', generator)).resolves.toBe(
        'Nks/tw=='
    );
    const bytes = new TextEncoder().encode('abc');
    await verifyStorageDownload(
        bytes,
        new Response(bytes, { headers: { 'x-goog-hash': 'crc32c=Nks/tw==' } }),
        'crc32c',
        generator
    );
    const response = verifyStorageStream(
        new Response(bytes, { headers: { 'x-goog-hash': 'crc32c=Nks/tw==' } }),
        'crc32c',
        generator
    );
    await expect(response.text()).resolves.toBe('abc');
    expect(generator).toHaveBeenCalledTimes(3);
    const crc = new StorageCrc32c();
    crc.update(bytes);
    expect(crc.toString()).toBe('Nks/tw==');
    expect(crc.validate('Nks/tw==')).toBe(true);
    expect(crc.validate('AAAAAA==')).toBe(false);
});

it.each([0, 1, 7, 262144, 524289])(
    'combines a resumed prefix and custom suffix checksum of length %i',
    async (length) => {
        const prefix = new Uint8Array(31).fill(17);
        const suffix = new Uint8Array(length).fill(203);
        const seed = await calculateStorageCrc32c(prefix);
        const checksum = createStorageCrc32c(() => new StorageCrc32c(), seed);
        checksum.update(suffix.subarray(0, 3));
        checksum.update(suffix.subarray(3));
        const expected = new StorageCrc32c(seed);
        expected.update(suffix);
        expect(checksum.digest()).toBe(expected.digest());
    }
);

it('rejects invalid custom validators and cancels downloaded bodies on factory/update errors', async () => {
    for (const generator of [
        null,
        3,
        () => ({}),
        () => ({
            update() {},
            toString() {
                return 'bad';
            },
            validate() {
                return true;
            }
        }),
        () => ({
            update() {},
            toString() {
                return 'AAAAAA==';
            },
            validate() {
                return false;
            }
        })
    ]) {
        await expect(
            calculateStorageCrc32c('abc', generator as never)
        ).rejects.toBeInstanceOf(Error);
    }
    const cancel = vi.fn();
    const response = new Response(new ReadableStream({ cancel }), {
        headers: { 'x-goog-hash': 'crc32c=Nks/tw==' }
    });
    expect(() =>
        verifyStorageStream(response, 'crc32c', () => {
            throw new Error('factory');
        })
    ).toThrow('factory');
    expect(cancel).toHaveBeenCalled();
    const corrupt = verifyStorageStream(
        new Response('abc', { headers: { 'x-goog-hash': 'crc32c=Nks/tw==' } }),
        'crc32c',
        () => ({
            update() {
                throw new Error('update');
            },
            toString() {
                return 'AAAAAA==';
            },
            validate() {
                return true;
            }
        })
    );
    await expect(corrupt.text()).rejects.toThrow('update');
    const unused = vi.fn(() => {
        throw new Error('unused');
    });
    await verifyStorageDownload(
        new TextEncoder().encode('abc'),
        new Response(null, {
            headers: { 'x-goog-hash': 'md5=kAFQmDzST7DWlj99KOF/cg==' }
        }),
        'md5',
        unused
    );
    expect(unused).not.toHaveBeenCalled();
});

it('calculates MD5 from every supported input and verifies buffered and streamed downloads', async () => {
    const hash = 'kAFQmDzST7DWlj99KOF/cg==';
    for (const input of [
        'abc',
        new Blob(['abc']),
        new TextEncoder().encode('abc'),
        new TextEncoder().encode('abc').buffer
    ]) {
        await expect(calculateStorageMd5(input)).resolves.toBe(hash);
    }
    validateStorageMd5(hash);
    expect(() => validateStorageMd5('bad')).toThrow();
    await expect(calculateStorageMd5({} as never)).rejects.toMatchObject({
        code: 'storage/invalid-argument'
    });
    const response = new Response('abc', {
        headers: { 'x-goog-hash': `crc32c=Nks/tw==,md5=${hash}` }
    });
    await verifyStorageDownload(
        new TextEncoder().encode('abc'),
        response,
        'md5'
    );
    const verified = verifyStorageStream(response, 'md5');
    await expect(verified.text()).resolves.toBe('abc');
    const corrupt = verifyStorageStream(
        new Response('bad', { headers: { 'x-goog-hash': `md5=${hash}` } }),
        'md5'
    );
    await expect(corrupt.text()).rejects.toMatchObject({
        code: 'storage/checksum-mismatch'
    });
    expect(() =>
        verifyStorageStream(
            new Response('abc', {
                headers: { 'x-goog-hash': 'crc32c=Nks/tw==' }
            }),
            'md5'
        )
    ).toThrow(/md5/);
    const metadata = {
        name: 'file',
        bucket: 'bucket',
        generation: '1',
        size: '3',
        md5Hash: hash
    };
    verifyStorageUpload(undefined, metadata, hash);
    expect(() =>
        verifyStorageUpload(
            undefined,
            { ...metadata, md5Hash: undefined },
            hash
        )
    ).toThrow(/MD5/);
    expect(() =>
        verifyStorageUpload(undefined, metadata, '1B2M2Y8AsgTpgAmY7PhCfg==')
    ).toThrow(/MD5/);
});

it('accumulates CRC32C across arbitrary chunk boundaries', () => {
    const checksum = new StorageCrc32c();
    expect(checksum.digest()).toBe('AAAAAA==');
    checksum.update(new TextEncoder().encode('1234'));
    checksum.update(new TextEncoder().encode('56789'));
    expect(checksum.digest()).toBe('4waSgw==');
    expect(checksum.digest()).toBe('4waSgw==');
});

it('continues a preceding CRC32C without retaining preceding bytes', () => {
    const first = new StorageCrc32c();
    first.update(new TextEncoder().encode('1234'));
    const resumed = new StorageCrc32c(first.digest());
    resumed.update(new TextEncoder().encode('56789'));
    expect(resumed.digest()).toBe('4waSgw==');
    expect(new StorageCrc32c(0).digest()).toBe('AAAAAA==');
    expect(() => new StorageCrc32c(0x100000000)).toThrow();
    expect(() => new StorageCrc32c('bad')).toThrow();
});

it('verifies streams through EOF while preserving response metadata', async () => {
    const response = verifyStorageStream(
        new Response('123456789', {
            headers: {
                'x-goog-hash': 'crc32c=4waSgw==',
                'content-type': 'text/plain'
            }
        })
    );
    expect(response.headers.get('content-type')).toBe('text/plain');
    const text = await response.text();
    expect(text).toBe('123456789');
    const corrupt = verifyStorageStream(
        new Response('wrong', { headers: { 'x-goog-hash': 'crc32c=4waSgw==' } })
    );
    await expect(corrupt.text()).rejects.toMatchObject({
        code: 'storage/checksum-mismatch'
    });
});

it('propagates source errors and cancellation without consuming the whole stream', async () => {
    let cancelled: unknown;
    let pulls = 0;
    const source = new ReadableStream<Uint8Array>({
        pull(controller) {
            pulls++;
            controller.enqueue(new Uint8Array([1]));
        },
        cancel(reason) {
            cancelled = reason;
        }
    });
    const response = verifyStorageStream(
        new Response(source, { headers: { 'x-goog-hash': 'crc32c=AAAAAA==' } })
    );
    const reader = response.body!.getReader();
    await reader.read();
    await reader.cancel('stop');
    expect(cancelled).toBe('stop');
    expect(pulls).toBeLessThanOrEqual(2);
    const failed = verifyStorageStream(
        new Response(
            new ReadableStream({
                start(controller) {
                    controller.error(new Error('source'));
                }
            }),
            { headers: { 'x-goog-hash': 'crc32c=AAAAAA==' } }
        )
    );
    await expect(failed.text()).rejects.toThrow('source');
});

it('rejects streaming responses without usable full-object checksums', () => {
    expect(() => verifyStorageStream(new Response('abc'))).toThrow();
    expect(() =>
        verifyStorageStream(
            new Response(null, {
                headers: { 'x-goog-hash': 'crc32c=AAAAAA==' }
            })
        )
    ).toThrow();
    expect(() =>
        verifyStorageStream(
            new Response('abc', {
                status: 206,
                headers: { 'x-goog-hash': 'crc32c=AAAAAA==' }
            })
        )
    ).toThrow();
});

it('checks accepted upload metadata and preserves generation details on failures', () => {
    const metadata = {
        name: 'file',
        bucket: 'bucket',
        generation: '7',
        size: '9'
    };
    verifyStorageUpload(undefined, metadata);
    verifyStorageUpload('4waSgw==', { ...metadata, crc32c: '4waSgw==' });
    expect(() => verifyStorageUpload('4waSgw==', metadata)).toThrow(
        expect.objectContaining({ code: 'storage/checksum-unavailable' })
    );
    expect(() =>
        verifyStorageUpload('4waSgw==', { ...metadata, crc32c: 'AAAAAA==' })
    ).toThrow(
        expect.objectContaining({
            code: 'storage/checksum-mismatch',
            context: expect.objectContaining({ generation: '7' })
        })
    );
});

it.each([
    '123456789',
    new Blob(['123456789']),
    new TextEncoder().encode('123456789'),
    new TextEncoder().encode('123456789').buffer
])(
    'calculates the standard CRC32C vector for web upload types',
    async (input) => {
        const checksum = await calculateStorageCrc32c(input);
        expect(checksum).toBe('4waSgw==');
    }
);
it('handles empty input and sliced typed arrays without including surrounding bytes', async () => {
    const empty = await calculateStorageCrc32c('');
    const sliced = await calculateStorageCrc32c(
        new TextEncoder().encode('x123456789y').subarray(1, 10)
    );
    expect(empty).toBe('AAAAAA==');
    expect(sliced).toBe('4waSgw==');
    expect(storageUploadBlob('é').size).toBe(2);
});
it.each([null, {}, 123])('rejects unsupported upload data %j', (input) => {
    expect(() => storageUploadBlob(input as never)).toThrow();
});
it.each(['auto', '', 'AAAAAB==', 'AAAAAA=', 1])(
    'rejects noncanonical checksums %j',
    (value) => {
        expect(() => validateStorageCrc32c(value)).toThrow();
    }
);
it('accepts canonical checksums and verifies a full response with multiple hashes', async () => {
    validateStorageCrc32c('4waSgw==');
    await verifyStorageDownload(
        new TextEncoder().encode('123456789'),
        new Response(null, {
            headers: { 'x-goog-hash': 'md5=ignored, crc32c=4waSgw==' }
        })
    );
});
it('rejects corrupt downloaded bytes', async () => {
    await expect(
        verifyStorageDownload(
            new Uint8Array([1]),
            new Response(null, {
                headers: { 'x-goog-hash': 'crc32c=AAAAAA==' }
            })
        )
    ).rejects.toMatchObject({ code: 'storage/checksum-mismatch' });
});
it.each([
    {},
    { status: 206, headers: { 'x-goog-hash': 'crc32c=AAAAAA==' } },
    {
        headers: {
            'content-encoding': 'gzip',
            'x-goog-hash': 'crc32c=AAAAAA=='
        }
    }
])('refuses unavailable or unsuitable response checksums', async (init) => {
    await expect(
        verifyStorageDownload(new Uint8Array(), new Response(null, init))
    ).rejects.toMatchObject({ code: 'storage/checksum-unavailable' });
});
