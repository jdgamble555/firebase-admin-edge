import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import { StorageMd5 } from './storage-md5.js';

it.each([
    '',
    'a',
    'abc',
    'message digest',
    'abcdefghijklmnopqrstuvwxyz',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    '1234567890'.repeat(8),
    'é😀'.repeat(100)
])('matches independent MD5 for %s', (text) => {
    const bytes = new TextEncoder().encode(text);
    const hash = new StorageMd5();
    for (let offset = 0; offset < bytes.length; offset += 7) {
        hash.update(bytes.subarray(offset, offset + 7));
    }
    expect(hash.digest()).toBe(
        createHash('md5').update(bytes).digest('base64')
    );
    expect(hash.digest()).toBe(
        createHash('md5').update(bytes).digest('base64')
    );
});
it.each([55, 56, 63, 64, 65, 127, 128, 129, 1048576])(
    'handles padding and block boundaries at %i bytes',
    (size) => {
        const input = Uint8Array.from(
            { length: size + 3 },
            (_, index) => index % 251
        ).subarray(3);
        const hash = new StorageMd5();
        hash.update(input);
        const expected = createHash('md5').update(input).digest('base64');
        expect(hash.digest()).toBe(expected);
        hash.update(new Uint8Array([1]));
        expect(hash.digest()).toBe(
            createHash('md5')
                .update(input)
                .update(new Uint8Array([1]))
                .digest('base64')
        );
    }
);
it('rejects non-byte input', () => {
    expect(() => new StorageMd5().update('abc' as never)).toThrow(/bytes/);
});
