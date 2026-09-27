import { expect, it } from 'vitest';
import { valueEquals } from './value-equality.js';
import { Timestamp } from './timestamp.js';
it('compares primitives, nested values, byte arrays and value classes', () => {
    expect(
        valueEquals(
            { a: [NaN, 1n], b: new Timestamp(1, 2) },
            { b: new Timestamp(1, 2), a: [NaN, 1n] }
        )
    ).toBe(true);
    expect(valueEquals(new Date(0), new Date(0))).toBe(true);
    expect(valueEquals(new Uint8Array([1]), new Uint8Array([1]))).toBe(true);
    for (const [a, b] of [
        [null, {}],
        [1, '1'],
        [[1], [2]],
        [{ a: 1 }, { b: 1 }],
        [new Date(0), new Date(1)],
        [new Uint8Array([1]), new Uint8Array([2])],
        [new Timestamp(1, 0), new Timestamp(2, 0)]
    ])
        expect(valueEquals(a, b)).toBe(false);
});
