import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it } from 'vitest';
import { FieldValue } from './field-value.js';
it('creates typed write sentinels and validates increments', () => {
    expect(FieldValue.serverTimestamp().kind).toBe('serverTimestamp');
    expect(FieldValue.delete().kind).toBe('delete');
    expect(FieldValue.increment(2)).toMatchObject({
        kind: 'increment',
        operands: [2]
    });
    expect(FieldValue.arrayUnion('a', 'b')).toMatchObject({
        kind: 'arrayUnion',
        operands: ['a', 'b']
    });
    expect(FieldValue.arrayRemove('a')).toMatchObject({
        kind: 'arrayRemove',
        operands: ['a']
    });
    expect(FieldValue.arrayUnion().operands).toEqual([]);
    for (const value of [NaN, Infinity, '1', null])
        expect(() => FieldValue.increment(value as number)).toThrow(
            FirebaseEdgeError
        );
});
it('compares transform kinds and operands including maps and vectors', () => {
    expect(FieldValue.increment(1).isEqual(FieldValue.increment(1))).toBe(true);
    expect(FieldValue.increment(1).isEqual(FieldValue.increment(2))).toBe(
        false
    );
    expect(FieldValue.serverTimestamp().isEqual(FieldValue.delete())).toBe(
        false
    );
    expect(
        FieldValue.arrayUnion({ a: 1, b: 2 }).isEqual(
            FieldValue.arrayUnion({ b: 2, a: 1 })
        )
    ).toBe(true);
    expect(FieldValue.delete().isEqual(null)).toBe(false);
    expect(FieldValue.vector([1]).toArray()).toEqual([1]);
    expect(FieldValue.vector().toArray()).toEqual([]);
});

it('supports numeric extrema including nonfinite operands and rejects nonnumbers', () => {
    for (const kind of ['minimum', 'maximum'] as const) {
        for (const value of [0, -0, -2, 3.5, NaN, Infinity, -Infinity]) {
            const transform = FieldValue[kind](value);
            expect(transform.kind).toBe(kind);
            expect(transform.operands).toEqual([value]);
            expect(transform.isEqual(FieldValue[kind](value))).toBe(true);
        }
        expect(() => FieldValue[kind]('1' as never)).toThrow(FirebaseEdgeError);
    }
});
