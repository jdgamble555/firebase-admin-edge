import { expect, it } from 'vitest';
import { VectorValue } from './vector-value.js';
import { FieldValue } from './field-value.js';
it('copies vector inputs and outputs and compares values', () => {
    const values = [1, 2];
    const vector = FieldValue.vector(values);
    values[0] = 3;
    vector.toArray()[1] = 4;
    expect(vector.toArray()).toEqual([1, 2]);
    expect(vector.isEqual(new VectorValue([1, 2]))).toBe(true);
    expect(vector.isEqual(new VectorValue([1]))).toBe(false);
    expect(vector.isEqual([1, 2])).toBe(false);
});
it.each([undefined, [NaN], [Infinity], ['1'], Array(1), Array(2049).fill(0)])(
    'rejects invalid vectors',
    (values) => {
        expect(() => new VectorValue(values as number[])).toThrow();
    }
);
