import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it } from 'vitest';
import { Filter } from './filter.js';
import { FieldPath } from './field-path.js';
it('builds nested AND/OR filters and captures values', () => {
    const data = ['a'];
    const a = Filter.where(new FieldPath('a.b'), 'in', data);
    data.push('b');
    expect(a.node).toEqual({
        field: '`a.b`',
        operator: 'in',
        value: { arrayValue: { values: [{ stringValue: 'a' }] } }
    });
    const b = Filter.where('age', '>', 18);
    expect(Filter.and(a, Filter.or(a, b)).node).toMatchObject({
        op: 'AND',
        filters: [a.node, { op: 'OR', filters: [a.node, b.node] }]
    });
});
it('rejects invalid filters', () => {
    expect(() => Filter.and()).toThrow(FirebaseEdgeError);
    expect(() => Filter.or({} as never)).toThrow(FirebaseEdgeError);
    expect(() => Filter.where('', '==', 1)).toThrow(FirebaseEdgeError);
    expect(() => Filter.where('x', 'bad' as never, 1)).toThrow(
        FirebaseEdgeError
    );
    for (const op of ['in', 'not-in', 'array-contains-any'] as const) {
        for (const value of [[], 'x', Array(31).fill(1)])
            expect(() => Filter.where('x', op, value)).toThrow(
                FirebaseEdgeError
            );
    }
    expect(() => Filter.where('x', 'not-in', Array(11).fill(1))).toThrow(
        FirebaseEdgeError
    );
});
