import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it } from 'vitest';
import { Timestamp } from './timestamp.js';
import { GeoPoint } from './geo-point.js';
import { Bytes } from './bytes.js';
import { Firestore } from './firestore.js';
import { Filter } from './filter.js';
import { FieldPath } from './field-path.js';
import type { ServiceAccount } from '../auth/firebase-types.js';

it('encodes value classes and document references', () => {
    expect(encodeValue(new Timestamp(0, 1))).toEqual({
        timestampValue: '1970-01-01T00:00:00.000000001Z'
    });
    expect(encodeValue(new GeoPoint(1, 2))).toEqual({
        geoPointValue: { latitude: 1, longitude: 2 }
    });
    expect(encodeValue(Bytes.fromBase64String('AA=='))).toEqual({
        bytesValue: 'AA=='
    });
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    expect(encodeValue(db.doc('users/a'))).toEqual({
        referenceValue: 'projects/p/databases/(default)/documents/users/a'
    });
});

it('encodes composite filters and document-ID values, arrays and cursors', () => {
    const parent = 'projects/p/databases/db/documents';
    const filter = Filter.or(
        Filter.where(FieldPath.documentId(), 'in', ['a', 'b']),
        Filter.where('active', '==', true)
    );
    const result = buildStructuredQuery(
        'users',
        {
            compositeFilters: [filter.node],
            orders: [{ field: '__name__', direction: 'asc' }],
            start: { before: true, values: [{ stringValue: 'a' }] }
        },
        parent
    );
    expect(result.startAt?.values).toEqual([
        { referenceValue: `${parent}/users/a` }
    ]);
    expect(result.where).toMatchObject({
        compositeFilter: {
            op: 'OR',
            filters: [
                {
                    fieldFilter: {
                        value: {
                            arrayValue: {
                                values: [
                                    { referenceValue: `${parent}/users/a` },
                                    { referenceValue: `${parent}/users/b` }
                                ]
                            }
                        }
                    }
                },
                { fieldFilter: { op: 'EQUAL' } }
            ]
        }
    });
    expect(() =>
        buildStructuredQuery(
            'users',
            {
                compositeFilters: [
                    Filter.where(FieldPath.documentId(), '==', 'bad/id').node
                ]
            },
            parent
        )
    ).toThrow('Document ID');
    const reference = `${parent}/users/a`;
    expect(
        buildStructuredQuery(
            'users',
            {
                filters: [
                    {
                        field: '__name__',
                        operator: '==',
                        value: { referenceValue: reference }
                    }
                ]
            },
            parent
        ).where
    ).toMatchObject({ fieldFilter: { value: { referenceValue: reference } } });
});
import {
    encodeValue,
    buildStructuredQuery,
    validateFieldPath,
    OPERATORS,
    normalizedOrders
} from './query-request.js';

it('adds inequality ordering and reverses limitToLast order and bounds', () => {
    const options = {
        filters: [
            {
                field: 'age',
                operator: '>' as const,
                value: { integerValue: '18' }
            }
        ],
        orders: [{ field: 'score', direction: 'desc' as const }],
        last: true,
        limit: 2,
        start: { before: true, values: [{ integerValue: '20' }] },
        end: { before: false, values: [{ integerValue: '30' }] }
    };
    expect(normalizedOrders(options)).toEqual([
        { field: 'score', direction: 'desc' },
        { field: 'age', direction: 'desc' },
        { field: '__name__', direction: 'desc' }
    ]);
    const query = buildStructuredQuery('users', options);
    expect(query.orderBy).toEqual([
        { field: { fieldPath: 'score' }, direction: 'ASCENDING' },
        { field: { fieldPath: 'age' }, direction: 'ASCENDING' },
        { field: { fieldPath: '__name__' }, direction: 'ASCENDING' }
    ]);
    expect(query.startAt).toEqual({
        before: true,
        values: [{ integerValue: '30' }]
    });
    expect(query.endAt).toEqual({
        before: false,
        values: [{ integerValue: '20' }]
    });
    expect(options.start.values[0]).toEqual({ integerValue: '20' });
});

it('encodes collection groups and their document-path filters', () => {
    const query = buildStructuredQuery(
        'posts',
        {
            allDescendants: true,
            filters: [
                {
                    field: '__name__',
                    operator: '==',
                    value: { stringValue: 'users/a/posts/b' }
                }
            ]
        },
        'projects/p/databases/db/documents'
    );
    expect(query.from).toEqual([
        { collectionId: 'posts', allDescendants: true }
    ]);
    expect(query.where).toMatchObject({
        fieldFilter: {
            value: {
                referenceValue:
                    'projects/p/databases/db/documents/users/a/posts/b'
            }
        }
    });
    expect(() =>
        buildStructuredQuery(
            'posts',
            {
                allDescendants: true,
                filters: [
                    {
                        field: '__name__',
                        operator: '==',
                        value: { stringValue: 'bad' }
                    }
                ]
            },
            'projects/p/databases/db/documents'
        )
    ).toThrow('document paths');
});

it('encodes primitive and nested values, dates, bytes and special numbers', () => {
    expect(
        encodeValue({
            str: 'x',
            bool: false,
            nil: null,
            int: 1,
            float: 1.5,
            nan: NaN,
            inf: Infinity,
            negative: -Infinity,
            date: new Date('2026-01-01'),
            bytes: new Uint8Array([0, 255]),
            list: [true]
        })
    ).toEqual({
        mapValue: {
            fields: {
                str: { stringValue: 'x' },
                bool: { booleanValue: false },
                nil: { nullValue: null },
                int: { integerValue: '1' },
                float: { doubleValue: 1.5 },
                nan: { doubleValue: 'NaN' },
                inf: { doubleValue: 'Infinity' },
                negative: { doubleValue: '-Infinity' },
                date: { timestampValue: '2026-01-01T00:00:00.000Z' },
                bytes: { bytesValue: 'AP8=' },
                list: { arrayValue: { values: [{ booleanValue: true }] } }
            }
        }
    });
    expect(encodeValue(1e21)).toEqual({ doubleValue: 1e21 });
    expect(encodeValue(-0)).toEqual({ doubleValue: -0 });
    expect(encodeValue(Object.create(null))).toEqual({
        mapValue: { fields: {} }
    });
});

it('rejects unsupported, cyclic and undefined values', () => {
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    for (const value of [
        undefined,
        () => {},
        Symbol(),
        9223372036854775808n,
        new Map(),
        new Date('bad'),
        cycle,
        [undefined],
        Array(1)
    ])
        expect(() => encodeValue(value)).toThrow(FirebaseEdgeError);
    const shared = { x: 1 };
    expect(() => encodeValue([shared, shared])).not.toThrow();
});

it('validates simple dotted fields and document IDs', () => {
    expect(() => validateFieldPath('profile.first_name')).not.toThrow();
    expect(() => validateFieldPath('__name__')).not.toThrow();
    for (const field of ['', 'a..b', '.a', 'a/b', 'a-b', null])
        expect(() => validateFieldPath(field as string)).toThrow(
            FirebaseEdgeError
        );
});

it('builds an unfiltered query and encodes every field operator', () => {
    expect(buildStructuredQuery('users', {})).toEqual({
        from: [{ collectionId: 'users' }]
    });
    for (const operator of Object.keys(OPERATORS) as Array<
        keyof typeof OPERATORS
    >) {
        expect(
            buildStructuredQuery('users', {
                filters: [
                    { field: 'age', operator, value: { integerValue: '1' } }
                ]
            }).where
        ).toEqual({
            fieldFilter: {
                field: { fieldPath: 'age' },
                op: OPERATORS[operator],
                value: { integerValue: '1' }
            }
        });
    }
});

it('uses unary filters for null/NaN equality and AND for multiple filters', () => {
    const result = buildStructuredQuery('users', {
        filters: [
            { field: 'a', operator: '==', value: { nullValue: null } },
            { field: 'b', operator: '!=', value: { nullValue: null } },
            { field: 'c', operator: '==', value: { doubleValue: 'NaN' } },
            { field: 'd', operator: '!=', value: { doubleValue: 'NaN' } }
        ]
    });
    expect(result.where).toEqual({
        compositeFilter: {
            op: 'AND',
            filters: ['IS_NULL', 'IS_NOT_NULL', 'IS_NAN', 'IS_NOT_NAN'].map(
                (op, i) => ({
                    unaryFilter: {
                        field: { fieldPath: ['a', 'b', 'c', 'd'][i] },
                        op
                    }
                })
            )
        }
    });
});

it('builds ordering, projection, limits, offsets and cursor bounds', () => {
    const start = { before: true, values: [{ integerValue: '1' }] };
    const end = { before: false, values: [{ integerValue: '2' }] };
    expect(
        buildStructuredQuery('users', {
            orders: [
                { field: 'a', direction: 'asc' },
                { field: 'b', direction: 'desc' }
            ],
            fields: ['a'],
            limit: 3,
            offset: 0,
            start,
            end
        })
    ).toEqual({
        from: [{ collectionId: 'users' }],
        orderBy: [
            { field: { fieldPath: 'a' }, direction: 'ASCENDING' },
            { field: { fieldPath: 'b' }, direction: 'DESCENDING' }
        ],
        select: { fields: [{ fieldPath: 'a' }] },
        limit: 3,
        offset: 0,
        startAt: start,
        endAt: end
    });
    expect(buildStructuredQuery('users', { fields: [] }).select).toEqual({
        fields: []
    });
});
it('omits undefined object properties inside arrays only when requested', () => {
    const value = [{ missing: undefined, present: 1 }];
    expect(encodeValue(value, new Set(), true)).toEqual({
        arrayValue: {
            values: [
                { mapValue: { fields: { present: { integerValue: '1' } } } }
            ]
        }
    });
    expect(() => encodeValue(value)).toThrow();
    expect(() => encodeValue([undefined], new Set(), true)).toThrow();
});
it('encodes int64 values and vector search stages', () => {
    expect(encodeValue(9223372036854775807n)).toEqual({
        integerValue: '9223372036854775807'
    });
    expect(encodeValue(-9223372036854775808n)).toEqual({
        integerValue: '-9223372036854775808'
    });
    const vector = encodeValue(FieldValue.vector([1, 2]));
    expect(vector).toEqual({
        mapValue: {
            fields: {
                __type__: { stringValue: '__vector__' },
                value: {
                    arrayValue: {
                        values: [{ doubleValue: 1 }, { doubleValue: 2 }]
                    }
                }
            }
        }
    });
    const nearest = {
        vectorField: { fieldPath: 'embedding' },
        queryVector: vector,
        limit: 10,
        distanceMeasure: 'COSINE' as const
    };
    expect(buildStructuredQuery('users', { nearest })).toMatchObject({
        findNearest: nearest
    });
});
import { FieldValue } from './field-value.js';
