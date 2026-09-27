import { expect, it } from 'vitest';
import {
    normalizeSnapshotDocument,
    normalizeSnapshotTimestamp
} from './firestore-document.js';

it('normalizes JSON and protobuf snapshot values to the same stored representation', () => {
    const time = '1970-01-01T00:00:05.000000006Z';
    const protoTime = { seconds: { toString: () => '5' }, nanos: 6 };
    const fields = {
        null: { nullValue: null },
        bool: { booleanValue: false },
        text: { stringValue: '' },
        integer: { integerValue: '9223372036854775807' },
        double: { doubleValue: 1.5 },
        nan: { doubleValue: 'NaN' },
        infinity: { doubleValue: 'Infinity' },
        bytes: { bytesValue: 'AQI=' },
        time: { timestampValue: time },
        point: { geoPointValue: { latitude: 0, longitude: 0 } },
        ref: { referenceValue: 'projects/p/databases/db/documents/users/a' },
        nested: {
            arrayValue: {
                values: [{ mapValue: { fields: { n: { integerValue: '3' } } } }]
            }
        },
        emptyArray: { arrayValue: {} },
        emptyMap: { mapValue: {} }
    };
    const json = {
        name: 'projects/p/databases/db/documents/users/a',
        fields,
        createTime: time,
        updateTime: time
    };
    const expected = normalizeSnapshotDocument(json, 'json');
    const proto = normalizeSnapshotDocument(
        {
            ...json,
            createTime: protoTime,
            updateTime: protoTime,
            fields: {
                ...fields,
                null: { nullValue: 0 },
                time: { timestampValue: protoTime },
                integer: {
                    integerValue: { toString: () => '9223372036854775807' }
                },
                bytes: {
                    valueType: 'bytesValue',
                    bytesValue: new Uint8Array([1, 2])
                },
                point: { geoPointValue: {} },
                nested: {
                    arrayValue: {
                        values: [
                            { mapValue: { fields: { n: { integerValue: 3 } } } }
                        ]
                    }
                }
            }
        },
        'protobufJS'
    );
    expect(proto).toEqual(expected);
    expect(normalizeSnapshotTimestamp(time, 'json')).toEqual(
        new Timestamp(5, 6)
    );
    expect(normalizeSnapshotTimestamp({}, 'protobufJS')).toEqual(
        new Timestamp(0, 0)
    );
    expect(
        normalizeSnapshotDocument({ ...json, fields: undefined }, 'json').fields
    ).toEqual({});
    fields.nested.arrayValue.values[0]!.mapValue.fields.n.integerValue = '9';
    expect(expected.fields?.nested).toEqual({
        arrayValue: {
            values: [{ mapValue: { fields: { n: { integerValue: '3' } } } }]
        }
    });
});

it.each([
    {},
    { stringValue: 'a', integerValue: '1' },
    { valueType: 'bytesValue', stringValue: 'a' },
    null,
    [],
    { integerValue: '9223372036854775808' },
    { integerValue: 9007199254740992 },
    { integerValue: 1.5 },
    { integerValue: true },
    { integerValue: {} },
    { timestampValue: 'invalid' },
    { bytesValue: '!' },
    { booleanValue: 1 },
    { stringValue: 1 },
    { doubleValue: 'bad' },
    { nullValue: 'bad' },
    { referenceValue: 'users/a' },
    { geoPointValue: false },
    { geoPointValue: { latitude: 91 } },
    { arrayValue: { values: false } },
    { arrayValue: [] },
    { mapValue: { fields: [] } }
])('rejects malformed raw snapshot values: %j', (value) => {
    expect(() =>
        normalizeSnapshotDocument(
            {
                name: 'projects/p/databases/db/documents/users/a',
                fields: { value },
                createTime: {},
                updateTime: {}
            },
            'protobufJS'
        )
    ).toThrow();
});

it('guards snapshot metadata and cyclic containers and preserves special field names', () => {
    for (const input of [null, [], {}, { name: 1 }])
        expect(() =>
            normalizeSnapshotDocument(input as never, 'json')
        ).toThrow();
    for (const input of [
        null,
        [],
        'bad',
        { seconds: 'bad' },
        { seconds: 253402300800 },
        { nanos: -1 },
        { nanos: 1e9 },
        { nanos: '1' }
    ])
        expect(() => normalizeSnapshotTimestamp(input, 'protobufJS')).toThrow();
    expect(() =>
        normalizeSnapshotTimestamp('2026-02-30T00:00:00Z', 'json')
    ).toThrow();
    const cyclic: Record<string, unknown> = {};
    cyclic.loop = { mapValue: { fields: cyclic } };
    expect(() =>
        normalizeSnapshotDocument(
            { name: 'n', fields: cyclic, createTime: {}, updateTime: {} },
            'protobufJS'
        )
    ).toThrow('circular');
    const fields = JSON.parse('{"__proto__":{"stringValue":"safe"}}');
    const result = normalizeSnapshotDocument(
        { name: 'n', fields, createTime: {}, updateTime: {} },
        'protobufJS'
    );
    expect(Object.hasOwn(result.fields!, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(result.fields!)).toBe(Object.prototype);
});
import { Timestamp } from './timestamp.js';
import { Bytes } from './bytes.js';
import { GeoPoint } from './geo-point.js';
import {
    decodeFields,
    decodeValue,
    type FirestoreValue
} from './firestore-document.js';

it('decodes all REST value types recursively', () => {
    expect(
        decodeFields({
            text: { stringValue: 'hello' },
            nil: { nullValue: null },
            bool: { booleanValue: false },
            integer: { integerValue: '42' },
            double: { doubleValue: 1.5 },
            nan: { doubleValue: 'NaN' },
            infinity: { doubleValue: 'Infinity' },
            time: { timestampValue: '2026-01-01T00:00:00Z' },
            bytes: { bytesValue: 'AP8=' },
            reference: {
                referenceValue:
                    'projects/p/databases/(default)/documents/users/a'
            },
            point: { geoPointValue: { latitude: 1, longitude: 2 } },
            list: {
                arrayValue: {
                    values: [
                        {
                            mapValue: {
                                fields: { nested: { integerValue: '3' } }
                            }
                        }
                    ]
                }
            }
        })
    ).toEqual({
        text: 'hello',
        nil: null,
        bool: false,
        integer: 42,
        double: 1.5,
        nan: NaN,
        infinity: Infinity,
        time: Timestamp.fromDate(new Date('2026-01-01T00:00:00Z')),
        bytes: Bytes.fromUint8Array(new Uint8Array([0, 255])),
        reference: 'projects/p/databases/(default)/documents/users/a',
        point: new GeoPoint(1, 2),
        list: [{ nested: 3 }]
    });
});

it('handles empty fields, arrays and maps', () => {
    expect(decodeFields()).toEqual({});
    expect(decodeValue({ arrayValue: {} })).toEqual([]);
    expect(decodeValue({ mapValue: {} })).toEqual({});
});

it('preserves special field names and rejects unknown value types', () => {
    const result = decodeFields(
        JSON.parse('{"__proto__":{"stringValue":"safe"}}')
    );
    expect(Object.hasOwn(result, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(result)).toBe(Object.prototype);
    expect(() => decodeValue({} as FirestoreValue)).toThrow('Unsupported');
    expect(() => decodeValue({} as FirestoreValue)).toThrow(
        expect.objectContaining({
            code: 'firestore/internal',
            name: 'FirebaseEdgeError'
        })
    );
});
it('decodes vector map values without exposing the wire representation', () => {
    const value = decodeValue({
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
    expect(value).toBeInstanceOf(VectorValue);
    expect((value as VectorValue).toArray()).toEqual([1, 2]);
    expect(() =>
        decodeValue({
            mapValue: { fields: { __type__: { stringValue: '__vector__' } } }
        })
    ).toThrow();
});
import { VectorValue } from './vector-value.js';
