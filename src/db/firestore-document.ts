import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { Timestamp } from './timestamp.js';
import { GeoPoint } from './geo-point.js';
import { Bytes } from './bytes.js';
import { VectorValue } from './vector-value.js';
import type { Firestore } from './firestore.js';
export type DocumentData = Record<string, unknown>;

export type FirestoreValue =
    | { nullValue: null }
    | { booleanValue: boolean }
    | { integerValue: string }
    | { doubleValue: number | string }
    | { timestampValue: string }
    | { stringValue: string }
    | { bytesValue: string }
    | { referenceValue: string }
    | { geoPointValue: { latitude: number; longitude: number } }
    | { arrayValue: { values?: FirestoreValue[] } }
    | { mapValue: { fields?: Record<string, FirestoreValue> } };

export interface FirestoreDocument {
    name: string;
    fields?: Record<string, FirestoreValue>;
    createTime?: string;
    updateTime?: string;
    readTime?: string;
    /** @internal A missing document returned by batchGet, with server read time. */
    missing?: boolean;
}

export type SnapshotTimestamp =
    | string
    | {
          seconds?: number | string | { toString(): string } | null;
          nanos?: number | null;
      };
export interface SnapshotDocument {
    name?: string | null;
    fields?: Record<string, unknown> | null;
    createTime?: SnapshotTimestamp | null;
    updateTime?: SnapshotTimestamp | null;
}

/** @internal Normalize raw snapshot metadata without losing nanoseconds. */
export function normalizeSnapshotTimestamp(
    value: unknown,
    encoding: 'json' | 'protobufJS'
): Timestamp {
    if (typeof value === 'string' && encoding === 'json')
        return Timestamp.fromString(value);
    if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Invalid snapshot timestamp.'
        });
    const proto = value as { seconds?: unknown; nanos?: unknown };
    const seconds = snapshotInteger(proto.seconds ?? 0);
    return new Timestamp(Number(seconds), (proto.nanos ?? 0) as number);
}

/** @internal Capture JSON/protobuf documents in the existing REST representation. */
export function normalizeSnapshotDocument(
    document: SnapshotDocument,
    encoding: 'json' | 'protobufJS'
): FirestoreDocument {
    if (
        !document ||
        typeof document !== 'object' ||
        Array.isArray(document) ||
        typeof document.name !== 'string'
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Expected a snapshot document with a resource name.'
        });
    return {
        name: document.name,
        fields: normalizeSnapshotFields(
            document.fields ?? {},
            encoding,
            new Set()
        ),
        createTime: normalizeSnapshotTimestamp(
            document.createTime,
            encoding
        ).toString(),
        updateTime: normalizeSnapshotTimestamp(
            document.updateTime,
            encoding
        ).toString()
    };
}

function snapshotInteger(value: unknown): string {
    if (
        (typeof value !== 'number' &&
            typeof value !== 'string' &&
            (!value || typeof value !== 'object')) ||
        (typeof value === 'number' && !Number.isSafeInteger(value))
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message:
                'Invalid snapshot integer; use text for integers beyond safe number precision.'
        });
    const text = String(value);
    if (
        !/^-?\d+$/.test(text) ||
        BigInt(text) < -(1n << 63n) ||
        BigInt(text) >= 1n << 63n
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Snapshot integer is outside the signed 64-bit range.'
        });
    return text;
}

function normalizeSnapshotFields(
    fields: unknown,
    encoding: 'json' | 'protobufJS',
    ancestors: Set<object>
): Record<string, FirestoreValue> {
    if (
        !fields ||
        typeof fields !== 'object' ||
        Array.isArray(fields) ||
        ancestors.has(fields)
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Invalid or circular snapshot fields.'
        });
    const next = new Set(ancestors).add(fields);
    return Object.fromEntries(
        Object.entries(fields).map(([key, value]) => [
            key,
            normalizeSnapshotValue(value, encoding, next)
        ])
    );
}

function normalizeSnapshotValue(
    input: unknown,
    encoding: 'json' | 'protobufJS',
    ancestors: Set<object>
): FirestoreValue {
    if (
        !input ||
        typeof input !== 'object' ||
        Array.isArray(input) ||
        ancestors.has(input)
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Invalid or circular snapshot value.'
        });
    const value = input as Record<string, unknown>;
    const keys = [
        'nullValue',
        'booleanValue',
        'integerValue',
        'doubleValue',
        'timestampValue',
        'stringValue',
        'bytesValue',
        'referenceValue',
        'geoPointValue',
        'arrayValue',
        'mapValue'
    ].filter(
        (key) =>
            Object.hasOwn(value, key) &&
            (key === 'nullValue' || value[key] != null)
    );
    if (
        keys.length !== 1 ||
        (value.valueType !== undefined && value.valueType !== keys[0])
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Expected exactly one Firestore value type.'
        });
    const key = keys[0]!;
    const raw = value[key];
    const next = new Set(ancestors).add(input);
    if (key === 'integerValue') return { integerValue: snapshotInteger(raw) };
    if (key === 'timestampValue')
        return {
            timestampValue: normalizeSnapshotTimestamp(raw, encoding).toString()
        };
    if (key === 'bytesValue') {
        const bytes =
            raw instanceof Uint8Array
                ? Bytes.fromUint8Array(raw)
                : Bytes.fromBase64String(raw as string);
        return { bytesValue: bytes.toBase64() };
    }
    if (key === 'arrayValue' || key === 'mapValue') {
        if (
            !raw ||
            typeof raw !== 'object' ||
            Array.isArray(raw) ||
            next.has(raw)
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid snapshot container.'
            });
        next.add(raw);
        if (key === 'mapValue')
            return {
                mapValue: {
                    fields: normalizeSnapshotFields(
                        (raw as { fields?: unknown }).fields ?? {},
                        encoding,
                        next
                    )
                }
            };
        const values = (raw as { values?: unknown }).values ?? [];
        if (!Array.isArray(values))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected snapshot array values.'
            });
        return {
            arrayValue: {
                values: values.map((item) =>
                    normalizeSnapshotValue(item, encoding, next)
                )
            }
        };
    }
    if (key === 'geoPointValue') {
        if (!raw || typeof raw !== 'object')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid snapshot geopoint.'
            });
        const point = raw as { latitude?: number; longitude?: number };
        const validated = new GeoPoint(
            point.latitude ?? 0,
            point.longitude ?? 0
        );
        return {
            geoPointValue: {
                latitude: validated.latitude,
                longitude: validated.longitude
            }
        };
    }
    if (
        key === 'nullValue' &&
        (raw === null || raw === 0 || raw === 'NULL_VALUE')
    )
        return { nullValue: null };
    if (key === 'booleanValue' && typeof raw === 'boolean')
        return { booleanValue: raw };
    if (key === 'stringValue' && typeof raw === 'string')
        return { stringValue: raw };
    if (
        key === 'referenceValue' &&
        typeof raw === 'string' &&
        /^projects\/[^/]+\/databases\/[^/]+\/documents\/.+/.test(raw)
    )
        return { referenceValue: raw };
    if (
        key === 'doubleValue' &&
        (typeof raw === 'number' ||
            ['NaN', 'Infinity', '-Infinity'].includes(raw as string))
    )
        return { doubleValue: raw as number | string };
    throw new FirebaseEdgeError({
        ...FirestoreErrorInfo.INVALID_ARGUMENT,
        message: 'Invalid snapshot field value.'
    });
}

/** Decode REST fields without invoking setters for user-controlled field names. */
export function decodeFields(
    fields: Record<string, FirestoreValue> = {},
    firestore?: Firestore
): DocumentData {
    return Object.fromEntries(
        Object.entries(fields).map(([key, value]) => [
            key,
            decodeValue(value, firestore)
        ])
    );
}

export function decodeValue(
    value: FirestoreValue,
    firestore?: Firestore
): unknown {
    if ('nullValue' in value) return null;
    if ('booleanValue' in value) return value.booleanValue;
    if ('integerValue' in value)
        return firestore?._useBigInt
            ? BigInt(value.integerValue)
            : Number(value.integerValue);
    if ('doubleValue' in value) return Number(value.doubleValue);
    if ('timestampValue' in value)
        return Timestamp.fromString(value.timestampValue);
    if ('stringValue' in value) return value.stringValue;
    if ('bytesValue' in value) return Bytes.fromBase64String(value.bytesValue);
    if ('referenceValue' in value)
        return firestore
            ? firestore._reference(value.referenceValue)
            : value.referenceValue;
    if ('geoPointValue' in value)
        return new GeoPoint(
            value.geoPointValue.latitude,
            value.geoPointValue.longitude
        );
    if ('arrayValue' in value)
        return (value.arrayValue.values ?? []).map((item) =>
            decodeValue(item, firestore)
        );
    if ('mapValue' in value) {
        const fields = value.mapValue.fields;
        if (
            fields?.__type__ &&
            'stringValue' in fields.__type__ &&
            fields.__type__.stringValue === '__vector__'
        ) {
            const vector = fields.value;
            if (!vector || !('arrayValue' in vector))
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.INVALID_RESPONSE,
                    message: 'Invalid vector value.'
                });
            return new VectorValue(
                (vector.arrayValue.values ?? []).map((item) => {
                    if (!('doubleValue' in item) && !('integerValue' in item))
                        throw new FirebaseEdgeError({
                            ...FirestoreErrorInfo.INVALID_RESPONSE,
                            message: 'Invalid vector component.'
                        });
                    return Number(decodeValue(item));
                })
            );
        }
        return decodeFields(fields, firestore);
    }
    throw new FirebaseEdgeError({
        ...FirestoreErrorInfo.INVALID_RESPONSE,
        message: 'Unsupported Firestore value.'
    });
}
