import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { FirestoreValue } from './firestore-document.js';
import { Timestamp } from './timestamp.js';
import { VectorValue } from './vector-value.js';
import { GeoPoint } from './geo-point.js';
import { Bytes } from './bytes.js';
import { DocumentReference } from './document-reference.js';
import type { FilterNode } from './filter.js';

export const OPERATORS = {
    '<': 'LESS_THAN',
    '<=': 'LESS_THAN_OR_EQUAL',
    '==': 'EQUAL',
    '!=': 'NOT_EQUAL',
    '>=': 'GREATER_THAN_OR_EQUAL',
    '>': 'GREATER_THAN',
    'array-contains': 'ARRAY_CONTAINS',
    in: 'IN',
    'not-in': 'NOT_IN',
    'array-contains-any': 'ARRAY_CONTAINS_ANY'
} as const;
export type WhereFilterOp = keyof typeof OPERATORS;
export interface QueryOptions {
    alwaysUseImplicitOrderBy?: boolean;
    nearest?: {
        vectorField: { fieldPath: string };
        queryVector: FirestoreValue;
        limit: number;
        distanceMeasure: 'EUCLIDEAN' | 'COSINE' | 'DOT_PRODUCT';
        distanceResultField?: string;
        distanceThreshold?: number;
    };
    allDescendants?: boolean;
    last?: boolean;
    compositeFilters?: FilterNode[];
    filters?: {
        field: string;
        operator: WhereFilterOp;
        value: FirestoreValue;
    }[];
    orders?: { field: string; direction: 'asc' | 'desc' }[];
    limit?: number;
    offset?: number;
    fields?: string[];
    start?: { values: FirestoreValue[]; before: boolean };
    end?: { values: FirestoreValue[]; before: boolean };
}

/** String field paths support dot-separated simple identifiers. */
export function validateFieldPath(field: string): void {
    if (
        typeof field !== 'string' ||
        !/^[A-Za-z_][A-Za-z_0-9]*(\.[A-Za-z_][A-Za-z_0-9]*)*$/.test(field)
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Expected a dot-separated Firestore field path.'
        });
}

export function encodeValue(
    value: unknown,
    ancestors = new Set<object>(),
    ignoreUndefinedProperties = false
): FirestoreValue {
    if (value instanceof VectorValue)
        return {
            mapValue: {
                fields: {
                    __type__: { stringValue: '__vector__' },
                    value: {
                        arrayValue: {
                            values: value
                                .toArray()
                                .map((number) => ({ doubleValue: number }))
                        }
                    }
                }
            }
        };
    if (typeof value === 'bigint') {
        if (value < -9223372036854775808n || value > 9223372036854775807n)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Firestore integers must fit signed 64 bits.'
            });
        return { integerValue: String(value) };
    }
    if (value instanceof Timestamp) return { timestampValue: value.toString() };
    if (value instanceof GeoPoint) return { geoPointValue: value.toJSON() };
    if (value instanceof Bytes) return { bytesValue: value.toBase64() };
    if (value instanceof DocumentReference)
        return { referenceValue: value.firestore._documentName(value.path) };
    if (value === null) return { nullValue: null };
    if (typeof value === 'string') return { stringValue: value };
    if (typeof value === 'boolean') return { booleanValue: value };
    if (typeof value === 'number') {
        if (Number.isSafeInteger(value) && !Object.is(value, -0))
            return { integerValue: String(value) };
        return { doubleValue: Number.isFinite(value) ? value : String(value) };
    }
    if (value instanceof Date) {
        if (!Number.isFinite(value.getTime()))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid query date.'
            });
        return { timestampValue: value.toISOString() };
    }
    if (value instanceof Uint8Array)
        return {
            bytesValue: btoa(
                Array.from(value, (byte) => String.fromCharCode(byte)).join('')
            )
        };
    if (typeof value !== 'object' || !value)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Unsupported Firestore query value.'
        });
    if (ancestors.has(value))
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Circular query values are not supported.'
        });
    if (
        !Array.isArray(value) &&
        Object.getPrototypeOf(value) !== Object.prototype &&
        Object.getPrototypeOf(value) !== null
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Query maps must be plain objects.'
        });
    const next = new Set(ancestors).add(value);
    if (Array.isArray(value))
        return {
            arrayValue: {
                values: Array.from(value, (item) =>
                    encodeValue(item, next, ignoreUndefinedProperties)
                )
            }
        };
    return {
        mapValue: {
            fields: Object.fromEntries(
                Object.entries(value)
                    .filter(
                        ([, item]) =>
                            !ignoreUndefinedProperties || item !== undefined
                    )
                    .map(([key, item]) => [
                        key,
                        encodeValue(item, next, ignoreUndefinedProperties)
                    ])
            )
        }
    };
}

/** Convert immutable query state to the Firestore REST structured query. */
export function buildStructuredQuery(
    collectionId: string,
    options: QueryOptions,
    parentName?: string
) {
    if (options.alwaysUseImplicitOrderBy)
        options = { ...options, orders: normalizedOrders(options) };
    if (options.last) {
        const orders = normalizedOrders(options).map((order) => ({
            ...order,
            direction:
                order.direction === 'asc' ? ('desc' as const) : ('asc' as const)
        }));
        options = {
            ...options,
            last: false,
            orders,
            start: options.end
                ? { ...options.end, before: !options.end.before }
                : undefined,
            end: options.start
                ? { ...options.start, before: !options.start.before }
                : undefined
        };
    }
    const collectionName = options.allDescendants
        ? parentName
        : parentName
          ? `${parentName}/${collectionId}`
          : undefined;
    const filters = [
        ...(options.filters ?? []),
        ...(options.compositeFilters ?? [])
    ].map((filter) =>
        encodeFilter(filter, collectionName, options.allDescendants)
    );
    return {
        ...(options.nearest ? { findNearest: options.nearest } : {}),
        from: [
            {
                collectionId,
                ...(options.allDescendants ? { allDescendants: true } : {})
            }
        ],
        ...(filters.length
            ? {
                  where:
                      filters.length === 1
                          ? filters[0]
                          : { compositeFilter: { op: 'AND', filters } }
              }
            : {}),
        ...(options.orders
            ? {
                  orderBy: options.orders.map((order) => ({
                      field: { fieldPath: order.field },
                      direction:
                          order.direction === 'asc' ? 'ASCENDING' : 'DESCENDING'
                  }))
              }
            : {}),
        ...(options.limit !== undefined ? { limit: options.limit } : {}),
        ...(options.offset !== undefined ? { offset: options.offset } : {}),
        ...(options.fields
            ? {
                  select: {
                      fields: options.fields.map((fieldPath) => ({ fieldPath }))
                  }
              }
            : {}),
        ...(options.start
            ? {
                  startAt: encodeCursor(options.start, options, collectionName)
              }
            : {}),
        ...(options.end
            ? {
                  endAt: encodeCursor(options.end, options, collectionName)
              }
            : {})
    };
}

function encodeCursor(
    cursor: NonNullable<QueryOptions['start']>,
    options: QueryOptions,
    collectionName?: string
) {
    return {
        ...cursor,
        values: cursor.values.map((value, index) =>
            options.orders?.[index]?.field === '__name__'
                ? encodeDocumentId(
                      value,
                      collectionName,
                      options.allDescendants
                  )
                : value
        )
    };
}

function encodeDocumentId(
    value: FirestoreValue,
    collectionName?: string,
    allDescendants = false
): FirestoreValue {
    if ('arrayValue' in value)
        return {
            arrayValue: {
                values: value.arrayValue.values?.map((item) =>
                    encodeDocumentId(item, collectionName, allDescendants)
                )
            }
        };
    if ('referenceValue' in value) return value;
    if (
        !('stringValue' in value) ||
        !value.stringValue ||
        (!allDescendants && value.stringValue.includes('/')) ||
        !collectionName
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message:
                'Document ID filters require a document ID or DocumentReference.'
        });
    if (
        allDescendants &&
        (value.stringValue.split('/').length % 2 !== 0 ||
            value.stringValue
                .split('/')
                .some(
                    (segment) => !segment || segment === '.' || segment === '..'
                ))
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Collection group document IDs must be document paths.'
        });
    return { referenceValue: `${collectionName}/${value.stringValue}` };
}

function encodeFilter(
    filter: FilterNode,
    collectionName?: string,
    allDescendants = false
): unknown {
    if ('filters' in filter)
        return {
            compositeFilter: {
                op: filter.op,
                filters: filter.filters.map((child) =>
                    encodeFilter(child, collectionName, allDescendants)
                )
            }
        };
    const { field, operator } = filter;
    const value =
        field === '__name__'
            ? encodeDocumentId(filter.value, collectionName, allDescendants)
            : filter.value;
    const special =
        'nullValue' in value
            ? 'NULL'
            : 'doubleValue' in value && value.doubleValue === 'NaN'
              ? 'NAN'
              : undefined;
    if (special && (operator === '==' || operator === '!='))
        return {
            unaryFilter: {
                field: { fieldPath: field },
                op: `IS_${operator === '!=' ? 'NOT_' : ''}${special}`
            }
        };
    return {
        fieldFilter: {
            field: { fieldPath: field },
            op: OPERATORS[operator],
            value
        }
    };
}

/** @internal Match Firestore's implicit inequality and document-name ordering. */
export function normalizedOrders(
    options: QueryOptions
): NonNullable<QueryOptions['orders']> {
    const orders = [...(options.orders ?? [])];
    const direction = orders.at(-1)?.direction ?? 'asc';
    const fields = new Set<string>();
    function collect(filter: FilterNode): void {
        if ('filters' in filter) {
            filter.filters.forEach(collect);
            return;
        }
        if (['<', '<=', '>', '>=', '!=', 'not-in'].includes(filter.operator))
            fields.add(filter.field);
    }
    [...(options.filters ?? []), ...(options.compositeFilters ?? [])].forEach(
        collect
    );
    for (const field of [...fields].sort())
        if (
            field !== '__name__' &&
            !orders.some((order) => order.field === field)
        )
            orders.push({ field, direction });
    if (!orders.some((order) => order.field === '__name__'))
        orders.push({ field: '__name__', direction });
    return orders;
}
