import { encodeValue, validateFieldPath } from './query-request.js';
import { FieldPath } from './field-path.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';

export type PipelineValue = Record<string, unknown>;
export class Expression {
    constructor(readonly _value: PipelineValue) {}
    add(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('add', [this, ...values]);
    }
    subtract(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('subtract', [this, ...values]);
    }
    multiply(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('multiply', [this, ...values]);
    }
    divide(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('divide', [this, ...values]);
    }
    mod(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('mod', [this, ...values]);
    }
    equal(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('equal', [this, ...values]).asBoolean();
    }
    notEqual(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('not_equal', [
            this,
            ...values
        ]).asBoolean();
    }
    lessThan(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('less_than', [
            this,
            ...values
        ]).asBoolean();
    }
    lessThanOrEqual(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('less_than_or_equal', [
            this,
            ...values
        ]).asBoolean();
    }
    greaterThan(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('greater_than', [
            this,
            ...values
        ]).asBoolean();
    }
    greaterThanOrEqual(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('greater_than_or_equal', [
            this,
            ...values
        ]).asBoolean();
    }
    arrayConcat(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_concat', [this, ...values]);
    }
    arrayContains(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('array_contains', [
            this,
            ...values
        ]).asBoolean();
    }
    arrayContainsAll(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('array_contains_all', [
            this,
            ...values
        ]).asBoolean();
    }
    arrayContainsAny(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('array_contains_any', [
            this,
            ...values
        ]).asBoolean();
    }
    arrayFilter(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_filter', [this, ...values]);
    }
    arrayTransform(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_transform', [this, ...values]);
    }
    arrayTransformWithIndex(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_transform', [this, ...values]);
    }
    arraySlice(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_slice', [this, ...values]);
    }
    arrayReverse(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_reverse', [this, ...values]);
    }
    arrayLength(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_length', [this, ...values]);
    }
    arrayFirst(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_first', [this, ...values]);
    }
    arrayFirstN(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_first_n', [this, ...values]);
    }
    arrayLast(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_last', [this, ...values]);
    }
    arrayLastN(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_last_n', [this, ...values]);
    }
    arrayMaximum(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('maximum', [this, ...values]);
    }
    arrayMaximumN(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('maximum_n', [this, ...values]);
    }
    arrayMinimum(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('minimum', [this, ...values]);
    }
    arrayMinimumN(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('minimum_n', [this, ...values]);
    }
    arrayIndexOf(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_index_of', [
            this,
            ...values,
            'first'
        ]);
    }
    arrayLastIndexOf(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_index_of', [
            this,
            ...values,
            'last'
        ]);
    }
    arrayIndexOfAll(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_index_of_all', [this, ...values]);
    }
    equalAny(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('equal_any', [
            this,
            ...values
        ]).asBoolean();
    }
    notEqualAny(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('not_equal_any', [
            this,
            ...values
        ]).asBoolean();
    }
    exists(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('exists', [this, ...values]).asBoolean();
    }
    charLength(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('char_length', [this, ...values]);
    }
    like(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('like', [this, ...values]).asBoolean();
    }
    regexContains(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('regex_contains', [
            this,
            ...values
        ]).asBoolean();
    }
    regexFind(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('regex_find', [this, ...values]);
    }
    regexFindAll(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('regex_find_all', [this, ...values]);
    }
    regexMatch(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('regex_match', [
            this,
            ...values
        ]).asBoolean();
    }
    stringContains(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('string_contains', [
            this,
            ...values
        ]).asBoolean();
    }
    startsWith(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('starts_with', [
            this,
            ...values
        ]).asBoolean();
    }
    endsWith(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('ends_with', [
            this,
            ...values
        ]).asBoolean();
    }
    toLower(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('to_lower', [this, ...values]);
    }
    toUpper(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('to_upper', [this, ...values]);
    }
    trim(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('trim', [this, ...values]);
    }
    ltrim(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('ltrim', [this, ...values]);
    }
    rtrim(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('rtrim', [this, ...values]);
    }
    stringConcat(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('string_concat', [this, ...values]);
    }
    stringIndexOf(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('string_index_of', [this, ...values]);
    }
    stringRepeat(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('string_repeat', [this, ...values]);
    }
    stringReplaceAll(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('string_replace_all', [this, ...values]);
    }
    stringReplaceOne(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('string_replace_one', [this, ...values]);
    }
    concat(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('concat', [this, ...values]);
    }
    reverse(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('reverse', [this, ...values]);
    }
    byteLength(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('byte_length', [this, ...values]);
    }
    ceil(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('ceil', [this, ...values]);
    }
    floor(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('floor', [this, ...values]);
    }
    abs(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('abs', [this, ...values]);
    }
    exp(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('exp', [this, ...values]);
    }
    mapGet(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('map_get', [this, ...values]);
    }
    mapSet(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('map_set', [this, ...values]);
    }
    mapKeys(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('map_keys', [this, ...values]);
    }
    mapValues(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('map_values', [this, ...values]);
    }
    mapEntries(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('map_entries', [this, ...values]);
    }
    count(...values: unknown[]): AggregateFunction {
        return new AggregateFunction('count', [this, ...values]);
    }
    sum(...values: unknown[]): AggregateFunction {
        return new AggregateFunction('sum', [this, ...values]);
    }
    average(...values: unknown[]): AggregateFunction {
        return new AggregateFunction('average', [this, ...values]);
    }
    minimum(...values: unknown[]): AggregateFunction {
        return new AggregateFunction('minimum', [this, ...values]);
    }
    maximum(...values: unknown[]): AggregateFunction {
        return new AggregateFunction('maximum', [this, ...values]);
    }
    first(...values: unknown[]): AggregateFunction {
        return new AggregateFunction('first', [this, ...values]);
    }
    last(...values: unknown[]): AggregateFunction {
        return new AggregateFunction('last', [this, ...values]);
    }
    arrayAgg(...values: unknown[]): AggregateFunction {
        return new AggregateFunction('array_agg', [this, ...values]);
    }
    arrayAggDistinct(...values: unknown[]): AggregateFunction {
        return new AggregateFunction('array_agg_distinct', [this, ...values]);
    }
    countDistinct(...values: unknown[]): AggregateFunction {
        return new AggregateFunction('count_distinct', [this, ...values]);
    }
    logicalMaximum(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('maximum', [this, ...values]);
    }
    logicalMinimum(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('minimum', [this, ...values]);
    }
    vectorLength(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('vector_length', [this, ...values]);
    }
    cosineDistance(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('cosine_distance', [this, ...values]);
    }
    dotProduct(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('dot_product', [this, ...values]);
    }
    euclideanDistance(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('euclidean_distance', [this, ...values]);
    }
    unixMicrosToTimestamp(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('unix_micros_to_timestamp', [
            this,
            ...values
        ]);
    }
    timestampToUnixMicros(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('timestamp_to_unix_micros', [
            this,
            ...values
        ]);
    }
    unixMillisToTimestamp(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('unix_millis_to_timestamp', [
            this,
            ...values
        ]);
    }
    timestampToUnixMillis(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('timestamp_to_unix_millis', [
            this,
            ...values
        ]);
    }
    unixSecondsToTimestamp(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('unix_seconds_to_timestamp', [
            this,
            ...values
        ]);
    }
    timestampToUnixSeconds(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('timestamp_to_unix_seconds', [
            this,
            ...values
        ]);
    }
    timestampAdd(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('timestamp_add', [this, ...values]);
    }
    timestampSubtract(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('timestamp_subtract', [this, ...values]);
    }
    timestampDiff(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('timestamp_diff', [this, ...values]);
    }
    timestampExtract(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('timestamp_extract', [this, ...values]);
    }
    documentId(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('document_id', [this, ...values]);
    }
    parent(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('parent', [this, ...values]);
    }
    substring(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('substring', [this, ...values]);
    }
    arrayGet(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('array_get', [this, ...values]);
    }
    isError(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('is_error', [
            this,
            ...values
        ]).asBoolean();
    }
    ifError(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('if_error', [this, ...values]);
    }
    isAbsent(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('is_absent', [
            this,
            ...values
        ]).asBoolean();
    }
    mapRemove(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('map_remove', [this, ...values]);
    }
    mapMerge(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('map_merge', [this, ...values]);
    }
    pow(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('pow', [this, ...values]);
    }
    trunc(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('trunc', [this, ...values]);
    }
    round(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('round', [this, ...values]);
    }
    collectionId(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('collection_id', [this, ...values]);
    }
    length(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('length', [this, ...values]);
    }
    ln(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('ln', [this, ...values]);
    }
    sqrt(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('sqrt', [this, ...values]);
    }
    stringReverse(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('string_reverse', [this, ...values]);
    }
    ifAbsent(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('if_absent', [this, ...values]);
    }
    ifNull(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('if_null', [this, ...values]);
    }
    coalesce(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('coalesce', [this, ...values]);
    }
    join(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('join', [this, ...values]);
    }
    log10(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('log10', [this, ...values]);
    }
    arraySum(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('sum', [this, ...values]);
    }
    split(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('split', [this, ...values]);
    }
    timestampTruncate(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('timestamp_trunc', [this, ...values]);
    }
    type(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('type', [this, ...values]);
    }
    isType(...values: unknown[]): BooleanExpression {
        return new FunctionExpression('is_type', [this, ...values]).asBoolean();
    }
    getField(...values: unknown[]): FunctionExpression {
        return new FunctionExpression('get_field', [this, ...values]);
    }
    as(alias: string): AliasedExpression {
        return new AliasedExpression(this, alias);
    }
    ascending(): Ordering {
        return new Ordering(this, 'ascending');
    }
    descending(): Ordering {
        return new Ordering(this, 'descending');
    }
    asBoolean(): BooleanExpression {
        return new BooleanExpression(this._value);
    }
}
export class FunctionExpression extends Expression {
    constructor(name: string, params: readonly unknown[]) {
        if (typeof name !== 'string' || !name || !Array.isArray(params))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected a function name and arguments.'
            });
        super({
            functionValue: { name, args: params.map(encodePipelineValue) }
        });
    }
}
export class BooleanExpression extends Expression {
    not(): BooleanExpression {
        return new FunctionExpression('not', [this]).asBoolean();
    }
}
export class AggregateFunction extends FunctionExpression {
    override as(alias: string): AliasedAggregate {
        return new AliasedAggregate(this, alias);
    }
}
export class Field extends Expression {
    constructor(readonly fieldPath: string | FieldPath) {
        if (!(fieldPath instanceof FieldPath)) validateFieldPath(fieldPath);
        super({ fieldReferenceValue: fieldPath.toString() });
    }
}
export class Constant extends Expression {
    constructor(value: unknown) {
        super(encodeValue(value));
    }
}
export class AliasedExpression {
    constructor(
        readonly expr: Expression,
        readonly alias: string
    ) {
        if (
            !(expr instanceof Expression) ||
            typeof alias !== 'string' ||
            !alias
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected an expression and nonempty alias.'
            });
    }
}
export class AliasedAggregate extends AliasedExpression {}
export class Ordering {
    constructor(
        readonly expr: Expression,
        readonly direction: 'ascending' | 'descending'
    ) {
        if (
            !(expr instanceof Expression) ||
            !['ascending', 'descending'].includes(direction)
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid pipeline ordering.'
            });
    }
}
export function field(path: string | FieldPath): Field {
    return new Field(path);
}
export function constant(value: unknown): Constant {
    return new Constant(value);
}
export function functionExpression(
    name: string,
    ...params: unknown[]
): FunctionExpression {
    return new FunctionExpression(name, params);
}
export function aggregateFunction(
    name: string,
    ...params: unknown[]
): AggregateFunction {
    return new AggregateFunction(name, params);
}
/** @internal Recursively encode expressions nested in stage maps and arrays. */
export function encodePipelineValue(value: unknown): PipelineValue {
    if (value instanceof Expression) return structuredClone(value._value);
    if (value instanceof Ordering)
        return encodePipelineValue({
            expression: value.expr,
            direction: value.direction
        });
    if (Array.isArray(value))
        return { arrayValue: { values: value.map(encodePipelineValue) } };
    if (value && Object.getPrototypeOf(value) === Object.prototype)
        return {
            mapValue: {
                fields: Object.fromEntries(
                    Object.entries(value).map(([key, entry]) => [
                        key,
                        encodePipelineValue(entry)
                    ])
                )
            }
        };
    return encodeValue(value);
}
export type Selectable = string | Field | AliasedExpression;
/** @internal Normalize selections without assigning user keys to object prototypes. */
export function selectionMap(
    selections: readonly Selectable[]
): Record<string, Expression> {
    return Object.fromEntries(
        selections.map((selection) => {
            if (typeof selection === 'string')
                return [selection, field(selection)];
            if (selection instanceof Field)
                return [selection.fieldPath.toString(), selection];
            if (selection instanceof AliasedExpression)
                return [selection.alias, selection.expr];
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected a field or aliased expression.'
            });
        })
    );
}

export function add(first: unknown, ...values: unknown[]): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).add(...values);
}
export function subtract(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).subtract(...values);
}
export function multiply(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).multiply(...values);
}
export function divide(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).divide(...values);
}
export function mod(first: unknown, ...values: unknown[]): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).mod(...values);
}
export function equal(first: unknown, ...values: unknown[]): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).equal(...values);
}
export function notEqual(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).notEqual(...values);
}
export function lessThan(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).lessThan(...values);
}
export function lessThanOrEqual(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).lessThanOrEqual(...values);
}
export function greaterThan(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).greaterThan(...values);
}
export function greaterThanOrEqual(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).greaterThanOrEqual(...values);
}
export function arrayConcat(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayConcat(...values);
}
export function arrayContains(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayContains(...values);
}
export function arrayContainsAll(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayContainsAll(...values);
}
export function arrayContainsAny(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayContainsAny(...values);
}
export function arrayFilter(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayFilter(...values);
}
export function arrayTransform(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayTransform(...values);
}
export function arrayTransformWithIndex(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayTransformWithIndex(...values);
}
export function arraySlice(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arraySlice(...values);
}
export function arrayReverse(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayReverse(...values);
}
export function arrayLength(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayLength(...values);
}
export function arrayFirst(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayFirst(...values);
}
export function arrayFirstN(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayFirstN(...values);
}
export function arrayLast(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayLast(...values);
}
export function arrayLastN(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayLastN(...values);
}
export function arrayMaximum(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayMaximum(...values);
}
export function arrayMaximumN(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayMaximumN(...values);
}
export function arrayMinimum(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayMinimum(...values);
}
export function arrayMinimumN(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayMinimumN(...values);
}
export function arrayIndexOf(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayIndexOf(...values);
}
export function arrayLastIndexOf(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayLastIndexOf(...values);
}
export function arrayIndexOfAll(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayIndexOfAll(...values);
}
export function equalAny(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).equalAny(...values);
}
export function notEqualAny(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).notEqualAny(...values);
}
export function exists(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).exists(...values);
}
export function charLength(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).charLength(...values);
}
export function like(first: unknown, ...values: unknown[]): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).like(...values);
}
export function regexContains(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).regexContains(...values);
}
export function regexFind(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).regexFind(...values);
}
export function regexFindAll(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).regexFindAll(...values);
}
export function regexMatch(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).regexMatch(...values);
}
export function stringContains(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).stringContains(...values);
}
export function startsWith(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).startsWith(...values);
}
export function endsWith(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).endsWith(...values);
}
export function toLower(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).toLower(...values);
}
export function toUpper(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).toUpper(...values);
}
export function trim(first: unknown, ...values: unknown[]): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).trim(...values);
}
export function ltrim(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).ltrim(...values);
}
export function rtrim(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).rtrim(...values);
}
export function stringConcat(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).stringConcat(...values);
}
export function stringIndexOf(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).stringIndexOf(...values);
}
export function stringRepeat(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).stringRepeat(...values);
}
export function stringReplaceAll(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).stringReplaceAll(...values);
}
export function stringReplaceOne(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).stringReplaceOne(...values);
}
export function concat(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).concat(...values);
}
export function reverse(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).reverse(...values);
}
export function byteLength(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).byteLength(...values);
}
export function ceil(first: unknown, ...values: unknown[]): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).ceil(...values);
}
export function floor(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).floor(...values);
}
export function abs(first: unknown, ...values: unknown[]): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).abs(...values);
}
export function exp(first: unknown, ...values: unknown[]): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).exp(...values);
}
export function mapGet(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).mapGet(...values);
}
export function mapSet(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).mapSet(...values);
}
export function mapKeys(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).mapKeys(...values);
}
export function mapValues(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).mapValues(...values);
}
export function mapEntries(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).mapEntries(...values);
}
export function count(first: unknown, ...values: unknown[]): AggregateFunction {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).count(...values);
}
export function sum(first: unknown, ...values: unknown[]): AggregateFunction {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).sum(...values);
}
export function average(
    first: unknown,
    ...values: unknown[]
): AggregateFunction {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).average(...values);
}
export function minimum(
    first: unknown,
    ...values: unknown[]
): AggregateFunction {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).minimum(...values);
}
export function maximum(
    first: unknown,
    ...values: unknown[]
): AggregateFunction {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).maximum(...values);
}
export function first(first: unknown, ...values: unknown[]): AggregateFunction {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).first(...values);
}
export function last(first: unknown, ...values: unknown[]): AggregateFunction {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).last(...values);
}
export function arrayAgg(
    first: unknown,
    ...values: unknown[]
): AggregateFunction {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayAgg(...values);
}
export function arrayAggDistinct(
    first: unknown,
    ...values: unknown[]
): AggregateFunction {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayAggDistinct(...values);
}
export function countDistinct(
    first: unknown,
    ...values: unknown[]
): AggregateFunction {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).countDistinct(...values);
}
export function logicalMaximum(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).logicalMaximum(...values);
}
export function logicalMinimum(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).logicalMinimum(...values);
}
export function vectorLength(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).vectorLength(...values);
}
export function cosineDistance(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).cosineDistance(...values);
}
export function dotProduct(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).dotProduct(...values);
}
export function euclideanDistance(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).euclideanDistance(...values);
}
export function unixMicrosToTimestamp(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).unixMicrosToTimestamp(...values);
}
export function timestampToUnixMicros(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).timestampToUnixMicros(...values);
}
export function unixMillisToTimestamp(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).unixMillisToTimestamp(...values);
}
export function timestampToUnixMillis(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).timestampToUnixMillis(...values);
}
export function unixSecondsToTimestamp(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).unixSecondsToTimestamp(...values);
}
export function timestampToUnixSeconds(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).timestampToUnixSeconds(...values);
}
export function timestampAdd(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).timestampAdd(...values);
}
export function timestampSubtract(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).timestampSubtract(...values);
}
export function timestampDiff(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).timestampDiff(...values);
}
export function timestampExtract(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).timestampExtract(...values);
}
export function documentId(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).documentId(...values);
}
export function parent(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).parent(...values);
}
export function substring(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).substring(...values);
}
export function arrayGet(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arrayGet(...values);
}
export function isError(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).isError(...values);
}
export function ifError(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).ifError(...values);
}
export function isAbsent(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).isAbsent(...values);
}
export function mapRemove(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).mapRemove(...values);
}
export function mapMerge(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).mapMerge(...values);
}
export function pow(first: unknown, ...values: unknown[]): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).pow(...values);
}
export function trunc(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).trunc(...values);
}
export function round(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).round(...values);
}
export function collectionId(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).collectionId(...values);
}
export function length(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).length(...values);
}
export function ln(first: unknown, ...values: unknown[]): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).ln(...values);
}
export function sqrt(first: unknown, ...values: unknown[]): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).sqrt(...values);
}
export function stringReverse(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).stringReverse(...values);
}
export function ifAbsent(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).ifAbsent(...values);
}
export function ifNull(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).ifNull(...values);
}
export function coalesce(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).coalesce(...values);
}
export function join(first: unknown, ...values: unknown[]): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).join(...values);
}
export function log10(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).log10(...values);
}
export function arraySum(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).arraySum(...values);
}
export function split(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).split(...values);
}
export function timestampTruncate(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).timestampTruncate(...values);
}
export function type(first: unknown, ...values: unknown[]): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).type(...values);
}
export function isType(
    first: unknown,
    ...values: unknown[]
): BooleanExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).isType(...values);
}
export function getField(
    first: unknown,
    ...values: unknown[]
): FunctionExpression {
    return (
        first instanceof Expression
            ? first
            : typeof first === 'string'
              ? field(first)
              : constant(first)
    ).getField(...values);
}

export function and(...conditions: Expression[]): BooleanExpression {
    return new FunctionExpression('and', conditions).asBoolean();
}
export function or(...conditions: Expression[]): BooleanExpression {
    return new FunctionExpression('or', conditions).asBoolean();
}
export function not(condition: Expression): BooleanExpression {
    return condition.asBoolean().not();
}
export function countAll(): AggregateFunction {
    return new AggregateFunction('count', []);
}
export function variable(name: string): Expression {
    if (typeof name !== 'string' || !name)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Expected a variable name.'
        });
    return new Expression({ variableReferenceValue: name });
}
