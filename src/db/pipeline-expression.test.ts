import * as expressions from './pipeline-expression.js';
import { expect, it } from 'vitest';
import { FieldPath } from './field-path.js';
import {
    field,
    constant,
    functionExpression,
    aggregateFunction,
    encodePipelineValue,
    selectionMap,
    Expression,
    FunctionExpression,
    BooleanExpression,
    AggregateFunction,
    AliasedExpression,
    Ordering
} from './pipeline-expression.js';
it('encodes fields, literal maps, nested expressions, arrays and ordering', () => {
    const f = field(new FieldPath('a.b'));
    expect(encodePipelineValue(f)).toEqual({ fieldReferenceValue: '`a.b`' });
    expect(encodePipelineValue({ nested: [f, constant(3)] })).toEqual({
        mapValue: {
            fields: {
                nested: {
                    arrayValue: {
                        values: [
                            { fieldReferenceValue: '`a.b`' },
                            { integerValue: '3' }
                        ]
                    }
                }
            }
        }
    });
    expect(encodePipelineValue(f.ascending())).toMatchObject({
        mapValue: { fields: { direction: { stringValue: 'ascending' } } }
    });
    expect(f.descending().direction).toBe('descending');
    expect(selectionMap(['name', field('age'), f.as('literal')])).toEqual({
        name: field('name'),
        age: field('age'),
        literal: f
    });
    expect(functionExpression('custom', f)).toBeInstanceOf(FunctionExpression);
    expect(aggregateFunction('custom', f)).toBeInstanceOf(AggregateFunction);
    expect(f.asBoolean().not()).toBeInstanceOf(BooleanExpression);
    expect(() => field('')).toThrow();
    expect(() => new FunctionExpression('', [])).toThrow();
    expect(() => new AliasedExpression(f, '')).toThrow();
    expect(() => new Ordering(f, 'bad' as never)).toThrow();
    expect(() => selectionMap([null as never])).toThrow();
    const encoded = encodePipelineValue(f);
    encoded.fieldReferenceValue = 'mutated';
    expect(encodePipelineValue(f).fieldReferenceValue).toBe('`a.b`');
});
it.each([
    ['add', 'add', []],
    ['subtract', 'subtract', []],
    ['multiply', 'multiply', []],
    ['divide', 'divide', []],
    ['mod', 'mod', []],
    ['equal', 'equal', []],
    ['notEqual', 'not_equal', []],
    ['lessThan', 'less_than', []],
    ['lessThanOrEqual', 'less_than_or_equal', []],
    ['greaterThan', 'greater_than', []],
    ['greaterThanOrEqual', 'greater_than_or_equal', []],
    ['arrayConcat', 'array_concat', []],
    ['arrayContains', 'array_contains', []],
    ['arrayContainsAll', 'array_contains_all', []],
    ['arrayContainsAny', 'array_contains_any', []],
    ['arrayFilter', 'array_filter', []],
    ['arrayTransform', 'array_transform', []],
    ['arrayTransformWithIndex', 'array_transform', []],
    ['arraySlice', 'array_slice', []],
    ['arrayReverse', 'array_reverse', []],
    ['arrayLength', 'array_length', []],
    ['arrayFirst', 'array_first', []],
    ['arrayFirstN', 'array_first_n', []],
    ['arrayLast', 'array_last', []],
    ['arrayLastN', 'array_last_n', []],
    ['arrayMaximum', 'maximum', []],
    ['arrayMaximumN', 'maximum_n', []],
    ['arrayMinimum', 'minimum', []],
    ['arrayMinimumN', 'minimum_n', []],
    ['arrayIndexOf', 'array_index_of', ['first']],
    ['arrayLastIndexOf', 'array_index_of', ['last']],
    ['arrayIndexOfAll', 'array_index_of_all', []],
    ['equalAny', 'equal_any', []],
    ['notEqualAny', 'not_equal_any', []],
    ['exists', 'exists', []],
    ['charLength', 'char_length', []],
    ['like', 'like', []],
    ['regexContains', 'regex_contains', []],
    ['regexFind', 'regex_find', []],
    ['regexFindAll', 'regex_find_all', []],
    ['regexMatch', 'regex_match', []],
    ['stringContains', 'string_contains', []],
    ['startsWith', 'starts_with', []],
    ['endsWith', 'ends_with', []],
    ['toLower', 'to_lower', []],
    ['toUpper', 'to_upper', []],
    ['trim', 'trim', []],
    ['ltrim', 'ltrim', []],
    ['rtrim', 'rtrim', []],
    ['stringConcat', 'string_concat', []],
    ['stringIndexOf', 'string_index_of', []],
    ['stringRepeat', 'string_repeat', []],
    ['stringReplaceAll', 'string_replace_all', []],
    ['stringReplaceOne', 'string_replace_one', []],
    ['concat', 'concat', []],
    ['reverse', 'reverse', []],
    ['byteLength', 'byte_length', []],
    ['ceil', 'ceil', []],
    ['floor', 'floor', []],
    ['abs', 'abs', []],
    ['exp', 'exp', []],
    ['mapGet', 'map_get', []],
    ['mapSet', 'map_set', []],
    ['mapKeys', 'map_keys', []],
    ['mapValues', 'map_values', []],
    ['mapEntries', 'map_entries', []],
    ['count', 'count', []],
    ['sum', 'sum', []],
    ['average', 'average', []],
    ['minimum', 'minimum', []],
    ['maximum', 'maximum', []],
    ['first', 'first', []],
    ['last', 'last', []],
    ['arrayAgg', 'array_agg', []],
    ['arrayAggDistinct', 'array_agg_distinct', []],
    ['countDistinct', 'count_distinct', []],
    ['logicalMaximum', 'maximum', []],
    ['logicalMinimum', 'minimum', []],
    ['vectorLength', 'vector_length', []],
    ['cosineDistance', 'cosine_distance', []],
    ['dotProduct', 'dot_product', []],
    ['euclideanDistance', 'euclidean_distance', []],
    ['unixMicrosToTimestamp', 'unix_micros_to_timestamp', []],
    ['timestampToUnixMicros', 'timestamp_to_unix_micros', []],
    ['unixMillisToTimestamp', 'unix_millis_to_timestamp', []],
    ['timestampToUnixMillis', 'timestamp_to_unix_millis', []],
    ['unixSecondsToTimestamp', 'unix_seconds_to_timestamp', []],
    ['timestampToUnixSeconds', 'timestamp_to_unix_seconds', []],
    ['timestampAdd', 'timestamp_add', []],
    ['timestampSubtract', 'timestamp_subtract', []],
    ['timestampDiff', 'timestamp_diff', []],
    ['timestampExtract', 'timestamp_extract', []],
    ['documentId', 'document_id', []],
    ['parent', 'parent', []],
    ['substring', 'substring', []],
    ['arrayGet', 'array_get', []],
    ['isError', 'is_error', []],
    ['ifError', 'if_error', []],
    ['isAbsent', 'is_absent', []],
    ['mapRemove', 'map_remove', []],
    ['mapMerge', 'map_merge', []],
    ['pow', 'pow', []],
    ['trunc', 'trunc', []],
    ['round', 'round', []],
    ['collectionId', 'collection_id', []],
    ['length', 'length', []],
    ['ln', 'ln', []],
    ['sqrt', 'sqrt', []],
    ['stringReverse', 'string_reverse', []],
    ['ifAbsent', 'if_absent', []],
    ['ifNull', 'if_null', []],
    ['coalesce', 'coalesce', []],
    ['join', 'join', []],
    ['log10', 'log10', []],
    ['arraySum', 'sum', []],
    ['split', 'split', []],
    ['timestampTruncate', 'timestamp_trunc', []],
    ['type', 'type', []],
    ['isType', 'is_type', []],
    ['getField', 'get_field', []]
])('encodes expression %s with its receiver', (method, wireName, suffix) => {
    const receiver = field('score');
    const result = (
        receiver[method as keyof Expression] as () => Expression
    ).call(receiver);
    const expected = {
        functionValue: {
            name: wireName,
            args: [
                { fieldReferenceValue: 'score' },
                ...(suffix as string[]).map((value) => ({ stringValue: value }))
            ]
        }
    };
    expect(encodePipelineValue(result)).toEqual(expected);
    const standalone = (
        expressions[method as keyof typeof expressions] as (
            first: string
        ) => Expression
    )('score');
    expect(encodePipelineValue(standalone)).toEqual(expected);
});
it('composes boolean conditions, variable bindings and count-all', () => {
    expect(
        expressions.and(field('a').exists(), field('b').exists())
    ).toBeInstanceOf(BooleanExpression);
    expect(expressions.or(field('a').exists())).toBeInstanceOf(
        BooleanExpression
    );
    expect(expressions.not(field('a').exists())).toBeInstanceOf(
        BooleanExpression
    );
    expect(encodePipelineValue(expressions.countAll())).toEqual({
        functionValue: { name: 'count', args: [] }
    });
    expect(expressions.countAll().as('count')).toBeInstanceOf(
        expressions.AliasedAggregate
    );
    expect(encodePipelineValue(expressions.variable('key'))).toEqual({
        variableReferenceValue: 'key'
    });
    expect(() => expressions.variable('')).toThrow();
});

it('accepts literal receivers in standalone arithmetic expressions', () => {
    expect(encodePipelineValue(expressions.add(5, field('quantity')))).toEqual({
        functionValue: {
            name: 'add',
            args: [{ integerValue: '5' }, { fieldReferenceValue: 'quantity' }]
        }
    });
});
