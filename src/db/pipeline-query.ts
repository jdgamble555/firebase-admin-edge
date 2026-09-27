import type { Firestore } from './firestore.js';
import type { FilterNode } from './filter.js';
import { normalizedOrders, type QueryOptions } from './query-request.js';
import {
    Pipeline,
    Expression,
    FunctionExpression,
    Ordering,
    field,
    and,
    or
} from './pipeline.js';
/** @internal Translate traditional query state without executing a query. */
export function queryPipeline(
    db: Firestore,
    path: string,
    options: QueryOptions
): Pipeline {
    let pipeline = options.allDescendants
        ? db.pipeline().collectionGroup(path.split('/').at(-1)!)
        : db.pipeline().collection(path);
    for (const filter of [
        ...(options.filters ?? []),
        ...(options.compositeFilters ?? [])
    ])
        pipeline = pipeline.where(pipelineFilter(filter));
    const orders = normalizedOrders(options);
    for (const order of orders)
        pipeline = pipeline.where(field(order.field).exists());
    for (const [key, cursor] of [
        ['start', options.start],
        ['end', options.end]
    ] as const) {
        if (!cursor) continue;
        const alternatives: Expression[] = [];
        for (let i = 0; i < cursor.values.length; i++) {
            const equalities = cursor.values
                .slice(0, i)
                .map((value, index) =>
                    field(orders[index]!.field).equal(new Expression(value))
                );
            const greater =
                (key === 'start') === (orders[i]!.direction === 'asc');
            const inclusive =
                i === cursor.values.length - 1 &&
                (key === 'start' ? cursor.before : !cursor.before);
            const comparison =
                (greater ? 'greater_than' : 'less_than') +
                (inclusive ? '_or_equal' : '');
            alternatives.push(
                and(
                    ...equalities,
                    new FunctionExpression(comparison, [
                        field(orders[i]!.field),
                        new Expression(cursor.values[i]!)
                    ])
                )
            );
        }
        if (alternatives.length) pipeline = pipeline.where(or(...alternatives));
    }
    const ordering = orders.map(
        (order) =>
            new Ordering(
                field(order.field),
                order.direction === 'asc' ? 'ascending' : 'descending'
            )
    );
    const effective = options.last
        ? ordering.map(
              (order) =>
                  new Ordering(
                      order.expr,
                      order.direction === 'ascending'
                          ? 'descending'
                          : 'ascending'
                  )
          )
        : ordering;
    pipeline = pipeline.sort(...effective);
    if (options.offset !== undefined)
        pipeline = pipeline.offset(options.offset);
    if (options.limit !== undefined) pipeline = pipeline.limit(options.limit);
    if (options.last) pipeline = pipeline.sort(...ordering);
    if (options.fields) pipeline = pipeline.select(...options.fields);
    if (options.nearest)
        pipeline = pipeline.rawStage(
            'find_nearest',
            [
                field(options.nearest.vectorField.fieldPath),
                new Expression(options.nearest.queryVector),
                options.nearest.distanceMeasure.toLowerCase()
            ],
            {
                limit: options.nearest.limit,
                ...(options.nearest.distanceResultField
                    ? {
                          distance_field: field(
                              options.nearest.distanceResultField
                          )
                      }
                    : {})
            }
        );
    return pipeline;
}
/** @internal Preserve nested boolean filter structure. */
function pipelineFilter(filter: FilterNode): Expression {
    if ('filters' in filter)
        return new FunctionExpression(
            filter.op.toLowerCase(),
            filter.filters.map(pipelineFilter)
        );
    const names = {
        '==': 'equal',
        '!=': 'not_equal',
        '<': 'less_than',
        '<=': 'less_than_or_equal',
        '>': 'greater_than',
        '>=': 'greater_than_or_equal',
        in: 'equal_any',
        'not-in': 'not_equal_any',
        'array-contains': 'array_contains',
        'array-contains-any': 'array_contains_any'
    };
    return new FunctionExpression(names[filter.operator], [
        field(filter.field),
        new Expression(filter.value)
    ]);
}
