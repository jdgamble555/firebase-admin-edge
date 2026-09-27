# AggregateQuery

`Query.aggregate()` and `Query.count()` return `AggregateQuery` instances. They
retain the originating query, including its filters, ordering, limits, and bounds.

```typescript
import { AggregateField, AggregateQuery } from 'firebase-admin-edge';

const orders = firestore.collection('orders').where('paid', '==', true);
const aggregate = orders.aggregate({
    orders: AggregateField.count(),
    revenue: AggregateField.sum('total'),
    averageOrder: AggregateField.average('total')
});
console.log(aggregate instanceof AggregateQuery); // true
console.log(aggregate.query === orders); // true
const { error: resultError, data: result } = await aggregate.get();
if (resultError) {
    throw resultError;
}
console.log(result.data());

const { error: countError, data: count } = await orders.count().get();
if (countError) {
    throw countError;
}
console.log(count.data().count);
```

One to five named aggregates are supported. Aliases are mapped to generated REST
aliases, so result keys may contain punctuation. `get()` runs server aggregation
and returns [AggregateQuerySnapshot](AGGREGATE_QUERY_SNAPSHOT.md); documents are
not downloaded to calculate results locally. Reads and explain operations return
`{ error, data }`; API failures return an error with `data: null`.
Aggregate fields refer to stored field names and do not invoke application converters.

```typescript
console.log(orders.count().isEqual(orders.count()));
const { error: planError, data: plan } = await aggregate.explain();
if (planError) {
    throw planError;
}
const { error: analyzedError, data: analyzed } = await aggregate.explain({
    analyze: true
});
if (analyzedError) {
    throw analyzedError;
}
console.log(plan.metrics, analyzed.snapshot?.data());
```

`explain()` returns the plan without executing the query by default. Analysis
returns aggregate data and execution statistics. `get()` and analyzed results
include server read-time metadata.
