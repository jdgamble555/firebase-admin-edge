# AggregateField

```typescript
import { AggregateField, FieldPath } from 'firebase-admin-edge';

const count = AggregateField.count();
const sum = AggregateField.sum('price');
const average = AggregateField.average(new FieldPath('price'));
console.log(count.isEqual(AggregateField.count())); // true

const { error: resultError, data: result } = await firestore
    .collection('orders')
    .aggregate({ count, sum, average })
    .get();
if (resultError) {
    throw resultError;
}
console.log(result.data());
```

Count includes all query results. Sum and average operate on the selected field
using Firestore's server aggregation semantics. Field paths accept simple dotted
strings or `FieldPath` instances. Empty field names throw.

```typescript
const average = AggregateField.average('price');
console.log(average.type); // AggregateField
console.log(average.aggregateType); // avg
```

Aggregate specifications retain their result types: count and sum yield numbers; average can also yield null.
