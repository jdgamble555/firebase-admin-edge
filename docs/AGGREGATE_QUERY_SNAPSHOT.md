# AggregateQuerySnapshot

```typescript
import { AggregateField, AggregateQuerySnapshot } from 'firebase-admin-edge';

const query = firestore.collection('orders').aggregate({
    total: AggregateField.sum('price'),
    average: AggregateField.average('price')
});
const { error: snapshotError, data: snapshot } = await query.get();
if (snapshotError) {
    throw snapshotError;
}
console.log(snapshot instanceof AggregateQuerySnapshot); // true
console.log(snapshot.query === query); // true
console.log(snapshot.data()); // { total: number, average: number | null }
console.log(snapshot.readTime.toDate());
const { error: againError, data: again } = await query.get();
if (againError) {
    throw againError;
}
console.log(snapshot.isEqual(again));
```

`data()` returns a fresh object keyed by your aggregate aliases. Numeric results
are JavaScript numbers; averages can be null when there are no qualifying values.
The constructor is intended for internal use by `AggregateQuery.get()`.
