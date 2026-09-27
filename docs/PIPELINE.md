# Pipeline API

REST pipelines execute through `documents:executePipeline`. They require an Enterprise edition database. The configured Standard edition project rejected the live pipeline check, so successful pipeline execution has not been live-validated here. Import expression helpers through the `Pipelines` namespace; no Firebase client dependency is installed.

```typescript
import { Pipelines } from 'firebase-admin-edge';
const { field, constant, countAll } = Pipelines;

const source = db.pipeline();
const books = source.collection('books');
const { error: snapshotError, data: snapshot } = await books
    .where(field('rating').greaterThan(3))
    .addFields(field('price').multiply(0.9).as('salePrice'))
    .select('title', 'salePrice')
    .sort(field('salePrice').ascending())
    .limit(10)
    .execute();
if (snapshotError) {
    throw snapshotError;
}
for (const row of snapshot.results) {
    console.log(row.data(), row.get('title'), row.id, row.ref);
    console.log(row.createTime, row.updateTime, row.isEqual(row));
}
console.log(snapshot.pipeline, snapshot.executionTime, snapshot.explainStats);
```

Results can be projected or computed objects without a document reference. `data()` returns decoded Firestore values, and `get()` accepts a dotted string or FieldPath.

Sources and immutable stages:

```typescript
const byGroup = source.collectionGroup('books');
const all = source.database();
const chosen = source.documents('books/a', db.doc('books/b'));
const ranked = books.offset(5).limit(10);
const unique = books.distinct('author');
const summary = books.aggregate({
    accumulators: [
        countAll().as('count'),
        field('price').average().as('average')
    ],
    groups: ['author']
});
const samples = books.sample({ percentage: 10 });
const expanded = books.unnest(field('tags').as('tag'), 'tagIndex');
const stripped = books.removeFields('privateNotes');
const renamed = books.replaceWith({ title: field('title') });
const combined = books.union(chosen);
const bound = books.define(field('author').as('currentAuthor'));
const nested = books.addFields(chosen.toArrayExpression().as('related'));
const scalar = books.addFields(summary.toScalarExpression().as('summary'));
const nearest = books.findNearest({
    field: 'embedding',
    vectorValue: [1, 0, 0],
    distanceMeasure: 'euclidean',
    limit: 5,
    distanceField: 'distance'
});
const search = books.search({ query: 'history', limit: 5 });
// Construct mutations explicitly; they run only when execute() is called.
const updates = chosen.update([constant(true).as('reviewed')]);
const deletes = chosen.delete();
```

Expressions support arithmetic, comparison, arrays, strings, maps, vectors, timestamps, and aggregate operations. The same receiver-based operations are exported as standalone helpers, taking a field name or expression first. `as()` names a selected expression; `ascending()`/`descending()` build orderings.

```typescript
const lower = field('title').toLower();
const match = Pipelines.and(
    field('published').equal(true),
    field('tags').arrayContains('history')
);
const fallback = field('title').ifAbsent('Untitled');
const total = field('price').sum().as('total');
const custom = Pipelines.functionExpression('custom_function', field('title'));
const customAggregate = Pipelines.aggregateFunction(
    'custom_aggregate',
    field('price')
);
const extension = books.rawStage('where', [match]);
const { error: explainError, data: explain } = await books.execute({
    explainOptions: { mode: 'explain', outputFormat: 'json' }
});
if (explainError) {
    throw explainError;
}
const reader = books.stream().getReader();
const first = await reader.read();
await reader.cancel();
```

`rawStage()` and generic expression helpers expose REST extensions without implementing transport outside the endpoint layer. Unknown functions/stages are validated by the service. Pipeline convenience overloads are not yet a complete replica of every Node SDK overload. Web streams decode response batches incrementally and abort fetch when cancelled or when Firestore is terminated.

```typescript
const converted = db
    .pipeline()
    .createFrom(
        db
            .collection('books')
            .where('rating', '>=', 4)
            .orderBy('rating')
            .limit(10)
    );
const { error: explainedError, data: explained } = await converted.execute({
    explainOptions: { mode: 'explain', outputFormat: 'json' }
});
if (explainedError) {
    throw explainedError;
}
console.log(
    explained.explainStats?.text,
    explained.explainStats?.json,
    explained.explainStats?.rawMessage
);
```
