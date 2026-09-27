# VectorQuery

`Query.findNearest()` creates a `VectorQuery`. Existing filters and converters
remain attached to the query. Firestore requires an appropriate vector index.

```typescript
const query = firestore.collection('items').where('active', '==', true);
const options = {
    vectorField: 'embedding',
    queryVector: [0.1, 0.2, 0.3],
    limit: 10,
    distanceMeasure: 'COSINE' as const,
    distanceResultField: 'distance',
    distanceThreshold: 0.5
};
const nearest = query.findNearest(options);
const { error: snapshotError, data: snapshot } = await nearest.get();
if (snapshotError) {
    throw snapshotError;
}
console.log(snapshot.docs.map((doc) => doc.data()));
console.log(nearest.isEqual(query.findNearest(options)));
const { error: planError, data: plan } = await nearest.explain();
if (planError) {
    throw planError;
}
console.log(plan.metrics);

// The positional Admin overload is also supported:
const positional = query.findNearest('embedding', [0.1, 0.2, 0.3], {
    limit: 10,
    distanceMeasure: 'EUCLIDEAN'
});
```

`queryVector` accepts a number array or `VectorValue`. Query vectors must be
non-empty. Limits range from 1 to 1000. Supported distances are `EUCLIDEAN`,
`COSINE`, and `DOT_PRODUCT`; thresholds follow the server's distance semantics.
The vector field and result field accept strings or `FieldPath` values.
See [VectorQuerySnapshot](VECTOR_QUERY_SNAPSHOT.md) for results.
