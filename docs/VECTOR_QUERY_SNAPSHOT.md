# VectorQuerySnapshot

Vector query results expose their query, documents, size, empty flag and read time.

```typescript
const { error: snapshotError, data: snapshot } = await nearest.get();
if (snapshotError) {
    throw snapshotError;
}
console.log(snapshot.query === nearest, snapshot.size, snapshot.empty);
console.log(snapshot.readTime.toDate());
snapshot.forEach((document) => console.log(document.data()));
const { error: againError, data: again } = await nearest.get();
if (againError) {
    throw againError;
}
console.log(snapshot.isEqual(again));
```

`forEach(callback, thisArg?)` supports a callback context. `isEqual()` compares
the vector query and ordered document data. Documents preserve the converter on
the underlying query.

```typescript
const { error: snapshotError, data: snapshot } = await query.get();
if (snapshotError) {
    throw snapshotError;
}
for (const change of snapshot.docChanges()) {
    console.log(change.type, change.doc.id, change.oldIndex, change.newIndex);
}
```

A fetched vector result reports its documents as `added`, in result order. An empty result has no changes.
