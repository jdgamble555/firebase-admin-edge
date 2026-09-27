# FieldValue

Sentinels describe server-side transforms. They are accepted in document writes,
batches, transactions, and bulk writes, including nested map fields.

```typescript
import { FieldValue } from 'firebase-admin-edge';

await firestore.doc('users/alice').set(
    {
        visitedAt: FieldValue.serverTimestamp(),
        visits: FieldValue.increment(1),
        tags: FieldValue.arrayUnion('active')
    },
    { merge: true }
);

await firestore.doc('users/alice').update({
    obsolete: FieldValue.delete(),
    tags: FieldValue.arrayRemove('inactive')
});
```

Deletion requires `update()` or a merge write. Increments require a finite number.
Sentinels inside arrays and query values are rejected. Transforms are encoded in
the same atomic commit as the document write. Sentinel equality and vector values
are not implemented.

## Equality and vectors

```typescript
console.log(FieldValue.increment(1).isEqual(FieldValue.increment(1))); // true
const embedding = FieldValue.vector([0.1, 0.2, 0.3]);
await firestore.doc('items/one').set({ embedding });
```

`isEqual()` compares transform kinds and operands. `vector()` returns a
[VectorValue](VECTOR_VALUE.md), supported by writes and nearest-neighbor queries.

Numeric extrema use server-side transforms:

```ts
await db.doc('scores/a').update({
    lowest: FieldValue.minimum(2),
    highest: FieldValue.maximum(99)
});
```

These accept numeric values, including NaN and infinities, with Firestore's numeric transform semantics.
