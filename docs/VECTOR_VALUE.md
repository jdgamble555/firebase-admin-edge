# VectorValue

Create vector fields with `FieldValue.vector()`. Inputs are copied, and `toArray()`
returns a fresh copy. Vectors accept up to 2048 finite numbers.

```typescript
import { FieldValue, VectorValue } from 'firebase-admin-edge';

const vector = FieldValue.vector([0.1, 0.2, 0.3]);
console.log(vector.toArray());
console.log(vector.isEqual(FieldValue.vector([0.1, 0.2, 0.3])));
await firestore.doc('items/one').set({ embedding: vector });
const snapshot = await firestore.doc('items/one').get();
console.log(snapshot.get('embedding') instanceof VectorValue);
```

The REST vector representation is encoded and decoded automatically. See
[VectorQuery](VECTOR_QUERY.md) for searching vector fields.
