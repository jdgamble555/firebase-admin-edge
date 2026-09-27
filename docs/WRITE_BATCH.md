# WriteBatch

`firestore.batch()` creates an atomic group of writes. All references must belong
to that Firestore instance. Nothing is sent until `commit()`.

```typescript
const batch = firestore.batch();
batch.create(firestore.doc('users/new-user'), { active: true });
batch.set(firestore.doc('users/alice'), { active: true }, { merge: true });
batch.update(firestore.doc('users/bob'), { 'profile.name': 'Bob' });
batch.delete(firestore.doc('users/old-user'));
const { error: resultsError, data: results } = await batch.commit();
if (resultsError) {
    throw resultsError;
}
console.log(results.map((result) => result.writeTime.toDate()));
```

`create()` fails if the document exists; `set()` replaces it unless `merge` or
`mergeFields` is supplied; `update()` requires an existing document by default.
`update()` accepts an object with dotted field keys. An empty map supplied to an
update replaces that map; merge writes use leaf-field masks. `delete()` does not
require the document to exist by default.

```typescript
import { Timestamp, FieldPath } from 'firebase-admin-edge';

const ref = firestore.doc('examples/options');
const { error: operationError1 } = await firestore
    .batch()
    .set(
        ref,
        { 'literal.name': 'value', ignored: 1 },
        {
            mergeFields: [new FieldPath('literal.name')]
        }
    )
    .commit();
if (operationError1) {
    throw operationError1;
}
// Supply the last known update time for optimistic concurrency.
const knownUpdateTime = new Timestamp(1700000000, 0);
const { error: operationError2 } = await firestore
    .batch()
    .update(ref, { value: 2 }, { lastUpdateTime: knownUpdateTime })
    .commit();
if (operationError2) {
    throw operationError2;
}
const { error: operationError3 } = await firestore
    .batch()
    .delete(ref, { exists: true })
    .commit();
if (operationError3) {
    throw operationError3;
}
```

A batch accepts up to 500 writes. It cannot be reused after commit, including a
failed commit. Empty batches resolve to `[]` without a request. Data is encoded at
enqueue time. See [FieldValue](FIELD_VALUE.md) for supported server transforms.
Preconditions support `exists` or `lastUpdateTime`, not both.

## Variadic updates

```typescript
import { FieldPath } from 'firebase-admin-edge';

const { error: operationError1 } = await firestore
    .batch()
    .update(
        firestore.doc('users/alice'),
        new FieldPath('literal.name'),
        'Alice',
        'active',
        true
    )
    .commit();
if (operationError1) {
    throw operationError1;
}
```

Field/value pairs may end with a precondition. The object update overload remains available.
