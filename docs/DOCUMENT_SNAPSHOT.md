# DocumentSnapshot

`DocumentSnapshot` is the class returned by `DocumentReference.get()`, including
when the document is missing. It exposes `id`, `ref`, `exists`, `data()`, and `get()`.

```typescript
import { DocumentSnapshot } from 'firebase-admin-edge';

const { error: snapshotError, data: snapshot } = await firestore
    .doc('users/alice')
    .get();
if (snapshotError) {
    throw snapshotError;
}
console.log(snapshot instanceof DocumentSnapshot); // true
console.log(snapshot.id, snapshot.ref.path); // alice, users/alice

if (snapshot.exists) {
    console.log(snapshot.data()); // document fields, or {} for an empty document
} else {
    console.log(snapshot.data()); // undefined
}
```

Each `data()` call returns a freshly decoded object, using the conversions in the
[Firestore guide](FIRESTORE.md). Obtain snapshots through reads; their constructor
accepts internal REST data and is not intended for application use.

[QueryDocumentSnapshot](QUERY_DOCUMENT_SNAPSHOT.md) extends this class and
guarantees that the document exists. `createTime` and `updateTime` expose server
timestamps for existing documents; both are undefined for missing documents.

## Field access

```typescript
import { FieldPath } from 'firebase-admin-edge';

const { error: snapshotError, data: snapshot } = await firestore
    .doc('users/alice')
    .get();
if (snapshotError) {
    throw snapshotError;
}
console.log(snapshot.get('profile.name')); // nested stored field
console.log(snapshot.get(new FieldPath('profile.name'))); // literal field name
```

Missing fields or missing documents return `undefined`; stored nulls remain
`null`. Invalid paths throw. `get()` reads stored fields even when `data()` uses a
converter, and does not traverse inherited object properties or array indexes.
With a converter, `data()` returns the application model instead of raw fields.

## Read times and bundles

Snapshots expose `readTime` as a `Timestamp`. Server-provided read times are
preserved for single-document, bulk and query reads. Internally constructed test
snapshots without server metadata fall back to the supplied or local time.

```typescript
const { error: snapshotError, data: snapshot } = await firestore
    .doc('users/alice')
    .get();
if (snapshotError) {
    throw snapshotError;
}
console.log(snapshot.readTime.toDate());
console.log(snapshot.createTime?.toDate(), snapshot.updateTime?.toDate());
const { error: againError, data: again } = await firestore
    .doc('users/alice')
    .get();
if (againError) {
    throw againError;
}
console.log(snapshot.isEqual(again));
const bytes = firestore.bundle('alice').add(snapshot).build();
```
