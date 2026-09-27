# QueryDocumentSnapshot

`QueryDocumentSnapshot` extends [DocumentSnapshot](DOCUMENT_SNAPSHOT.md). Each
document in `QuerySnapshot.docs` is an instance of both classes. Its `exists`
property is always `true`, and `data()` always returns a document object.

```typescript
import { DocumentSnapshot, QueryDocumentSnapshot } from 'firebase-admin-edge';

const { error: resultsError, data: results } = await firestore
    .collection('users')
    .get();
if (resultsError) {
    throw resultsError;
}
for (const document of results.docs) {
    console.log(document instanceof QueryDocumentSnapshot); // true
    console.log(document instanceof DocumentSnapshot); // true
    console.log(document.id, document.ref.path, document.exists);
    const data = document.data(); // always an object, including {} for empty documents
    console.log(data);
}
```

`data()` uses the shared document decoder and returns a fresh copy on each call.
With a converter, it returns the converted application model. The inherited
`get(fieldPath)` always accesses stored fields:

```typescript
const { error: resultError, data: result } = await firestore
    .collection('users')
    .limit(1)
    .get();
if (resultError) {
    throw resultError;
}
for (const document of result.docs) console.log(document.get('profile.name'));
```

Obtain instances from query results; the internal constructor requires an existing
REST document and rejects missing documents.
