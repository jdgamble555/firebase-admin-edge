# CollectionReference

`CollectionReference` extends [Query](QUERY.md), providing a collection's location,
document references, and all supported read/query methods. Obtain instances through
`firestore.collection(path)`; this also works with `firebaseServer.firestore`.

`doc()` and non-null `parent` values return
[DocumentReference](DOCUMENT_REFERENCE.md) instances.

```typescript
import { CollectionReference, Query } from 'firebase-admin-edge';

const users = firestore.collection('users');
console.log(users instanceof CollectionReference); // true
console.log(users instanceof Query); // true
console.log(users.firestore === firestore); // true
console.log(users.id, users.path, users.parent); // users, users, null

const alice = users.doc('alice');
const { error: snapshotError, data: snapshot } = await alice.get();
if (snapshotError) {
    throw snapshotError;
}
const { error: everyoneError, data: everyone } = await users.get();
if (everyoneError) {
    throw everyoneError;
}
const { error: activeError, data: active } = await users
    .where('active', '==', true)
    .limit(10)
    .get();
if (activeError) {
    throw activeError;
}
```

Nested collections expose their parent document reference:

```typescript
const posts = firestore.collection('users/alice/posts');
console.log(posts.id, posts.path); // posts, users/alice/posts
console.log(posts.parent?.path); // users/alice
const { error: postError, data: post } = await posts.doc('first').get();
if (postError) {
    throw postError;
}
const { error: samePostError, data: samePost } = await users
    .doc('alice/posts/first')
    .get();
if (samePostError) {
    throw samePostError;
}
```

Collection paths have an odd number of segments. `doc(id)` accepts an explicit ID
or relative path ending at a document. Empty paths, empty segments, `.` and `..`
are rejected. Reference navigation alone does not send network requests.

Query builders return a new `Query`, leaving the collection reference unchanged.
Collection references inherit `Query.isEqual()`:

```typescript
console.log(
    firestore.collection('users').isEqual(firestore.collection('users'))
);
```

## Auto IDs, adding, and listing

```typescript
const reserved = users.doc(); // creates a reference, with no network request
console.log(reserved.id); // 20 cryptographically random alphanumeric characters
const { error: operationError1 } = await reserved.set({ name: 'Alice' });
if (operationError1) {
    throw operationError1;
}
const { error: createdError, data: created } = await users.add({ name: 'Bob' });
if (createdError) {
    throw createdError;
}
console.log(created.path); // resolves after the create write succeeds

const { error: referencesError, data: references } =
    await users.listDocuments();
if (referencesError) {
    throw referencesError;
}
console.log(references.map((ref) => ref.path));
```

`add()` uses a create precondition and propagates failures. `listDocuments()`
follows all pages and includes references to missing parent documents containing
subcollections; a returned reference does not guarantee `get().exists` is true.

## Converters

```typescript
const converted = users.withConverter({
    toFirestore(user: { label: string }) {
        return { name: user.label };
    },
    fromFirestore(snapshot) {
        return { label: String(snapshot.get('name')) };
    }
});
const { error: refError, data: ref } = await converted.add({ label: 'Alice' });
if (refError) {
    throw refError;
}
const { error: snapshotError, data: snapshot } = await ref.get();
if (snapshotError) {
    throw snapshotError;
}
console.log(snapshot.data()?.label);
const rawCollection = converted.withConverter(null);
```

`withConverter()` returns a new `CollectionReference`. The converter follows
`doc()`, `add()`, `listDocuments()`, and query builders.
