# DocumentReference

## Polling snapshots

```typescript
const unsubscribe = firestore.doc('users/alice').onSnapshot(
    { pollIntervalMs: 2000 },
    (snapshot) => console.log(snapshot.exists, snapshot.data()),
    (error) => console.error('Listener stopped:', error)
);
// Later:
unsubscribe();
```

`onSnapshot(next, error?, { pollIntervalMs: 2000 })` is also supported. The initial
read runs immediately, including for missing documents. Later callbacks run when
data or existence changes. The default interval is 5000 ms; a positive integer
controls the delay after each completed read. Reads never overlap within a listener.

This uses REST polling. Every poll performs a read, intermediate changes can be
missed, and the runtime must stay active. Unsubscribe and `firestore.terminate()`
clear pending timers and suppress callbacks from in-flight reads; an already-sent
HTTP request may still finish. Read errors stop polling and invoke the error
callback once, or log to the console if no error callback was supplied. Callbacks
should be synchronous; a thrown snapshot callback error also stops the listener.

`DocumentReference` represents a document location. Obtain one from
`firestore.doc(path)` or `collection.doc(id)`; both use the Firestore instance's
service account, database, fetch implementation, and token cache.

```typescript
import { DocumentReference } from 'firebase-admin-edge';

const firestore = firebaseServer.firestore;
const alice = firestore.doc('users/alice');
const sameAlice = firestore.collection('users').doc('alice');

console.log(alice instanceof DocumentReference); // true
console.log(alice.id, alice.path); // alice, users/alice
console.log(alice.firestore === firestore); // true
```

## Read a document

```typescript
try {
    const { error: snapshotError, data: snapshot } = await alice.get();
    if (snapshotError) {
        throw snapshotError;
    }
    console.log(snapshot.id, snapshot.ref === alice); // alice, true
    if (snapshot.exists) {
        console.log(snapshot.data());
    } else {
        console.log(snapshot.data()); // undefined
    }
} catch (error) {
    console.error('Document read failed', error);
}
```

Each `get()` performs a read. Missing documents return `exists: false`; existing
empty documents return `{}` from `data()`. Each `data()` call decodes a fresh copy
using the value conversions described in [Firestore](FIRESTORE.md). Authentication
and request errors return `{ error, data: null }`. Successful reads return
`{ error: null, data: snapshot }`; writes and collection listing use the same
result convention.

Both existing and missing reads return [DocumentSnapshot](DOCUMENT_SNAPSHOT.md)
class instances.

## Parent collections and subcollections

```typescript
const users = alice.parent;
console.log(users.path, users.parent); // users, null
const { error: activeUsersError, data: activeUsers } = await users
    .where('active', '==', true)
    .get();
if (activeUsersError) {
    throw activeUsersError;
}

const posts = alice.collection('posts');
console.log(posts.path); // users/alice/posts
console.log(posts.parent?.isEqual(alice)); // true
const { error: firstPostError, data: firstPost } = await posts
    .doc('first')
    .get();
if (firstPostError) {
    throw firstPostError;
}
const { error: recentPostsError, data: recentPosts } = await posts
    .orderBy('createdAt', 'desc')
    .limit(10)
    .get();
if (recentPostsError) {
    throw recentPostsError;
}

// Relative paths may span multiple collection/document pairs.
const comments = alice.collection('posts/first/comments');
console.log(comments.path); // users/alice/posts/first/comments
```

Navigation creates references without network requests or checking document
existence. Collection paths are relative, must have an odd number of segments,
and cannot contain empty, `.` or `..` segments. Document paths have an even number
of segments and follow the same segment restrictions.

## Reference equality

```typescript
console.log(alice.isEqual(sameAlice)); // true
console.log(alice.isEqual(firestore.doc('users/bob'))); // false

const { error: snapshotError, data: snapshot } = await firestore
    .collection('users')
    .get();
if (snapshotError) {
    throw snapshotError;
}
for (const doc of snapshot.docs) {
    console.log(doc.ref instanceof DocumentReference); // true
    console.log(doc.ref.isEqual(alice));
}
```

`isEqual()` compares the Firestore instance, document path, and converter identity. References owned by
different Firestore instances compare unequal, even if their configurations match.

## Write a document

```typescript
import { FieldValue } from 'firebase-admin-edge';

const { error: operationError1 } = await alice.create({ name: 'Alice' });
if (operationError1) {
    throw operationError1;
} // fails if the document already exists
const { error: operationError2 } = await alice.set({
    name: 'Alice',
    visits: 0
});
if (operationError2) {
    throw operationError2;
} // replaces document data
const { error: operationError3 } = await alice.set(
    { active: true },
    { merge: true }
);
if (operationError3) {
    throw operationError3;
}
const { error: resultError, data: result } = await alice.update({
    'profile.name': 'Alice',
    visits: FieldValue.increment(1)
});
if (resultError) {
    throw resultError;
}
console.log(result.writeTime.toDate());
const { error: operationError4 } = await alice.delete();
if (operationError4) {
    throw operationError4;
}
```

Write options, object-form updates, and preconditions follow [WriteBatch](WRITE_BATCH.md).
Each method sends one atomic commit and returns its `WriteResult`.

This implements a subset of the
[Admin DocumentReference API](https://googleapis.dev/nodejs/firestore/latest/DocumentReference.html).
`onSnapshot()` uses the polling behavior described above.

## Listing and converters

```typescript
const { error: collectionsError, data: collections } =
    await alice.listCollections();
if (collectionsError) {
    throw collectionsError;
}
console.log(collections.map((collection) => collection.path));

const typedAlice = alice.withConverter({
    toFirestore(user: { label: string }) {
        return { name: user.label };
    },
    fromFirestore(snapshot) {
        return { label: String(snapshot.get('name')) };
    }
});
const { error: operationError1 } = await typedAlice.set({ label: 'Alice' });
if (operationError1) {
    throw operationError1;
}
const { error: snapshotError, data: snapshot } = await typedAlice.get();
if (snapshotError) {
    throw snapshotError;
}
console.log(snapshot.data()?.label);
const rawAlice = typedAlice.withConverter(null);
```

`listCollections()` follows all pages and does not require the parent document to
exist. `withConverter()` returns a new reference. Create/set operations use
`toFirestore`, including writes through batches, transactions, and bulk writers;
merge options are forwarded to the converter. Updates use database field names
and bypass `toFirestore`. Reads use `fromFirestore` only when the document exists.
The parent collection retains the converter; child collections are unconverted.

## Variadic updates

```typescript
import { FieldPath, FieldValue } from 'firebase-admin-edge';

const { error: operationError1 } = await firestore
    .doc('users/alice')
    .update(
        new FieldPath('literal.name'),
        'Alice',
        'visits',
        FieldValue.increment(1)
    );
if (operationError1) {
    throw operationError1;
}
```

String field paths address nested fields. `FieldPath` preserves literal dots and
other special characters. A final precondition may follow the field/value pairs.
Duplicate fields, conflicting parent/child paths, and incomplete pairs are rejected.

Replacement and merge writes preserve the converter's distinct overloads. See [typed converter examples](FIRESTORE_DATA_CONVERTER.md). Update objects are checked against the stored model, while `set()` and `create()` use the application model.
