# BundleBuilder

`firestore.bundle(name?)` creates a builder. An omitted name gets a random ID.
Add document snapshots or named query snapshots, then build once:

```typescript
const { error: aliceError, data: alice } = await firestore
    .doc('users/alice')
    .get();
if (aliceError) {
    throw aliceError;
}
const { error: activeError, data: active } = await firestore
    .collection('users')
    .where('active', '==', true)
    .get();
if (activeError) {
    throw activeError;
}
const builder = firestore.bundle('users-v1');
builder.add(alice);
builder.add('active-users', active);
const bytes = builder.build();
const response = new Response(bytes, {
    headers: { 'Content-Type': 'application/octet-stream' }
});
```

The output is a `Uint8Array` in Firebase's length-prefixed UTF-8 bundle format,
suitable for the Web SDK's `loadBundle()`. This uses web-standard byte arrays
instead of Node's `Buffer`. Names must be non-empty, and query names must be
unique within a bundle. Empty bundles and missing document snapshots are supported.

Documents are deduplicated by resource name, keeping the latest snapshot and
all named-query memberships. Stored fields are serialized directly, bypassing
application converters. After `build()`, further `add()` or `build()` calls throw.
Server read times are preserved for document and query reads. Internally
constructed snapshots without server metadata fall back to their supplied or
locally recorded read time.

```typescript
const builder = db.bundle('homepage');
console.log(builder.bundleId); // homepage
```
