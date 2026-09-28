---
'firebase-admin-edge': major
---

Replace optional positional constructor arguments with typed options objects for
FirebaseAdminAuth, FirebaseAuth, Firestore, Storage, and AppCheck. Required arguments
remain positional; omitted options retain their existing defaults.

For example, use `new FirebaseAdminAuth(serviceAccount, { tenantId, fetch, cache,
cacheName, emulatorHost })` and `new Firestore(serviceAccount, { databaseId, fetch,
cache, cacheName })`. FirebaseAuth accepts `new FirebaseAuth(config, callbackUrl,
{ tenantId, fetch, emulatorHost })`. Storage accepts `{ bucketName, fetch, cache,
cacheName, retryOptions }`, and AppCheck accepts `{ fetch, cache, cacheName }` as
their second argument. The previous optional positional signatures are removed.
